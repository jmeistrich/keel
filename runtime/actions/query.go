package actions

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/samber/lo"
	"github.com/teamkeel/keel/casing"
	"github.com/teamkeel/keel/db"
	"github.com/teamkeel/keel/proto"
	"github.com/teamkeel/keel/runtime/auth"
	"github.com/teamkeel/keel/runtime/common"
	"github.com/teamkeel/keel/schema/parser"
	"go.opentelemetry.io/otel/trace"
)

// Some field on the query builder's model.
func Field(field string) *QueryOperand {
	return &QueryOperand{
		column: casing.ToSnake(field),
	}
}

// The identifier field on the query builder's model.
func IdField() *QueryOperand {
	return &QueryOperand{
		column: casing.ToSnake(parser.ImplicitFieldNameId),
	}
}

// All fields on the query builder's model.
func AllFields() *QueryOperand {
	return &QueryOperand{
		column: "*",
	}
}

// Some field from the fragments of an expression or input.
func ExpressionField(fragments []string, field string) *QueryOperand {
	return &QueryOperand{
		table:  casing.ToSnake(strings.Join(fragments, "$")),
		column: casing.ToSnake(field),
	}
}

// Represents an inline query.
func InlineQuery(query *QueryBuilder) *QueryOperand {
	return &QueryOperand{query: query}
}

// Represents a value operand.
func Value(value any) *QueryOperand {
	return &QueryOperand{value: value}
}

// Represents a null value operand.
func Null() *QueryOperand {
	return &QueryOperand{}
}

type QueryOperand struct {
	query  *QueryBuilder
	table  string
	column string
	value  any
}

func (o *QueryOperand) IsInlineQuery() bool {
	return o.query != nil
}

func (o *QueryOperand) IsField() bool {
	return o.column != ""
}

func (o *QueryOperand) IsValue() bool {
	return o.value != nil
}

func (o *QueryOperand) IsNull() bool {
	return o.query == nil && o.table == "" && o.column == "" && o.value == nil
}

func (operand *QueryOperand) toColumnString(query *QueryBuilder) string {
	if !operand.IsField() {
		panic("operand is not of type field")
	}

	table := operand.table
	// If no model table is specified, then use the base model in the query builder
	if table == "" {
		table = query.table
	}

	return sqlQuote(table, operand.column)
}

// The templated SQL statement and associated values, ready to be executed.
type Statement struct {
	// The generated SQL template.
	template string
	// The arguments associated with the generated SQL template.
	args []any
}

func (statement *Statement) SqlTemplate() string {
	return statement.template
}

func (statement *Statement) SqlArgs() []any {
	return statement.args
}

type QueryBuilder struct {
	context context.Context
	// The base model this query builder is acting on.
	Model *proto.Model
	// The table name in the database.
	table string
	// The columns and clauses in SELECT.
	selection []string
	// The columns and clause in DISTINCT ON.
	distinctOn []string
	// The join clauses required for the query.
	joins []joinClause
	// The filter fragments used to construct WHERE.
	filters []string
	// The columns and clauses in ORDER BY.
	orderBy []*orderClause
	// The columns and clauses in RETURNING.
	returning []string
	// The value for LIMIT.
	limit *int
	// The ordered slice of arguments for the SQL statement template.
	args []any
	// The graph of rows to be written during an INSERT or UPDATE.
	writeValues *Row
	// The type of SQL join to use.
	joinType JoinType
}

type JoinType string

const (
	JoinTypeInner JoinType = "INNER"
	JoinTypeLeft  JoinType = "LEFT"
)

type JoinOption struct {
	Type JoinType
}

type joinClause struct {
	table     string
	alias     string
	condition string
	joinType  JoinType
}

type orderClause struct {
	field     *QueryOperand
	direction string
}

type Row struct {
	// The schema model which this row represents data for.
	model *proto.Model
	// The target fragments that this row represents in the input.
	target []string
	// The values of the fields to insert.
	values map[string]any
	// Other rows to insert which this row depends on.
	references []*Relationship
	// Other rows to insert which are dependent on this row.
	referencedBy []*Relationship
}

type Relationship struct {
	// The row which is either referenced to or by in a relationship.
	row *Row
	// The foreign key in the relationship.
	foreignKey *proto.Field
}

type QueryBuilderOption func(qb *QueryBuilder)

func WithJoinType(joinType JoinType) QueryBuilderOption {
	return func(qb *QueryBuilder) {
		qb.joinType = joinType
	}
}

func NewQuery(ctx context.Context, model *proto.Model, opts ...QueryBuilderOption) *QueryBuilder {
	qb := &QueryBuilder{
		context:    ctx,
		Model:      model,
		table:      casing.ToSnake(model.Name),
		selection:  []string{},
		distinctOn: []string{},
		joins:      []joinClause{},
		filters:    []string{},
		orderBy:    []*orderClause{},
		limit:      nil,
		returning:  []string{},
		args:       []any{},
		writeValues: &Row{
			model:        nil,
			target:       nil,
			values:       map[string]any{},
			referencedBy: []*Relationship{},
			references:   []*Relationship{},
		},
		joinType: JoinTypeLeft,
	}

	if len(opts) > 0 {
		for _, o := range opts {
			o(qb)
		}
	}

	return qb
}

// Creates a copy of the query builder.
func (query *QueryBuilder) Copy() *QueryBuilder {
	return &QueryBuilder{
		Model:      query.Model,
		table:      query.table,
		selection:  copySlice(query.selection),
		distinctOn: copySlice(query.distinctOn),
		joins:      copySlice(query.joins),
		filters:    copySlice(query.filters),
		orderBy:    copySlice(query.orderBy),
		limit:      query.limit,
		returning:  copySlice(query.returning),
		args:       query.args,
	}
}

// Includes a value to be written during an INSERT or UPDATE.
func (query *QueryBuilder) AddWriteValue(operand *QueryOperand, value any) {

	query.writeValues.values[operand.column] = value
}

// Includes root values to be written during an INSERT or UPDATE for a model.
func (query *QueryBuilder) AddWriteValues(values map[string]any) {
	query.writeValues.model = query.Model
	for k, v := range values {
		query.AddWriteValue(Field(k), v)
	}
}

// Includes a column in SELECT.
func (query *QueryBuilder) AppendSelect(operand *QueryOperand) {
	c := operand.toColumnString(query)

	if !lo.Contains(query.selection, c) {
		query.selection = append(query.selection, c)
	}
}

// Include a clause in SELECT.
func (query *QueryBuilder) AppendSelectClause(clause string) {
	if !lo.Contains(query.selection, clause) {
		query.selection = append(query.selection, clause)
	}
}

// Include a column in this table in DISTINCT ON.
func (query *QueryBuilder) AppendDistinctOn(operand *QueryOperand) {
	c := operand.toColumnString(query)

	if !lo.Contains(query.distinctOn, c) {
		query.distinctOn = append(query.distinctOn, c)
	}
}

// Include a WHERE condition, ANDed to the existing filters (unless an OR has been specified)
func (query *QueryBuilder) Where(left *QueryOperand, operator ActionOperator, right *QueryOperand) error {
	template, args, err := query.generateConditionTemplate(left, operator, right)
	if err != nil {
		return err
	}

	query.filters = append(query.filters, template)
	query.args = append(query.args, args...)

	return nil
}

// Appends the next condition with a logical AND.
func (query *QueryBuilder) And() {
	query.filters = trimRhsOperators(query.filters)
	if len(query.filters) > 0 {
		query.filters = append(query.filters, "AND")
	}
}

// Appends the next condition with a logical OR.
func (query *QueryBuilder) Or() {
	query.filters = trimRhsOperators(query.filters)
	if len(query.filters) > 0 {
		query.filters = append(query.filters, "OR")
	}
}

// Opens a new conditional scope in the where expression (i.e. open parethesis).
func (query *QueryBuilder) OpenParenthesis() {
	query.filters = append(query.filters, "(")
}

// Closes the current conditional scope in the where expression (i.e. close parethesis).
func (query *QueryBuilder) CloseParenthesis() {
	query.filters = trimRhsOperators(query.filters)
	query.filters = append(query.filters, ")")
}

// Trims an excess OR / AND operators from the rhs side of the filter conditions.
func trimRhsOperators(filters []string) []string {
	return lo.DropRightWhile(filters, func(s string) bool { return s == "OR" || s == "AND" })
}

// Include an JOIN clause.
func (query *QueryBuilder) Join(joinModel string, joinField *QueryOperand, modelField *QueryOperand) {
	join := joinClause{
		table:     sqlQuote(casing.ToSnake(joinModel)),
		alias:     sqlQuote(joinField.table),
		condition: fmt.Sprintf("%s = %s", joinField.toColumnString(query), modelField.toColumnString(query)),
		joinType:  query.joinType,
	}

	if !lo.Contains(query.joins, join) {
		query.joins = append(query.joins, join)
	}
}

// Include a column in ORDER BY.
// If the column already exists, then just update the sort direction.
func (query *QueryBuilder) AppendOrderBy(operand *QueryOperand, direction string) {
	order := &orderClause{field: operand, direction: strings.ToUpper(direction)}

	existing, found := lo.Find(query.orderBy, func(o *orderClause) bool {
		return o.field.column == order.field.column
	})

	if found {
		existing.direction = strings.ToUpper(direction)
	} else {
		query.orderBy = append(query.orderBy, order)
		query.AppendDistinctOn(operand)
	}
}

// Set the LIMIT to a number.
func (query *QueryBuilder) Limit(limit int) {
	query.limit = &limit
}

// Include a column in RETURNING.
func (query *QueryBuilder) AppendReturning(operand *QueryOperand) {
	c := operand.toColumnString(query)

	if !lo.Contains(query.returning, c) {
		query.returning = append(query.returning, c)
	}
}

// Apply pagination filters to the query.
func (query *QueryBuilder) ApplyPaging(page Page) error {

	// Paging condition is ANDed to any existing conditions
	query.And()

	// Add where condition to implement the page size
	switch {
	case page.First != 0:
		query.Limit(page.First)
	case page.Last != 0:
		query.Limit(page.Last)
	}

	// Specify the ORDER BY - but also a "LEAD" extra column to harvest extra data
	// that helps to determine "hasNextPage"
	query.AppendOrderBy(IdField(), "ASC")

	// Select hasNext clause
	orderByClausesAsSql := []string{}
	for _, o := range query.orderBy {
		orderByClausesAsSql = append(orderByClausesAsSql, fmt.Sprintf("%s %s", o.field.toColumnString(query), o.direction))
	}
	hasNext := fmt.Sprintf("CASE WHEN LEAD(%s) OVER (ORDER BY %s) IS NOT NULL THEN true ELSE false END AS hasNext", IdField().toColumnString(query), strings.Join(orderByClausesAsSql, ", "))
	query.AppendSelectClause(hasNext)

	// We add a subquery to the select list that fetches the total count of records
	// matching the constraints specified by the main query without the offset/limit applied
	// This is actually more performant than COUNT(*) OVER() [window function]
	totalResults := fmt.Sprintf("(%s) AS totalCount", query.countQuery())
	query.AppendSelectClause(totalResults)
	// Because we are essentially performing the same query again within the subquery, we need to duplicate the query parameters again as they will be used twice in the course of the whole query
	query.args = append(query.args, query.args...)

	// Add where condition to implement the after/before paging request
	switch {
	case page.After != "":
		err := query.applyCursorFilter(page.After, false)
		if err != nil {
			return err
		}
	case page.Before != "":
		err := query.applyCursorFilter(page.Before, true)
		if err != nil {
			return err
		}
	}

	return nil
}

// Apply forward pagination 'after' cursor filter to the query.
func (query *QueryBuilder) applyCursorFilter(cursor string, isBackwards bool) error {
	query.And()

	var err error
	if len(query.orderBy) > 1 {
		query.OpenParenthesis()
	}

	// For each column being ordered, we need to filter those which proceed the cursor row.
	for i := 0; i < len(query.orderBy); i++ {
		if i > 0 {
			query.OpenParenthesis()
		}
		for j := 0; j < i; j++ {
			orderClause := query.orderBy[j]

			inline := NewQuery(query.context, query.Model)
			inline.AppendSelect(orderClause.field)
			err = inline.Where(IdField(), Equals, Value(cursor))
			if err != nil {
				return err
			}

			err = query.Where(orderClause.field, Equals, InlineQuery(inline))
			if err != nil {
				return err
			}
			query.And()
		}

		orderClause := query.orderBy[i]

		inline := NewQuery(query.context, query.Model)
		inline.AppendSelect(orderClause.field)
		err = inline.Where(IdField(), Equals, Value(cursor))
		if err != nil {
			return err
		}

		var operator ActionOperator
		switch {
		case strings.EqualFold(orderClause.direction, "ASC") && !isBackwards:
			operator = GreaterThan
		case strings.EqualFold(orderClause.direction, "ASC") && isBackwards:
			operator = LessThan
		case strings.EqualFold(orderClause.direction, "DESC") && !isBackwards:
			operator = LessThan
		case strings.EqualFold(orderClause.direction, "DESC") && isBackwards:
			operator = GreaterThan
		default:
			return errors.New("unknown order by direction")
		}

		err = query.Where(orderClause.field, operator, InlineQuery(inline))
		if err != nil {
			return err
		}
		if i > 0 {
			query.CloseParenthesis()
		}
		query.Or()
	}

	if len(query.orderBy) > 1 {
		query.CloseParenthesis()
	}
	return nil
}

func (query *QueryBuilder) countQuery() string {
	selection := "COUNT("
	joins := ""
	filters := ""
	if len(query.distinctOn) > 0 {
		distinctFields := strings.Join(query.distinctOn, ", ")
		if len(query.distinctOn) > 1 {
			distinctFields = fmt.Sprintf("(%s)", distinctFields)
		}
		selection += fmt.Sprintf("DISTINCT %s", distinctFields)
	} else {
		selection += "*"
	}
	selection += ")"

	if len(query.joins) > 0 {
		for _, j := range query.joins {
			joins += fmt.Sprintf("%s JOIN %s AS %s ON %s ", query.joinType, j.table, j.alias, j.condition)
		}
	}

	conditions := trimRhsOperators(query.filters)
	if len(conditions) > 0 {
		filters = fmt.Sprintf("WHERE %s", strings.Join(conditions, " "))
	}

	sql := fmt.Sprintf("SELECT %s FROM %s %s %s",
		selection,
		sqlQuote(query.table),
		joins,
		filters)

	return sql
}

// Generates an executable SELECT statement with the list of arguments.
func (query *QueryBuilder) SelectStatement() *Statement {
	distinctOn := ""
	selection := ""
	joins := ""
	filters := ""
	orderBy := ""
	limit := ""

	if len(query.distinctOn) > 0 {
		distinctOn = fmt.Sprintf("DISTINCT ON(%s)", strings.Join(query.distinctOn, ", "))
	}

	if len(query.selection) == 0 {
		query.AppendSelect(AllFields())
	}

	selection = strings.Join(query.selection, ", ")

	if len(query.joins) > 0 {
		for _, j := range query.joins {
			joins += fmt.Sprintf("%s JOIN %s AS %s ON %s ", query.joinType, j.table, j.alias, j.condition)
		}
	}

	conditions := trimRhsOperators(query.filters)
	if len(conditions) > 0 {
		filters = fmt.Sprintf("WHERE %s", strings.Join(conditions, " "))
	}

	if len(query.orderBy) > 0 {
		orderByClausesAsSql := []string{}
		for _, o := range query.orderBy {
			orderByClausesAsSql = append(orderByClausesAsSql, fmt.Sprintf("%s %s", o.field.toColumnString(query), o.direction))
		}

		orderBy = fmt.Sprintf("ORDER BY %s", strings.Join(orderByClausesAsSql, ", "))
	}

	if query.limit != nil {
		limit = "LIMIT ?"
		query.args = append(query.args, *query.limit)
	}

	sql := fmt.Sprintf("SELECT %s %s FROM %s %s %s %s %s",
		distinctOn,
		selection,
		sqlQuote(query.table),
		joins,
		filters,
		orderBy,
		limit)

	return &Statement{
		template: sql,
		args:     query.args,
	}
}

// Generates an executable INSERT statement with the list of arguments.
func (query *QueryBuilder) InsertStatement() *Statement {
	sql, args, _, alias := query.generateInsertCte(query.writeValues, nil, "")

	selection := []string{"*"}
	if auth.IsAuthenticated(query.context) {
		identity, _ := auth.GetIdentity(query.context)
		selection = append(selection, setIdentityIdClause(identity.Id))
	}

	spanContext := trace.SpanContextFromContext(query.context)
	if spanContext.IsValid() {
		selection = append(selection, setTraceIdClause(spanContext.TraceID().String()))
	}

	statement := fmt.Sprintf("WITH %s SELECT %s FROM %s",
		sql,
		strings.Join(selection, ", "),
		alias)

	return &Statement{
		template: statement,
		args:     args,
	}
}

// Recursively generates in common table expression insert query for the write values graph.
func (query QueryBuilder) generateInsertCte(row *Row, foreignKey *proto.Field, primaryKeyTableAlias string) (string, []any, *proto.Field, string) {
	sql := ""
	alias := fmt.Sprintf("new_%v_%s", makeAlias(query.writeValues, row), casing.ToSnake(row.model.Name))

	columnNames := []string{}
	args := []any{}

	// Rows which this row references need to created first, and the primary needs to be extracted (as a SELECT statement from them to insert into this row.
	// The foreign key field for this row is returned, along with the alias of the table needed to extract the primary key from.
	for _, r := range row.references {
		var foreignKeyField *proto.Field
		var primaryKeyTable string

		s, a, foreignKeyField, primaryKeyTable := query.generateInsertCte(r.row, r.foreignKey, alias)
		if len(sql) > 0 {
			sql += ", "
		}
		sql += s
		args = append(args, a...)

		// For every row that this references, we need to set the foreign key.
		// For example, on the Sale row; customerId = (SELECT id FROM new_customer_1)
		if foreignKeyField != nil && row.model.Name == foreignKeyField.ModelName {
			row.values[foreignKeyField.ForeignKeyFieldName.Value] = &inlineSelect{sql: fmt.Sprintf("(SELECT id FROM %s)", primaryKeyTable)}
		}
	}

	// Does this foreign key of the relationship exist on this row?
	// This means this row exists as a referencedBy row for another.
	// For example, on the SaleItem row; saleId = (SELECT id FROM new_sale_1)
	if foreignKey != nil && row.model.Name == foreignKey.ModelName {
		row.values[foreignKey.ForeignKeyFieldName.Value] = &inlineSelect{sql: fmt.Sprintf("(SELECT id FROM %s)", primaryKeyTableAlias)}
	}

	// Make iterating through the map with deterministic ordering
	orderedKeys := make([]string, 0, len(row.values))
	for k := range row.values {
		orderedKeys = append(orderedKeys, k)
	}

	columnValues := []string{}
	sort.Strings(orderedKeys)
	for _, col := range orderedKeys {
		colName := casing.ToSnake(col)
		columnNames = append(columnNames, colName)

		if inline, ok := row.values[col].(*inlineSelect); ok {
			columnValues = append(columnValues, inline.sql)
		} else {
			args = append(args, row.values[col])
			columnValues = append(columnValues, "?")
		}
	}

	// If there are no values to insert then we use "DEFAULT VALUES" which means:
	// "All columns will be filled with their default values"
	values := "DEFAULT VALUES"

	if len(columnNames) > 0 {
		values = fmt.Sprintf("(%s) VALUES (%s)",
			strings.Join(columnNames, ", "),
			strings.Join(columnValues, ", "))
	}

	cte := fmt.Sprintf("%s AS (INSERT INTO %s %s RETURNING *)",
		alias,
		sqlQuote(casing.ToSnake(row.model.Name)),
		values)

	if len(sql) > 0 {
		sql += ", "
	}
	sql += cte

	// If this row is referenced by other rows, then we need to create these rows afterwards. We need to pass in this row table alias in order to extract the primary key.
	for _, r := range row.referencedBy {
		s, a, _, _ := query.generateInsertCte(r.row, r.foreignKey, alias)
		if len(sql) > 0 {
			sql += ", "
		}
		sql += s
		args = append(args, a...)
	}

	return sql, args, foreignKey, alias
}

type inlineSelect struct {
	sql string
}

// Generates a unique alias for this row in the graph.
func makeAlias(graph *Row, row *Row) int {
	rows := orderGraphNodes(graph)

	modelCount := map[string]int{}

	for _, r := range rows {
		modelCount[r.model.Name] += 1

		if r == row {
			return modelCount[r.model.Name]
		}
	}

	panic("the row does not exist within this graph")
}

// Generates an ordered slice of rows by insertion order.
func orderGraphNodes(graph *Row) []*Row {
	rows := []*Row{}

	for _, r := range graph.references {
		g := orderGraphNodes(r.row)
		rows = append(rows, g...)
	}

	rows = append(rows, graph)

	for _, r := range graph.referencedBy {
		g := orderGraphNodes(r.row)
		rows = append(rows, g...)
	}

	return rows
}

// Generates an executable UPDATE statement with the list of arguments.
func (query *QueryBuilder) UpdateStatement() *Statement {
	joins := ""
	filters := ""
	returning := ""
	sets := []string{}
	args := []any{}

	// Make iteratng through the writeValues map deterministically ordered
	orderedKeys := make([]string, 0, len(query.writeValues.values))
	for k := range query.writeValues.values {
		orderedKeys = append(orderedKeys, k)
	}
	sort.Strings(orderedKeys)
	for _, v := range orderedKeys {
		sets = append(sets, fmt.Sprintf("%s = ?", casing.ToSnake(v)))
		args = append(args, query.writeValues.values[v])
	}

	args = append(args, query.args...)

	if len(query.joins) > 0 {
		for _, j := range query.joins {
			joins += fmt.Sprintf("%s JOIN %s AS %s ON %s ", query.joinType, j.table, j.alias, j.condition)
		}
	}

	conditions := trimRhsOperators(query.filters)
	if len(conditions) > 0 {
		filters = fmt.Sprintf("WHERE %s", strings.Join(conditions, " "))
	}

	if auth.IsAuthenticated(query.context) {
		identity, _ := auth.GetIdentity(query.context)
		query.returning = append(query.returning, setIdentityIdClause(identity.Id))
	}

	spanContext := trace.SpanContextFromContext(query.context)
	if spanContext.IsValid() {
		query.returning = append(query.returning, setTraceIdClause(spanContext.TraceID().String()))
	}

	if len(query.returning) > 0 {
		returning = fmt.Sprintf("RETURNING %s", strings.Join(query.returning, ", "))
	}

	template := fmt.Sprintf("UPDATE %s SET %s %s %s %s",
		sqlQuote(query.table),
		strings.Join(sets, ", "),
		joins,
		filters,
		returning)

	return &Statement{
		template: template,
		args:     args,
	}
}

// Generates an executable DELETE statement with the list of arguments.
func (query *QueryBuilder) DeleteStatement() *Statement {
	usings := ""
	filters := ""
	returning := ""

	if len(query.joins) > 0 {
		usingTables := lo.Map(query.joins, func(j joinClause, _ int) string {
			return fmt.Sprintf("%s AS %s", j.table, j.alias)
		})
		usings = fmt.Sprintf("USING %s", strings.Join(usingTables, ", "))
		filters = strings.Join(lo.Map(query.joins, func(j joinClause, _ int) string { return j.condition }), " AND ")

		// If there are also filters, then append another AND
		if len(query.filters) > 0 {
			filters += " AND "
		}
	}

	conditions := trimRhsOperators(query.filters)
	if len(conditions) > 0 {
		filters = fmt.Sprintf("WHERE %s", strings.Join(conditions, " "))
	}

	if auth.IsAuthenticated(query.context) {
		identity, _ := auth.GetIdentity(query.context)
		query.returning = append(query.returning, setIdentityIdClause(identity.Id))
	}

	spanContext := trace.SpanContextFromContext(query.context)
	if spanContext.IsValid() {
		query.returning = append(query.returning, setTraceIdClause(spanContext.TraceID().String()))
	}

	if len(query.returning) > 0 {
		returning = fmt.Sprintf("RETURNING %s", strings.Join(query.returning, ", "))
	}

	template := fmt.Sprintf("DELETE FROM %s %s %s %s",
		sqlQuote(query.table),
		usings,
		filters,
		returning)

	return &Statement{
		template: template,
		args:     query.args,
	}
}

// Execute the SQL statement against the database, returning the number of rows affected.
func (statement *Statement) Execute(ctx context.Context) (int, error) {
	database, err := db.GetDatabase(ctx)
	if err != nil {
		return 0, err
	}

	result, err := database.ExecuteStatement(ctx, statement.template, statement.args...)
	if err != nil {
		return 0, toRuntimeError(err)
	}

	return int(result.RowsAffected), nil
}

type Rows = []map[string]interface{}

type PageInfo struct {
	// Count returns the number of rows returned for the current page
	Count int

	// TotalCount returns the total number of rows across all pages
	TotalCount int

	// HasNextPage indicates if there is a subsequent page after the current page
	HasNextPage bool

	// StartCursor is the identifier representing the first row in the set
	StartCursor string

	// EndCursor is the identifier representing the last row in the set
	EndCursor string
}

func (pi *PageInfo) ToMap() map[string]any {
	return map[string]any{
		"count":       pi.Count,
		"totalCount":  pi.TotalCount,
		"startCursor": pi.StartCursor,
		"endCursor":   pi.EndCursor,
		"hasNextPage": pi.HasNextPage,
	}
}

// Execute the SQL statement against the database, return the rows, number of rows affected, and a boolean to indicate if there is a next page.
func (statement *Statement) ExecuteToMany(ctx context.Context, page *Page) (Rows, *PageInfo, error) {
	database, err := db.GetDatabase(ctx)
	if err != nil {
		return nil, nil, err
	}

	result, err := database.ExecuteQuery(ctx, statement.template, statement.args...)
	if err != nil {
		return nil, nil, toRuntimeError(err)
	}

	rows := result.Rows
	returnedCount := len(result.Rows)

	// Sort out the hasNextPage value, and clean up the response.
	hasNextPage := false
	var totalCount int64
	var startCursor string
	var endCursor string

	if page != nil && page.Last != 0 {
		rows = lo.Reverse(rows)
	}
	if returnedCount > 0 {
		last := rows[returnedCount-1]
		var hasPagination bool
		hasNextPage, hasPagination = last["hasnext"].(bool)

		if hasPagination {
			totalCount = last["totalcount"].(int64)

			for i, row := range rows {
				delete(row, "hasnext")
				delete(row, "totalcount")

				if i == 0 {
					startCursor, _ = row["id"].(string)
				}
				if i == returnedCount-1 {
					endCursor, _ = row["id"].(string)
				}
			}
		}

		// TODO: only do this if we know auditing was added
		for _, row := range rows {
			delete(row, setIdentityIdAlias)
			delete(row, setTraceIdAlias)
		}
	}

	pageInfo := &PageInfo{
		Count:       returnedCount,
		TotalCount:  int(totalCount),
		HasNextPage: hasNextPage,
		StartCursor: startCursor,
		EndCursor:   endCursor,
	}

	return toLowerCamelMaps(rows), pageInfo, nil
}

// Execute the SQL statement against the database and expects a single row, returns the single row or nil if no data is found.
func (statement *Statement) ExecuteToSingle(ctx context.Context) (map[string]any, error) {
	results, pageInfo, err := statement.ExecuteToMany(ctx, nil)
	if err != nil {
		return nil, err
	}

	if pageInfo.Count > 1 {
		return nil, fmt.Errorf("%v results returned for ExecuteToSingle which expects 0 or 1 result", pageInfo.Count)
	} else if pageInfo.Count == 0 {
		return nil, nil
	}

	return results[0], nil
}

// Builds a condition SQL template using the ? placeholder for values.
func (query *QueryBuilder) generateConditionTemplate(lhs *QueryOperand, operator ActionOperator, rhs *QueryOperand) (string, []any, error) {
	var template string
	var lhsSqlOperand, rhsSqlOperand any
	args := []any{}

	switch operator {
	case StartsWith:
		rhs.value = rhs.value.(string) + "%%"
	case EndsWith:
		rhs.value = "%%" + rhs.value.(string)
	case Contains, NotContains:
		rhs.value = "%%" + rhs.value.(string) + "%%"
	}

	switch {
	case lhs.IsField():
		lhsSqlOperand = lhs.toColumnString(query)
	case lhs.IsValue():
		lhsSqlOperand = "?"
		args = append(args, lhs.value)
	case lhs.IsNull():
		lhsSqlOperand = "NULL"
	default:
		return "", nil, errors.New("no handling for lhs QueryOperand type")
	}

	switch {
	case rhs.IsField():
		rhsSqlOperand = rhs.toColumnString(query)
	case rhs.IsValue():
		if operator == OneOf || operator == NotOneOf {
			// The IN operator on an a value slice needs to have its template structured like this:
			// WHERE x IN (?, ?, ?)
			inPlaceholders := []string{}
			inValues := rhs.value.([]any)

			// if the inValues is empty, then it is invalid SQL to have "IN ()"
			// so therefore we should just apply a constraint that evaluates to false
			// to the query
			if len(inValues) < 1 {
				return "false", nil, nil
			}

			for _, v := range inValues {
				inPlaceholders = append(inPlaceholders, "?")
				args = append(args, v)
			}

			rhsSqlOperand = fmt.Sprintf("(%s)", strings.Join(inPlaceholders, ", "))
		} else {
			rhsSqlOperand = "?"
			args = append(args, rhs.value)
		}
	case rhs.IsNull():
		rhsSqlOperand = "NULL"
	case rhs.IsInlineQuery():
		rhsSqlOperand = fmt.Sprintf("(%s)", rhs.query.SelectStatement().template)
		args = append(args, rhs.query.args...)
	default:
		return "", nil, errors.New("no handling for rhs QueryOperand type")
	}

	switch operator {
	case Equals:
		template = fmt.Sprintf("%s IS NOT DISTINCT FROM %s", lhsSqlOperand, rhsSqlOperand)
	case NotEquals:
		template = fmt.Sprintf("%s IS DISTINCT FROM %s", lhsSqlOperand, rhsSqlOperand)
	case StartsWith, EndsWith, Contains:
		template = fmt.Sprintf("%s LIKE %s", lhsSqlOperand, rhsSqlOperand)
	case NotContains:
		template = fmt.Sprintf("%s NOT LIKE %s", lhsSqlOperand, rhsSqlOperand)
	case OneOf:
		// If the RHS is a repeated field where the parent is the array, then we must use a comparison
		// instead of an `IN` to avoid comparing an array with a value.
		if rhs.IsField() {
			template = fmt.Sprintf("%s IS NOT DISTINCT FROM %s", lhsSqlOperand, rhsSqlOperand)
		} else {
			template = fmt.Sprintf("%s IN %s", lhsSqlOperand, rhsSqlOperand)
		}

	case NotOneOf:
		template = fmt.Sprintf("%s NOT IN %s", lhsSqlOperand, rhsSqlOperand)
	case LessThan:
		template = fmt.Sprintf("%s < %s", lhsSqlOperand, rhsSqlOperand)
	case LessThanEquals:
		template = fmt.Sprintf("%s <= %s", lhsSqlOperand, rhsSqlOperand)
	case GreaterThan:
		template = fmt.Sprintf("%s > %s", lhsSqlOperand, rhsSqlOperand)
	case GreaterThanEquals:
		template = fmt.Sprintf("%s >= %s", lhsSqlOperand, rhsSqlOperand)
	case Before:
		template = fmt.Sprintf("%s < %s", lhsSqlOperand, rhsSqlOperand)
	case After:
		template = fmt.Sprintf("%s > %s", lhsSqlOperand, rhsSqlOperand)
	case OnOrBefore:
		template = fmt.Sprintf("%s <= %s", lhsSqlOperand, rhsSqlOperand)
	case OnOrAfter:
		template = fmt.Sprintf("%s >= %s", lhsSqlOperand, rhsSqlOperand)
	default:
		return "", nil, fmt.Errorf("operator: %v is not yet supported", operator)
	}

	return template, args, nil
}

func copySlice[T any](a []T) []T {
	tmp := make([]T, len(a))
	copy(tmp, a)
	return tmp
}

// toLowerCamelMap returns a copy of the given map, in which all
// of the key strings are converted to LowerCamelCase.
// It is good for converting identifiers typically used as database
// table or column names, to the case requirements stipulated by the Keel schema.
func toLowerCamelMap(m map[string]any) map[string]any {
	res := map[string]any{}
	for key, value := range m {
		res[casing.ToLowerCamel(key)] = value
	}
	return res
}

// toLowerCamelMaps is a convenience wrapper around toLowerCamelMap
// that operates on a list of input maps - rather than just a single map.
func toLowerCamelMaps(maps []map[string]any) []map[string]any {
	res := []map[string]any{}
	for _, m := range maps {
		res = append(res, toLowerCamelMap(m))
	}
	return res
}

// given a variadic list of tokens (e.g sqlQuote("person", "id")),
// returns sql friendly quoted tokens: "person"."id"
func sqlQuote(tokens ...string) string {
	quotedTokens := []string{}

	for _, token := range tokens {
		switch token {
		case "*":
			// if the token is * then it doesnt need to be quoted e.g "post".*
			quotedTokens = append(quotedTokens, token)
		default:
			quotedTokens = append(quotedTokens, db.QuoteIdentifier(token))
		}
	}
	return strings.Join(quotedTokens, ".")
}

func toRuntimeError(err error) error {
	var value *db.DbError
	if errors.As(err, &value) {
		switch value.Err {
		case db.ErrNotNullConstraintViolation:
			return common.NewNotNullError(value.Columns[0])
		case db.ErrUniqueConstraintViolation:
			return common.NewUniquenessError(value.Columns)
		case db.ErrForeignKeyConstraintViolation:
			return common.NewForeignKeyConstraintError(value.Columns[0])
		default:
			return common.RuntimeError{
				Code:    common.ErrInvalidInput,
				Message: "action failed to complete",
			}
		}
	}
	return err
}

const (
	setIdentityIdAlias = "__keel_identity_id"
	setTraceIdAlias    = "__keel_trace_id"
)

func setIdentityIdClause(value string) string {
	return fmt.Sprintf("set_identity_id('%s') AS %s", value, setIdentityIdAlias)
}

func setTraceIdClause(value string) string {
	return fmt.Sprintf("set_trace_id('%s') AS %s", value, setTraceIdAlias)
}
