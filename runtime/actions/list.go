package actions

import (
	q "github.com/teamkeel/keel/query"
	"github.com/teamkeel/keel/runtime/common"
)

func List(scope *Scope, input map[string]any) (map[string]any, error) {
	query := q.NewQuery(scope.Context, scope.Schema, scope.Model)

	// Generate the SQL statement.
	statement, page, err := GenerateListStatement(query, scope, input)
	if err != nil {
		return nil, err
	}

	// Execute database request with results
	results, pageInfo, err := statement.ExecuteToMany(scope.Context, page)
	if err != nil {
		return nil, err
	}

	isAuthorised, err := AuthoriseAction(scope, input, results)
	if err != nil {
		return nil, err
	}

	if !isAuthorised {
		return nil, common.NewPermissionError()
	}

	return map[string]any{
		"results":  results,
		"pageInfo": pageInfo.ToMap(),
	}, nil
}

func GenerateListStatement(query *q.QueryBuilder, scope *Scope, input map[string]any) (*q.Statement, *q.Page, error) {
	where, ok := input["where"].(map[string]any)
	if !ok {
		where = map[string]any{}
	}

	orderBy, ok := input["orderBy"].([]any)
	if !ok {
		orderBy = []any{}
	}

	err := query.ApplyImplicitFiltersForList(scope.Context, scope.Schema, scope.Action, where)
	if err != nil {
		return nil, nil, err
	}

	err = query.ApplyExplicitFilters(scope.Context, scope.Schema, scope.Action, where)
	if err != nil {
		return nil, nil, err
	}

	err = query.ApplySchemaOrdering(scope.Action)
	if err != nil {
		return nil, nil, err
	}

	err = query.ApplyRequestOrdering(orderBy)
	if err != nil {
		return nil, nil, err
	}

	page, err := ParsePage(input)
	if err != nil {
		return nil, nil, err
	}

	// Select all columns from this table and distinct on id
	query.AppendDistinctOn(q.IdField())
	query.AppendSelect(q.AllFields())

	err = query.ApplyPaging(page)
	if err != nil {
		return nil, &page, err
	}

	return query.SelectStatement(), &page, nil
}
