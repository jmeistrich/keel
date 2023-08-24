package migrations

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"strings"

	"github.com/samber/lo"
	"github.com/teamkeel/keel/casing"
	"github.com/teamkeel/keel/db"
	"github.com/teamkeel/keel/proto"
	"github.com/teamkeel/keel/schema/parser"
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	ChangeTypeAdded    = "ADDED"
	ChangeTypeRemoved  = "REMOVED"
	ChangeTypeModified = "MODIFIED"
)

var ErrNoStoredSchema = errors.New("no schema stored in keel_schema table")
var ErrMultipleStoredSchemas = errors.New("more than one schema found in keel_schema table")

var (
	//go:embed ksuid.sql
	ksuidFunction string

	//go:embed process_audit.sql
	processAuditFunction string
)

type DatabaseChange struct {
	// The model this change applies to
	Model string

	// The field this change applies to (might be empty)
	Field string

	// The type of change
	Type string
}

type Migrations struct {
	database db.Database

	Schema *proto.Schema

	// Describes the changes that will be applied to the database
	// if SQL is run
	Changes []*DatabaseChange

	// The SQL to run to execute the database schema changes
	SQL string
}

// HasModelFieldChanges returns true if the migrations contain model field changes to be applied
func (m *Migrations) HasModelFieldChanges() bool {
	return m.SQL != ""
}

// Apply executes the migrations against the database
func (m *Migrations) Apply(ctx context.Context) error {
	sql := strings.Builder{}

	// Enable extensions
	sql.WriteString("CREATE EXTENSION IF NOT EXISTS pg_stat_statements;\n")

	// Functions
	sql.WriteString(ksuidFunction)
	sql.WriteString(processAuditFunction)

	sql.WriteString("CREATE TABLE IF NOT EXISTS keel_schema ( schema TEXT NOT NULL );\n")
	sql.WriteString("DELETE FROM keel_schema;\n")

	b, err := protojson.Marshal(m.Schema)
	if err != nil {
		return err
	}

	// Cannot use parameters as then you get an error:
	//   ERROR: cannot insert multiple commands into a prepared statement (SQLSTATE 42601)
	escapedJSON := db.QuoteLiteral(string(b))
	insertStmt := fmt.Sprintf("INSERT INTO keel_schema (schema) VALUES (%s);", escapedJSON)
	sql.WriteString(insertStmt)

	sql.WriteString(m.SQL)
	sql.WriteString("\n")

	_, err = m.database.ExecuteStatement(ctx, sql.String())
	return err
}

// New creates a new Migrations instance for the given schema and database.
// Introspection is performed on the database to work out what schema changes
// need to be applied to result in the database schema matching the Keel schema
func New(ctx context.Context, schema *proto.Schema, database db.Database) (*Migrations, error) {
	columns, err := getColumns(ctx, database)
	if err != nil {
		return nil, err
	}

	constraints, err := getConstraints(ctx, database)
	if err != nil {
		return nil, err
	}

	statements := []string{}
	changes := []*DatabaseChange{}
	modelsAdded := []*proto.Model{}
	existingModels := []*proto.Model{}

	modelNames := proto.ModelNames(schema)

	// Add any new models
	for _, modelName := range modelNames {
		model := proto.FindModel(schema.Models, modelName)
		_, exists := lo.Find(columns, func(c *ColumnRow) bool {
			return c.TableName == casing.ToSnake(model.Name)
		})
		if !exists {
			stmt, err := createTableStmt(schema, model)
			if err != nil {
				return nil, err
			}
			statements = append(statements, stmt)
			changes = append(changes, &DatabaseChange{
				Model: model.Name,
				Type:  ChangeTypeAdded,
			})
			modelsAdded = append(modelsAdded, model)

			// Add audit logs hooks to every table - excluding of course
			// the audit table itself.
			if model.Name != parser.ImplicitAuditTableName {
				stmt, err = createAuditHookStmt(schema, model)
				if err != nil {
					return nil, err
				}
				statements = append(statements, stmt)
			}
			continue
		}

		existingModels = append(existingModels, model)
	}

	// Foreign key constraints for new models (done after all tables have been created)
	for _, model := range modelsAdded {
		statements = append(statements, fkConstraintsForModel(model, schema)...)
	}

	// Drop tables if models removed from schema
	tablesDeleted := map[string]bool{}
	for _, column := range columns {
		if _, ok := tablesDeleted[column.TableName]; ok {
			continue
		}

		modelName := casing.ToCamel(column.TableName)

		m := proto.FindModel(schema.Models, modelName)
		if m == nil {
			tablesDeleted[column.TableName] = true
			statements = append(statements, dropTableStmt(modelName))
			changes = append(changes, &DatabaseChange{
				Model: modelName,
				Type:  ChangeTypeRemoved,
			})
		}
	}

	// Updating columns for tables that already exist
	for _, model := range existingModels {
		tableName := casing.ToSnake(model.Name)

		tableColumns := lo.Filter(columns, func(c *ColumnRow, _ int) bool {
			return c.TableName == tableName
		})

		for _, field := range model.Fields {
			if field.Type.Type == proto.Type_TYPE_MODEL {
				continue
			}

			column, _ := lo.Find(tableColumns, func(c *ColumnRow) bool {
				return c.ColumnName == casing.ToSnake(field.Name)
			})
			if column == nil {
				// Add new column
				stmt, err := addColumnStmt(schema, model.Name, field)
				if err != nil {
					return nil, err
				}
				statements = append(statements, stmt)
				changes = append(changes, &DatabaseChange{
					Model: model.Name,
					Field: field.Name,
					Type:  ChangeTypeAdded,
				})

				// When the field added is a foreign key field, we add a corresponding foreign key constraint.
				if field.ForeignKeyInfo != nil {
					statements = append(statements, fkConstraint(field, model, schema))
				}
				continue
			}

			// Column already exists - see if any changes need to be applied
			hasChanged := false

			alterSQL, err := alterColumnStmt(schema, model.Name, field, column)
			if err != nil {
				return nil, err
			}
			if alterSQL != "" {
				statements = append(statements, alterSQL)
				hasChanged = true
			}

			uniqueConstraint, hasUniqueConstraint := lo.Find(constraints, func(c *ConstraintRow) bool {
				return c.TableName == tableName && c.ConstraintType == "u" && len(c.ConstrainedColumns) == 1 && c.ConstrainedColumns[0] == int64(column.ColumnNum)
			})

			if field.Unique && !hasUniqueConstraint {
				uniqueStmt, err := addUniqueConstraintStmt(schema, model.Name, []string{field.Name})
				if err != nil {
					return nil, err
				}

				statements = append(statements, uniqueStmt)
				hasChanged = true
			}
			if !field.Unique && hasUniqueConstraint {
				statements = append(statements, dropConstraintStmt(uniqueConstraint.TableName, uniqueConstraint.ConstraintName))
				hasChanged = true
			}

			if hasChanged {
				changes = append(changes, &DatabaseChange{
					Model: model.Name,
					Field: field.Name,
					Type:  ChangeTypeModified,
				})
			}
		}

		// Drop columns if fields removed from model
		for _, column := range tableColumns {
			field := proto.FindField(schema.Models, model.Name, casing.ToLowerCamel(column.ColumnName))
			if field == nil {
				statements = append(statements, dropColumnStmt(model.Name, column.ColumnName))
				changes = append(changes, &DatabaseChange{
					Model: model.Name,
					Field: casing.ToLowerCamel(column.ColumnName),
					Type:  ChangeTypeRemoved,
				})
			}
		}

		stmts, err := compositeUniqueConstraints(schema, model, constraints)
		if err != nil {
			return nil, err
		}

		if len(stmts) > 0 {
			statements = append(statements, stmts...)
			changes = append(changes, &DatabaseChange{
				Model: model.Name,
				Type:  ChangeTypeModified,
			})
		}
	}

	return &Migrations{
		database: database,
		Schema:   schema,
		Changes:  changes,
		SQL:      strings.TrimSpace(strings.Join(statements, "\n")),
	}, nil
}

// compositeUniqueConstraintsForModel finds all composite unique constraints in model and
// returns a map where the keys are constraint names and the keys are the field names in
// that constraint
func compositeUniqueConstraintsForModel(model *proto.Model) map[string][]string {
	uniqueConstraints := map[string][]string{}
	for _, field := range model.Fields {
		if len(field.UniqueWith) > 0 {
			fieldNames := append([]string{field.Name}, field.UniqueWith...)
			constraintName := UniqueConstraintName(model.Name, fieldNames)
			uniqueConstraints[constraintName] = fieldNames
		}
	}
	return uniqueConstraints
}

// compositeUniqueConstraints generates SQL statements for dropping or creating composite
// unique constraints for model
func compositeUniqueConstraints(schema *proto.Schema, model *proto.Model, constraints []*ConstraintRow) (statements []string, err error) {
	uniqueConstraints := compositeUniqueConstraintsForModel(model)

	for _, c := range constraints {
		if c.TableName != casing.ToSnake(model.Name) || c.ConstraintType != "u" || len(c.ConstrainedColumns) == 1 {
			continue
		}

		if _, ok := uniqueConstraints[c.ConstraintName]; ok {
			delete(uniqueConstraints, c.ConstraintName)
			continue
		}

		stmt := dropConstraintStmt(c.TableName, c.ConstraintName)
		statements = append(statements, stmt)
	}

	for _, fieldNames := range uniqueConstraints {
		stmt, err := addUniqueConstraintStmt(schema, model.Name, fieldNames)
		if err != nil {
			return nil, err
		}
		statements = append(statements, stmt)
	}

	return statements, nil
}

func keelSchemaTableExists(ctx context.Context, database db.Database) (bool, error) {

	// to_regclass docs - https://www.postgresql.org/docs/current/functions-info.html#FUNCTIONS-INFO-CATALOG-TABLE
	// translates a textual relation name to its OID ... this function will
	// return NULL rather than throwing an error if the name is not found.
	result, err := database.ExecuteQuery(ctx, "SELECT to_regclass('keel_schema') AS name")
	if err != nil {
		return false, err
	}

	return result.Rows[0]["name"] != nil, nil
}

func GetCurrentSchema(ctx context.Context, database db.Database) (*proto.Schema, error) {
	exists, err := keelSchemaTableExists(ctx, database)
	if err != nil {
		return nil, err
	}

	if !exists {
		return nil, nil
	}

	result, err := database.ExecuteQuery(ctx, "SELECT schema FROM keel_schema")
	if err != nil {
		return nil, err
	}

	if len(result.Rows) == 0 {
		return nil, ErrNoStoredSchema
	} else if len(result.Rows) > 1 {
		return nil, ErrMultipleStoredSchemas
	}

	schema, ok := result.Rows[0]["schema"].(string)
	if !ok {
		return nil, errors.New("schema could not be converted to string")
	}

	var protoSchema proto.Schema
	err = protojson.Unmarshal([]byte(schema), &protoSchema)
	if err != nil {
		return nil, err
	}

	return &protoSchema, nil
}

// fkConstraintsForModel generates foreign key constraint statements for each of fields marked as
// being foreign keys in the given model.
// present in the given model.
func fkConstraintsForModel(model *proto.Model, schema *proto.Schema) (fkStatements []string) {
	fkFields := proto.ForeignKeyFields(model)
	for _, field := range fkFields {
		stmt := fkConstraint(field, model, schema)
		fkStatements = append(fkStatements, stmt)
	}
	return fkStatements
}

// fkConstraint generates a foreign key constraint statement for the given foreign key field.
func fkConstraint(field *proto.Field, thisModel *proto.Model, schema *proto.Schema) (fkStatement string) {
	fki := field.ForeignKeyInfo
	onDelete := lo.Ternary(field.Optional, "SET NULL", "CASCADE")
	stmt := addForeignKeyConstraintStmt(
		Identifier(thisModel.Name),
		Identifier(field.Name),
		Identifier(fki.RelatedModelName),
		Identifier(fki.RelatedModelField),
		onDelete,
	)
	return stmt
}
