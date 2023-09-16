package actions

import (
	q "github.com/teamkeel/keel/query"
	"github.com/teamkeel/keel/runtime/common"
)

func Delete(scope *Scope, input map[string]any) (*string, error) {
	query := q.NewQuery(scope.Context, scope.Model)

	// Generate the SQL statement
	statement, err := GenerateDeleteStatement(query, scope, input)
	if err != nil {
		return nil, err
	}

	query.AppendSelect(q.IdField())
	query.AppendDistinctOn(q.IdField())
	res, err := query.SelectStatement().ExecuteToSingle(scope.Context)
	if err != nil {
		return nil, err
	}

	rowsToAuthorise := []map[string]any{}
	if res != nil {
		rowsToAuthorise = append(rowsToAuthorise, res)
	}

	isAuthorised, err := AuthoriseAction(scope, input, rowsToAuthorise)
	if err != nil {
		return nil, err
	}

	if !isAuthorised {
		return nil, common.NewPermissionError()
	}

	// Execute database request
	row, err := statement.ExecuteToSingle(scope.Context)

	// TODO: if the error is multiple rows affected then rollback transaction
	if err != nil {
		return nil, err
	}

	if row == nil {
		return nil, common.NewNotFoundError()
	}

	id, _ := row["id"].(string)
	return &id, err
}

func GenerateDeleteStatement(query *q.QueryBuilder, scope *Scope, input map[string]any) (*q.Statement, error) {
	err := query.ApplyImplicitFilters(scope.Context, scope.Schema, scope.Action, input)
	if err != nil {
		return nil, err
	}

	err = query.ApplyExplicitFilters(scope.Context, scope.Schema, scope.Action, input)
	if err != nil {
		return nil, err
	}

	query.AppendReturning(q.Field("id"))

	return query.DeleteStatement(), nil
}
