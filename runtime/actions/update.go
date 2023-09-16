package actions

import (
	q "github.com/teamkeel/keel/query"
	"github.com/teamkeel/keel/runtime/common"
)

func Update(scope *Scope, input map[string]any) (res map[string]any, err error) {
	query := q.NewQuery(scope.Context, scope.Model)

	// Generate the SQL statement
	statement, err := GenerateUpdateStatement(query, scope, input)
	if err != nil {
		return nil, err
	}

	query.AppendSelect(q.IdField())
	query.AppendDistinctOn(q.IdField())
	rowToAuthorise, err := query.SelectStatement().ExecuteToSingle(scope.Context)
	if err != nil {
		return nil, err
	}

	rowsToAuthorise := []map[string]any{}
	if rowToAuthorise != nil {
		rowsToAuthorise = append(rowsToAuthorise, rowToAuthorise)
	}

	isAuthorised, err := AuthoriseAction(scope, input, rowsToAuthorise)
	if err != nil {
		return nil, err
	}

	if !isAuthorised {
		return nil, common.NewPermissionError()
	}

	// Execute database request, expecting a single result
	res, err = statement.ExecuteToSingle(scope.Context)

	// TODO: if error is multiple rows affected then rollback transaction
	if err != nil {
		return nil, err
	}

	if res == nil {
		return nil, common.NewNotFoundError()
	}

	return res, err
}

func GenerateUpdateStatement(query *q.QueryBuilder, scope *Scope, input map[string]any) (*q.Statement, error) {
	values, ok := input["values"].(map[string]any)
	if !ok {
		values = map[string]any{}
	}

	err := query.CaptureWriteValues(scope.Context, scope.Schema, scope.Action, values)
	if err != nil {
		return nil, err
	}

	err = query.CaptureSetValues(scope.Context, scope.Schema, scope.Action, values)
	if err != nil {
		return nil, err
	}

	where, ok := input["where"].(map[string]any)
	if !ok {
		where = map[string]any{}
	}

	err = query.ApplyImplicitFilters(scope.Context, scope.Schema, scope.Action, where)
	if err != nil {
		return nil, err
	}

	err = query.ApplyExplicitFilters(scope.Context, scope.Schema, scope.Action, where)
	if err != nil {
		return nil, err
	}

	// Return the updated row
	query.AppendReturning(q.AllFields())

	return query.UpdateStatement(), nil
}
