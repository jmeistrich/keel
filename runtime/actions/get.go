package actions

import (
	q "github.com/teamkeel/keel/query"
	"github.com/teamkeel/keel/runtime/common"
)

func Get(scope *Scope, input map[string]any) (map[string]any, error) {
	query := q.NewQuery(scope.Context, scope.Model)

	// Generate the SQL statement
	statement, err := GenerateGetStatement(query, scope, input)
	if err != nil {
		return nil, err
	}

	// Execute database request, expecting a single result.
	res, err := statement.ExecuteToSingle(scope.Context)
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

	return res, err
}

func GenerateGetStatement(query *q.QueryBuilder, scope *Scope, input map[string]any) (*q.Statement, error) {
	err := query.ApplyImplicitFilters(scope.Context, scope.Schema, scope.Action, input)
	if err != nil {
		return nil, err
	}

	err = query.ApplyExplicitFilters(scope.Context, scope.Schema, scope.Action, input)
	if err != nil {
		return nil, err
	}

	// Select all columns and distinct on id
	query.AppendSelect(q.AllFields())
	query.AppendDistinctOn(q.IdField())

	return query.SelectStatement(), nil
}
