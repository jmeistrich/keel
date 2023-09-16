package actions

import (
	"context"

	"github.com/teamkeel/keel/db"
	q "github.com/teamkeel/keel/query"
	"github.com/teamkeel/keel/runtime/common"
)

func Create(scope *Scope, input map[string]any) (res map[string]any, err error) {
	database, err := db.GetDatabase(scope.Context)
	if err != nil {
		return nil, err
	}

	err = database.Transaction(scope.Context, func(ctx context.Context) error {
		scope := scope.WithContext(ctx)
		query := q.NewQuery(scope.Context, scope.Model)

		// Generate the SQL statement
		statement, err := GenerateCreateStatement(query, scope, input)
		if err != nil {
			return err
		}

		// Execute database request, expecting a single result
		res, err = statement.ExecuteToSingle(scope.Context)
		if err != nil {
			return err
		}

		isAuthorised, err := AuthoriseAction(scope, input, []map[string]any{res})
		if err != nil {
			return err
		}

		if !isAuthorised {
			return common.NewPermissionError()
		}

		return nil
	})

	return res, err
}

func GenerateCreateStatement(query *q.QueryBuilder, scope *Scope, input map[string]any) (*q.Statement, error) {
	err := query.CaptureWriteValues(scope.Context, scope.Schema, scope.Action, input)
	if err != nil {
		return nil, err
	}

	err = query.CaptureSetValues(scope.Context, scope.Schema, scope.Action, input)
	if err != nil {
		return nil, err
	}

	// Return the inserted row
	query.AppendReturning(q.AllFields())

	return query.InsertStatement(), nil
}
