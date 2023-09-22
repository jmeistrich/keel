package q

import (
	"context"
	"fmt"

	"github.com/teamkeel/keel/proto"
	"github.com/teamkeel/keel/schema/parser"
)

// Applies all implicit input filters to the query.
func ApplyImplicitFilters(query *QueryBuilder, action *proto.Action, args map[string]any) (*QueryBuilder, error) {
	message := proto.FindWhereInputMessage(query.schema, action.Name)
	if message == nil {
		return query, nil
	}

	for _, input := range message.Fields {
		if !input.IsModelField() {
			// Skip if this is an explicit input (probably used in a @where)
			continue
		}

		fieldName := input.Name
		value, ok := args[fieldName]

		if !ok {
			return query, fmt.Errorf("this expected input: %s, is missing from this provided args map: %+v", fieldName, args)
		}

		err := query.whereByImplicitFilter(schema, action, input.Target, Equals, value)
		if err != nil {
			return query, err
		}

		// Implicit input filters are ANDed together
		query.And()
	}

	return query, nil
}

// Applies all exlicit where attribute filters to the query.
func (query *QueryBuilder) ApplyExplicitFilters(ctx context.Context, schema *proto.Schema, action *proto.Action, args map[string]any) error {
	for _, where := range action.WhereExpressions {
		expression, err := parser.ParseExpression(where.Source)
		if err != nil {
			return err
		}

		// Resolve the database statement for this expression
		query, err = WithExpressionFilter(query, action, expression, args)
		if err != nil {
			return err
		}

		// Where attributes are ANDed together
		query.And()
	}

	return nil
}
