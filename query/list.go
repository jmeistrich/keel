package q

import (
	"fmt"

	"github.com/teamkeel/keel/proto"
)

func ApplyImplicitFiltersForList(query *QueryBuilder, action *proto.Action, args map[string]any) (*QueryBuilder, error) {
	message := proto.FindWhereInputMessage(query.schema, action.Name)
	if message == nil {
		return query, nil
	}

	model := proto.FindModel(query.schema.Models, action.ModelName)

	return applyImplicitFiltersFromMessage(query, action, message, model, args)
}

func applyImplicitFiltersFromMessage(query *QueryBuilder, action *proto.Action, message *proto.Message, model *proto.Model, args map[string]any) (*QueryBuilder, error) {

	for _, input := range message.Fields {
		field := proto.FindField(query.schema.Models, model.Name, input.Name)

		// If the input is not targeting a model field, then it is either a:
		//  - Message, with nested fields which we must recurse into, or an
		//  - Explicit input, which is handled elsewhere.
		if !input.IsModelField() {
			if input.Type.Type == proto.Type_TYPE_MESSAGE {
				messageModel := proto.FindModel(query.schema.Models, field.Type.ModelName.Value)
				nestedMessage := proto.FindMessage(query.schema.Messages, input.Type.MessageName.Value)

				argsSectioned, ok := args[input.Name].(map[string]any)
				if !ok {
					if input.Optional {
						continue
					}
					return nil, fmt.Errorf("cannot convert args to map[string]any for key %s", input.Name)
				}

				var err error
				query, err = applyImplicitFiltersFromMessage(query, action, nestedMessage, messageModel, argsSectioned)
				if err != nil {
					return nil, err
				}
			}
			continue
		}

		fieldName := input.Name
		value, ok := args[fieldName]

		// Not found in arguments
		if !ok {
			if input.Optional {
				continue
			}
			return nil, fmt.Errorf("did not find required '%s' input in where clause", fieldName)
		}

		valueMap, ok := value.(map[string]any)

		// Cannot be parsed into map
		if !ok {
			return nil, fmt.Errorf("'%s' input value %v is not in correct format", fieldName, value)
		}

		for operatorStr, operand := range valueMap {
			operator, err := apiOperatorToActionOperator(operatorStr)
			if err != nil {
				return nil, err
			}

			// Resolve the database statement for this expression
			query, err = whereByImplicitFilter(schema, action, input.Target, operator, operand)
			if err != nil {
				return nil, err
			}

			// Implicit input conditions are ANDed together
			query.And()
		}
	}

	return query, nil
}

// Applies schema-defined @orderBy ordering to the query.
func (query *QueryBuilder) ApplySchemaOrdering(action *proto.Action) error {
	for _, orderBy := range action.OrderBy {
		direction, err := toSql(orderBy.Direction)
		if err != nil {
			return err
		}

		query.AppendOrderBy(Field(orderBy.FieldName), direction)
	}

	return nil
}

// Applies ordering of @sortable fields to the query.
func (query *QueryBuilder) ApplyRequestOrdering(orderBy []any) error {
	for _, item := range orderBy {
		obj := item.(map[string]any)
		for field, direction := range obj {
			query.AppendOrderBy(Field(field), direction.(string))
		}
	}

	return nil
}
