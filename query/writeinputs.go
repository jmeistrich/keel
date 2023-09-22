package q

import (
	"context"
	"errors"
	"fmt"

	"github.com/samber/lo"
	"github.com/teamkeel/keel/casing"
	"github.com/teamkeel/keel/proto"
	"github.com/teamkeel/keel/runtime/expressions"
	"github.com/teamkeel/keel/schema/parser"
)

// Updates the query with all set attributes defined on the action.
func (query *QueryBuilder) CaptureSetValues(ctx context.Context, schema *proto.Schema, action *proto.Action, args map[string]any) error {
	for _, setExpression := range action.SetExpressions {
		expression, err := parser.ParseExpression(setExpression.Source)
		if err != nil {
			return err
		}

		assignment, err := expression.ToAssignmentCondition()
		if err != nil {
			return err
		}

		lhsResolver := expressions.NewOperandResolver(ctx, schema, action, assignment.LHS)
		rhsResolver := expressions.NewOperandResolver(ctx, schema, action, assignment.RHS)
		operandType, err := lhsResolver.GetOperandType()
		if err != nil {
			return err
		}

		if !lhsResolver.IsDatabaseColumn() {
			return errors.New("lhs operand of assignment expression must be a model field")
		}

		value, err := rhsResolver.ResolveValue(args)
		if err != nil {
			return err
		}

		target := lo.Map(assignment.LHS.Ident.Fragments, func(f *parser.IdentFragment, _ int) string {
			return f.Fragment
		})

		currRows := []*Row{query.writeValues}

		// The model field to update.
		field := target[len(target)-1]
		targetsLessField := target[:len(target)-1]

		// If the target field is id, then we need to update the foreign key field on the previous target fragment model
		if field == "id" {
			field = fmt.Sprintf("%sId", target[len(target)-2])
			targetsLessField = target[:len(target)-2]
		}

		// Iterate through the fragments in the @set expression AND traverse the graph until we have a set of rows to update.
		for i, frag := range targetsLessField {
			nextRows := []*Row{}

			if len(currRows) == 0 {
				// We cannot set order.customer.name if the input is order.customer.id (implying an assocation).
				return fmt.Errorf("set expression operand out of range of inputs: %s. we currently only support setting fields within the input data and cannot set associated model fields", setExpression.Source)
			}

			for _, row := range currRows {
				if frag == row.target[i] {
					if i == len(targetsLessField)-1 {
						nextRows = append(nextRows, row)
					} else {
						for _, ref := range row.references {
							nextRows = append(nextRows, ref.row)
						}
						for _, refBy := range row.referencedBy {
							nextRows = append(nextRows, refBy.row)
						}
					}
				}
			}
			currRows = nextRows
		}

		// If targeting the nested model (without a field), then set the foreign key with the "id" of the assigning model.
		// For example, @set(post.user = ctx.identity) will set post.userId with ctx.identity.id.
		if operandType == proto.Type_TYPE_MODEL {
			field = fmt.Sprintf("%sId", field)
		}

		// Set the field on all rows.
		for _, row := range currRows {
			row.values[field] = value
		}
	}
	return nil
}

// Updates the query with all write inputs defined on the action.
func (query *QueryBuilder) CaptureWriteValues(ctx context.Context, schema *proto.Schema, action *proto.Action, args map[string]any) error {
	message := proto.FindValuesInputMessage(schema, action.Name)
	if message == nil {
		return nil
	}

	target := []string{casing.ToLowerCamel(action.ModelName)}

	model := proto.FindModel(schema.Models, action.ModelName)

	foreignKeys, row, err := captureWriteValuesFromMessage(ctx, schema, message, model, target, args)

	// Add any foreign keys to the root row from rows which it references.
	for k, v := range foreignKeys {
		row.values[k] = v
	}

	query.writeValues = row

	return err
}

// Parses the input data and builds a graph of row data which is organised by how this data would be stored in the database.
// Uses the protobuf schema to determine which rows are referenced by using (i.e. it determines where the foreign key sits).
func captureWriteValuesFromMessage(ctx context.Context, schema *proto.Schema, message *proto.Message, model *proto.Model, currentTarget []string, args map[string]any) (map[string]any, *Row, error) {
	// Instantiate an empty row.
	newRow := &Row{
		model:        model,
		target:       currentTarget,
		values:       map[string]any{},
		referencedBy: []*Relationship{},
		references:   []*Relationship{},
	}

	// For each field in this message either:
	//   - add its value to the current row where an input has been provided, OR
	//   - create a new row and relate it to the current row (either referencedBy or references), OR
	//   - determine that it is a primary key reference, do not create a row, and return the FK to the referencing row.
	for _, input := range message.Fields {
		field := proto.FindField(schema.Models, model.Name, input.Name)

		// If the input is not targeting a model field, then it is either a:
		//  - Message, with nested fields which we must recurse into, or an
		//  - Explicit input, which is handled elsewhere.
		if !input.IsModelField() {
			if input.Type.Type == proto.Type_TYPE_MESSAGE {

				target := append(newRow.target, casing.ToLowerCamel(input.Name))
				messageModel := proto.FindModel(schema.Models, field.Type.ModelName.Value)
				nestedMessage := proto.FindMessage(schema.Messages, input.Type.MessageName.Value)

				var foreignKeys map[string]any
				var err error

				if input.Type.Repeated {
					// A repeated field means that we have a 1:M relationship. Therefore:
					//  - we will have an array of models to parse,
					//  - these models will have foreign keys on them.

					arg, hasArg := args[input.Name]
					if !hasArg && !input.Optional {
						return nil, nil, fmt.Errorf("input argument is missing for required field %s", input.Name)
					} else if !hasArg && input.Optional {
						continue
					}

					argsArraySectioned, ok := arg.([]any)
					if !ok {
						return nil, nil, fmt.Errorf("cannot convert args to []any for key %s", input.Name)
					}

					// Create (or associate with) all the models which this model will be referenced by.
					var rows []*Row
					foreignKeys, rows, err = captureWriteValuesArrayFromMessage(ctx, schema, nestedMessage, messageModel, target, argsArraySectioned)
					if err != nil {
						return nil, nil, err
					}

					// rows will be empty if we are associating to existing models.
					if len(rows) > 0 {
						// Retrieve the foreign key model field on the related model.
						// If there are multiple relationships to the same model, then field.InverseFieldName will be
						// populated and will provide the disambiguation as to which foreign key field to use.
						foriegnKeyModelField := lo.Filter(messageModel.Fields, func(f *proto.Field, _ int) bool {
							return f.Type.Type == proto.Type_TYPE_MODEL &&
								f.Type.ModelName.Value == model.Name &&
								(field.InverseFieldName == nil || f.ForeignKeyFieldName.Value == fmt.Sprintf("%sId", field.InverseFieldName.Value))
						})

						if len(foriegnKeyModelField) != 1 {
							return nil, nil, fmt.Errorf("there needs to be exactly one foreign key field for %s", input.Name)
						}

						for _, r := range rows {
							for _, fk := range foriegnKeyModelField {
								relationship := &Relationship{
									foreignKey: fk,
									row:        r,
								}
								newRow.referencedBy = append(newRow.referencedBy, relationship)
							}
						}
					}
				} else {
					// A not-repeating field means that we have a M:1 or 1:1 relationship. Therefore:
					//  - we will have a single of model to parse,
					//  - this model will have the primary ID that needs to be referenced from the current model.

					argValue, hasArg := args[input.Name]
					if !hasArg {
						if !input.Optional {
							return nil, nil, fmt.Errorf("input argument is missing for required field %s", input.Name)
						}

						continue
					}

					if argValue == nil && !input.Nullable {
						return nil, nil, fmt.Errorf("input argument is null for non-nullable field %s", input.Name)
					}

					if argValue == nil {
						// We know this needs to be a FK on the referencing row.
						fieldName := fmt.Sprintf("%sId", target[len(target)-1])
						foreignKeys = map[string]any{
							fieldName: nil,
						}
					} else {
						argsSectioned, ok := argValue.(map[string]any)
						if !ok {
							return nil, nil, fmt.Errorf("cannot convert args to map[string]any for key %s", input.Name)
						}

						// Create (or associate with) the model which this model references.
						var row *Row
						foreignKeys, row, err = captureWriteValuesFromMessage(ctx, schema, nestedMessage, messageModel, target, argsSectioned)
						if err != nil {
							return nil, nil, err
						}

						// row will be nil if we are associating to an existing model.
						if row != nil {
							// Retrieve the foreign key model field on the this model.
							foriegnKeyModelField := lo.Filter(model.Fields, func(f *proto.Field, _ int) bool {
								return f.Type.Type == proto.Type_TYPE_MODEL && f.Type.ModelName.Value == messageModel.Name && f.Name == input.Name
							})

							if len(foriegnKeyModelField) != 1 {
								return nil, nil, fmt.Errorf("there needs to be exactly one foreign key field for %s", input.Name)
							}

							// Add foreign key to current model from the newly referenced models.
							relationship := &Relationship{
								foreignKey: foriegnKeyModelField[0],
								row:        row,
							}
							newRow.references = append(newRow.references, relationship)
						}
					}
				}

				// If any nested messages referenced a primary key, then the
				// foreign keys will be generated instead of a new row created.
				for k, v := range foreignKeys {
					newRow.values[k] = v
				}
			}

			continue
		}

		// If the input is targeting a model field, then it is either:
		//  - the id (primary key), in which case this is an association to an existing row, OR
		//  - the remaining value fields, in which case we are adding this values to the newly related model.
		if field.PrimaryKey {
			// We know this needs to be a FK on the referencing row.
			fieldName := fmt.Sprintf("%sId", input.Target[len(input.Target)-2])

			// Do not create a new row, and rather return this FK to add to the referencing row.
			return map[string]any{
				fieldName: args[input.Name],
			}, nil, nil
		} else {
			value, ok := args[input.Name]
			// Only add the arg value if it was provided as an input.
			if ok {
				newRow.values[input.Name] = value
			}
		}
	}

	return nil, newRow, nil
}

func captureWriteValuesArrayFromMessage(ctx context.Context, schema *proto.Schema, message *proto.Message, model *proto.Model, currentTarget []string, argsArray []any) (map[string]any, []*Row, error) {
	rows := []*Row{}
	foreignKeys := map[string]any{}

	// Capture all fields for each item in the array.
	for _, v := range argsArray {
		args, ok := v.(map[string]any)
		if !ok {
			return nil, nil, errors.New("cannot convert args to map[string]any")
		}

		fks, row, err := captureWriteValuesFromMessage(ctx, schema, message, model, currentTarget, args)
		if err != nil {
			return nil, nil, err
		}

		rows = append(rows, row)

		for k, v := range fks {
			foreignKeys[k] = v
		}
	}

	return foreignKeys, rows, nil
}
