package expression

import (
	"fmt"
	"github.com/samber/lo"
	"github.com/teamkeel/keel/schema/expressions"
	"github.com/teamkeel/keel/schema/parser"
	"github.com/teamkeel/keel/schema/validation/errorhandling"
	"golang.org/x/exp/slices"
)

type Rule func(asts []*parser.AST, expression *parser.Expression, context expressions.ExpressionContext) []error

func ValidateExpression(asts []*parser.AST, expression *parser.Expression, rules []Rule, context expressions.ExpressionContext) (errors []error) {
	for _, rule := range rules {
		errs := rule(asts, expression, context)
		errors = append(errors, errs...)
	}

	return errors
}

// Validates that the field type has a zero value (no expression necessary).
// Zero values are the following:
// * Text -> ""
// * Number => 0
// * Boolean -> false
// * ID -> a ksuid
// * Timestamp -> now
func DefaultCanUseZeroValueRule(asts []*parser.AST, attr *parser.AttributeNode, context expressions.ExpressionContext) (errors []*errorhandling.ValidationError) {
	typesWithZeroValue := []string{"Text", "Number", "Boolean", "ID", "Timestamp"}

	if !lo.Contains(typesWithZeroValue, context.Field.Type) {
		errors = append(errors,
			errorhandling.NewValidationError(
				errorhandling.ErrorDefaultExpressionNeeded,
				errorhandling.TemplateLiterals{},
				attr,
			),
		)
		return errors
	}

	return errors
}

// Validates that the expression has a single value and it matches the expected type
func ValueTypechecksRule(asts []*parser.AST, expression *parser.Expression, context expressions.ExpressionContext) (errors []error) {
	conditions := expression.Conditions()
	if len(conditions) != 1 {
		errors = append(errors,
			errorhandling.NewValidationError(
				errorhandling.ErrorExpressionMultipleConditions,
				errorhandling.TemplateLiterals{},
				expression,
			),
		)
		return errors
	}
	condition := conditions[0]

	if condition.RHS != nil {
		errors = append(errors,
			errorhandling.NewValidationError(
				errorhandling.ErrorDefaultExpressionOperatorPresent,
				errorhandling.TemplateLiterals{
					Literals: map[string]string{
						"Op": condition.Operator.Symbol,
					},
				},
				condition,
			),
		)
		return errors
	}
	operand := condition.LHS

	resolver := expressions.NewOperandResolver(
		operand,
		asts,
		&context,
		expressions.OperandPositionLhs,
	)
	expressionScopeEntity, err := resolver.Resolve()
	if err != nil {
		errors = append(errors, err.ToValidationError())
		return errors
	}

	expectedType := context.Field.Type
	resolvedType := expressionScopeEntity.GetType()

	if expectedType != resolvedType {
		errors = append(errors,
			errorhandling.NewValidationError(
				errorhandling.ErrorExpressionFieldTypeMismatch,
				errorhandling.TemplateLiterals{
					Literals: map[string]string{
						"Exp":       operand.ToString(),
						"Type":      resolvedType,
						"FieldName": context.Field.Name.Value,
						"FieldType": expectedType,
					},
				},
				expression,
			),
		)
		return errors
	}

	return errors
}

// Validates that all operands resolve correctly
// This handles operands of all types including operands such as model.associationA.associationB
// as well as simple value types such as string, number, bool etc
func OperandResolutionRule(asts []*parser.AST, condition *parser.Condition, context expressions.ExpressionContext) (errors []error) {
	resolver := expressions.NewConditionResolver(condition, asts, &context)
	_, _, errs := resolver.Resolve()
	errors = append(errors, errs...)

	return errors
}

// Validates that all conditions in an expression use assignment
func OperatorAssignmentRule(asts []*parser.AST, expression *parser.Expression, context expressions.ExpressionContext) (errors []error) {
	conditions := expression.Conditions()

	for _, condition := range conditions {
		// If there is no operator, then it means there is no rhs
		if condition.Operator == nil {
			continue
		}

		if condition.Type() != parser.AssignmentCondition {
			correction := errorhandling.NewCorrectionHint([]string{"="}, condition.Operator.Symbol)

			errors = append(errors,
				errorhandling.NewValidationError(
					errorhandling.ErrorForbiddenExpressionOperation,
					errorhandling.TemplateLiterals{
						Literals: map[string]string{
							"Operator":   condition.Operator.Symbol,
							"Suggestion": correction.ToString(),
							"Attribute":  fmt.Sprintf("@%s", context.Attribute.Name.Value),
						},
					},
					condition.Operator,
				),
			)

			continue
		}

		errors = append(errors, runSideEffectOperandRules(asts, condition, context, parser.AssignmentOperators)...)
	}

	return errors
}

// Validates that all conditions in an expression use logical operators
func OperatorLogicalRule(asts []*parser.AST, expression *parser.Expression, context expressions.ExpressionContext) (errors []error) {
	conditions := expression.Conditions()

	for _, condition := range conditions {
		// If there is no operator, then it means there is no rhs
		if condition.Operator == nil {
			continue
		}
		correction := errorhandling.NewCorrectionHint([]string{"=="}, condition.Operator.Symbol)

		if condition.Type() != parser.LogicalCondition {
			errors = append(errors,
				errorhandling.NewValidationError(
					errorhandling.ErrorForbiddenExpressionOperation,
					errorhandling.TemplateLiterals{
						Literals: map[string]string{
							"Operator":   condition.Operator.Symbol,
							"Attribute":  fmt.Sprintf("@%s", context.Attribute.Name.Value),
							"Suggestion": correction.ToString(),
						},
					},
					condition.Operator,
				),
			)

			continue
		}

		errors = append(errors, runSideEffectOperandRules(asts, condition, context, parser.LogicalOperators)...)
	}

	return errors
}

// Validates that no value conditions are used
func PreventValueConditionRule(asts []*parser.AST, expression *parser.Expression, context expressions.ExpressionContext) (errors []error) {
	conditions := expression.Conditions()

	for _, condition := range conditions {
		if condition.Type() == parser.ValueCondition {
			errors = append(errors,
				errorhandling.NewValidationError(
					errorhandling.ErrorForbiddenValueCondition,
					errorhandling.TemplateLiterals{
						Literals: map[string]string{
							"Value":      condition.ToString(),
							"Attribute":  fmt.Sprintf("@%s", context.Attribute.Name.Value),
							"Suggestion": fmt.Sprintf("%s = xxx", condition.ToString()),
						},
					},
					condition,
				),
			)
		}
	}

	return errors
}

func InvalidOperatorForOperandsRule(asts []*parser.AST, condition *parser.Condition, context expressions.ExpressionContext, permittedOperators []string) (errors []error) {
	resolver := expressions.NewConditionResolver(condition, asts, &context)
	resolvedLHS, resolvedRHS, _ := resolver.Resolve()

	// If there is no operator, then we are not interested in validating this rule
	if condition.Operator == nil {
		return nil
	}

	allowedOperatorsLHS := resolvedLHS.AllowedOperators()
	allowedOperatorsRHS := resolvedRHS.AllowedOperators()

	if resolvedLHS.IsRepeated() && resolvedRHS.IsRepeated() {
		return append(errors, errorhandling.NewValidationError(
			errorhandling.ErrorExpressionForbiddenArrayLHS,
			errorhandling.TemplateLiterals{
				Literals: map[string]string{
					"LHS": condition.LHS.ToString(),
				},
			},
			condition.Operator,
		))
	}

	if slices.Equal(allowedOperatorsLHS, allowedOperatorsRHS) {
		if !lo.Contains(allowedOperatorsLHS, condition.Operator.Symbol) {
			collection := lo.Intersect(permittedOperators, allowedOperatorsLHS)
			corrections := errorhandling.NewCorrectionHint(collection, condition.Operator.Symbol)

			errors = append(errors, errorhandling.NewValidationError(
				errorhandling.ErrorForbiddenOperator,
				errorhandling.TemplateLiterals{
					Literals: map[string]string{
						"Type":       resolvedLHS.GetType(),
						"Operator":   condition.Operator.Symbol,
						"Suggestion": corrections.ToString(),
					},
				},
				condition.Operator,
			))
		}
	} else {
		if resolvedRHS.IsRepeated() {
			if !lo.Contains(allowedOperatorsRHS, condition.Operator.Symbol) {

				errors = append(errors, errorhandling.NewValidationError(
					errorhandling.ErrorExpressionArrayMismatchingOperator,
					errorhandling.TemplateLiterals{
						Literals: map[string]string{
							"RHS":      condition.RHS.ToString(),
							"RHSType":  resolvedRHS.GetType(),
							"Operator": condition.Operator.Symbol,
						},
					},
					condition.Operator,
				))
			}
		}
	}

	return errors
}

// OperandTypesMatchRule checks that the left-hand side and right-hand side are
// compatible.
//   - LHS and RHS are the same type
//   - LHS and RHS are of _compatible_ types
//   - LHS is of type T and RHS is an array of type T
//   - LHS or RHS is an optional field and the other side is an explicit null
func OperandTypesMatchRule(asts []*parser.AST, condition *parser.Condition, context expressions.ExpressionContext) (errors []error) {
	resolver := expressions.NewConditionResolver(condition, asts, &context)
	resolvedLHS, resolvedRHS, _ := resolver.Resolve()

	// If either side fails to resolve then no point checking compatibility
	if resolvedLHS == nil || resolvedRHS == nil {
		return nil
	}

	// Case: LHS and RHS are the same type
	if resolvedLHS.GetType() == resolvedRHS.GetType() {
		return nil
	}

	// Case: LHS and RHS are of _compatible_ types
	// Possibly this only applies to Date and Timestamp
	comparable := [][]string{
		{parser.FieldTypeDate, parser.FieldTypeDatetime},
	}
	for _, c := range comparable {
		if lo.Contains(c, resolvedLHS.GetType()) && lo.Contains(c, resolvedRHS.GetType()) {
			return nil
		}
	}

	// Case: LHS is of type T and RHS is an array of type T
	if resolvedRHS.GetType() == parser.TypeArray {

		// First check array contains only one type
		var arrayType string
		valid := true
		for i, item := range resolvedRHS.Array {
			if i == 0 {
				arrayType = item.GetType()
				continue
			}

			if arrayType != item.GetType() {
				valid = false
				errors = append(errors,
					errorhandling.NewValidationError(
						errorhandling.ErrorExpressionMixedTypesInArrayLiteral,
						errorhandling.TemplateLiterals{
							Literals: map[string]string{
								"Item": item.Literal.ToString(),
								"Type": arrayType,
							},
						},
						item.Literal,
					),
				)
			}
		}

		if !valid {
			return errors
		}

		// Now we know the RHS is an array of type T we can check if
		// the LHS is also of type T
		if arrayType == resolvedLHS.GetType() {
			return nil
		}
	}

	// Case: LHS or RHS is an optional field and the other side is an explicit null
	if resolvedLHS.IsOptional() && resolvedRHS.IsNull() ||
		resolvedRHS.IsOptional() && resolvedLHS.IsNull() {
		return nil
	}

	lhsType := resolvedLHS.GetType()
	if resolvedLHS.IsRepeated() {
		if resolvedLHS.Array != nil {
			lhsType = "an array of " + resolvedLHS.Array[0].GetType()
		} else {
			lhsType = "an array of " + lhsType
		}
	}

	rhsType := resolvedRHS.GetType()
	if resolvedRHS.IsRepeated() {
		if resolvedRHS.Array != nil {
			rhsType = "an array of " + resolvedRHS.Array[0].GetType()
		} else {
			rhsType = "an array of " + rhsType
		}
	}

	// LHS and RHS types do not match, report error
	errors = append(errors,
		errorhandling.NewValidationError(
			errorhandling.ErrorExpressionTypeMismatch,
			errorhandling.TemplateLiterals{
				Literals: map[string]string{
					"Operator": condition.Operator.Symbol,
					"LHS":      condition.LHS.ToString(),
					"LHSType":  lhsType,
					"RHS":      condition.RHS.ToString(),
					"RHSType":  rhsType,
				},
			},
			condition,
		),
	)

	return errors
}
func runSideEffectOperandRules(asts []*parser.AST, condition *parser.Condition, context expressions.ExpressionContext, permittedOperators []string) (errors []error) {
	errors = append(errors, OperandResolutionRule(asts, condition, context)...)

	if len(errors) > 0 {
		return errors
	}

	errors = append(errors, OperandTypesMatchRule(asts, condition, context)...)

	if len(errors) > 0 {
		return errors
	}

	errors = append(errors, InvalidOperatorForOperandsRule(asts, condition, context, permittedOperators)...)

	return errors
}
