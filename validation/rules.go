package validation

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/alecthomas/participle/v2/lexer"
	"github.com/iancoleman/strcase"
	"github.com/teamkeel/keel/expressions"
	"github.com/teamkeel/keel/parser"
)

var (
	ReservedNames  = []string{"id", "createdAt", "updatedAt"}
	ReservedModels = []string{"query"}
)

// A Validator knows how to validate a parsed Keel schema.
//
// Conceptually we are validating a single schema.
// But the Validator supports it being "delivered" as a collection
// of *parser.Schema objects - to match up with a user's schema likely
// being written across N files.
//
// We use a []Input to model the inputs - so that the original file names are
// available for error reporting. (TODO although that is not implemented yet).
type Validator struct {
	inputs []Input
}

func NewValidator(inputs []Input) *Validator {
	return &Validator{
		inputs: inputs,
	}
}

func (v *Validator) RunAllValidators() error {
	validatorFuncs := []func([]Input) []error{
		modelsUpperCamel,
		fieldsOpsFuncsLowerCamel,
		fieldNamesMustBeUniqueInAModel,
		operationsUniqueGlobally,
		operationFunctionInputs,
		noReservedFieldNames,
		noReservedModelNames,
		operationUniqueFieldInput,
		supportedFieldTypes,
		supportedAttributeTypes,
		modelsGloballyUnique,
	}
	var errors []*ValidationError
	for _, vf := range validatorFuncs {
		err := vf(v.inputs)

		for _, e := range err {
			if verrs, ok := e.(*ValidationError); ok {

				errors = append(errors, verrs)
			}
		}
	}

	if len(errors) > 0 {
		return ValidationErrors{Errors: errors}
	}

	return nil
}

// Models are UpperCamel
func modelsUpperCamel(inputs []Input) []error {
	var errors []error
	for _, input := range inputs {
		schema := input.ParsedSchema
		for _, decl := range schema.Declarations {
			if decl.Model == nil {
				continue
			}
			// todo - these MustCompile regex would be better at module scope, to
			// make the MustCompile panic a load-time thing rather than a runtime thing.
			reg := regexp.MustCompile("([A-Z][a-z0-9]+)+")

			if reg.FindString(decl.Model.Name) != decl.Model.Name {
				message := strcase.ToCamel(strings.ToLower(decl.Model.Name))
				hint := NewHint(message)

				errors = append(
					errors,
					validationError(
						fmt.Sprintf("you have a model name that is not UpperCamel %s", decl.Model.Name),
						fmt.Sprintf("%s is not UpperCamel", decl.Model.Name),
						hint.ToString(),
						decl.Model.Pos,
					),
				)
			}
		}
	}

	return errors
}

//Fields/operations are lowerCamel
func fieldsOpsFuncsLowerCamel(inputs []Input) []error {
	var errors []error
	for _, input := range inputs {
		schema := input.ParsedSchema

		for _, decl := range schema.Declarations {
			if decl.Model == nil {
				continue
			}
			for _, model := range decl.Model.Sections {
				for _, field := range model.Fields {
					if field.BuiltIn {
						continue
					}
					if strcase.ToLowerCamel(field.Name) != field.Name {
						errors = append(errors, validationError(fmt.Sprintf("you have a field name that is not lowerCamel %s", field.Name),
							fmt.Sprintf("%s isn't lower camel", field.Name),
							strcase.ToLowerCamel(strings.ToLower(field.Name)),
							field.Pos))

					}
				}
				for _, function := range model.Operations {
					if strcase.ToLowerCamel(function.Name) != function.Name {
						errors = append(errors, validationError(fmt.Sprintf("you have a function name that is not lowerCamel %s", function.Name),
							fmt.Sprintf("%s isn't lower camel", function.Name),
							strcase.ToLowerCamel(strings.ToLower(function.Name)),
							function.Pos))

					}
				}
			}
		}
	}

	return errors
}

//Field names must be unique in a model
func fieldNamesMustBeUniqueInAModel(inputs []Input) []error {
	var errors []error
	for _, input := range inputs {
		schema := input.ParsedSchema
		for _, model := range schema.Declarations {
			if model.Model == nil {
				continue
			}
			for _, sections := range model.Model.Sections {
				fieldNames := map[string]bool{}
				for _, name := range sections.Fields {
					if _, ok := fieldNames[name.Name]; ok {
						errors = append(errors, validationError(
							fmt.Sprintf("you have duplicate field names %s", name.Name),
							fmt.Sprintf("%s is duplicated", name.Name),
							fmt.Sprintf(`Remove '%s' on line %v`, name.Name, name.Pos.Line),
							name.Pos))

					}
					fieldNames[name.Name] = true
				}
			}
		}
	}
	return errors
}

type GlobalOperations struct {
	Name  string
	Model string
	Pos   lexer.Position
}

func uniqueOperationsGlobally(inputs []Input) []GlobalOperations {
	var globalOperations []GlobalOperations
	for _, input := range inputs {
		schema := input.ParsedSchema
		for _, declaration := range schema.Declarations {
			if declaration.Model == nil {
				continue
			}
			for _, sec := range declaration.Model.Sections {
				for _, operation := range sec.Operations {
					globalOperations = append(globalOperations, GlobalOperations{
						Name: operation.Name, Model: declaration.Model.Name, Pos: operation.Pos,
					})
				}
			}
		}
	}
	return globalOperations
}

//Operations must be globally unique
func operationsUniqueGlobally(inputs []Input) []error {
	var errors []error
	var operationNames []string

	globalOperations := uniqueOperationsGlobally(inputs)

	for _, name := range globalOperations {
		operationNames = append(operationNames, name.Name)
	}
	duplicates := findDuplicates(operationNames)

	if len(duplicates) == 0 {
		return nil
	}

	var duplicationOperations []GlobalOperations

	for _, operation := range globalOperations {
		for _, duplicate := range duplicates {
			if operation.Name == duplicate {
				duplicationOperations = append(duplicationOperations, operation)
			}
		}
	}

	for _, operation := range duplicationOperations {
		errors = append(errors, validationError(
			fmt.Sprintf("you have duplicate operations Model:%s Name:%s", operation.Model, operation.Name),
			fmt.Sprintf("%s is duplicated", operation.Name),
			fmt.Sprintf(`Remove '%s' on line %v`, operation.Name, operation.Pos.Line),
			operation.Pos))

	}

	return errors
}

type operationFunctionInputFields struct {
	Fields []*parser.ActionArg
	Pos    lexer.Position
}

//Inputs of operations/functions must be model fields
func operationFunctionInputs(inputs []Input) []error {
	var errors []error

	operationFields := make(map[string]*operationFunctionInputFields, 0)
	functionFields := make(map[string]*operationFunctionInputFields, 0)

	for _, input := range inputs {
		schema := input.ParsedSchema

		for _, declaration := range schema.Declarations {
			if declaration.Model == nil {
				continue
			}
			for _, modelSection := range declaration.Model.Sections {
				for _, operation := range modelSection.Operations {
					if len(operation.Arguments) == 0 {
						continue
					}
					operationFields[operation.Name] = &operationFunctionInputFields{
						Fields: operation.Arguments,
						Pos:    operation.Pos,
					}
				}
			}

		}

		operationFields = findInvalidOpsFunctionInputs(inputs, operationFields)
	}
	for _, input := range inputs {
		schema := input.ParsedSchema

		for _, declaration := range schema.Declarations {
			if declaration.Model == nil {
				continue
			}
			for _, modelSection := range declaration.Model.Sections {
				for _, function := range modelSection.Functions {
					if len(function.Arguments) == 0 {
						continue
					}
					functionFields[function.Name] = &operationFunctionInputFields{
						Fields: function.Arguments,
						Pos:    function.Pos,
					}
				}
			}

		}

		functionFields = findInvalidOpsFunctionInputs(inputs, functionFields)
	}

	errors = append(errors, buildErrorInvalidInputs(operationFields)...)
	errors = append(errors, buildErrorInvalidInputs(functionFields)...)

	return errors
}

//No reserved field names (id, createdAt, updatedAt)
func noReservedFieldNames(inputs []Input) []error {
	var errors []error
	for _, input := range inputs {
		schema := input.ParsedSchema
		for _, name := range ReservedNames {
			for _, dec := range schema.Declarations {
				if dec.Model == nil {
					continue
				}
				for _, modelSection := range dec.Model.Sections {
					for _, field := range modelSection.Fields {
						if field.BuiltIn {
							continue
						}
						if strings.EqualFold(name, field.Name) {
							errors = append(errors, validationError(fmt.Sprintf("you have a reserved field name %s", field.Name),
								fmt.Sprintf("cannot use %s", field.Name),
								fmt.Sprintf("You cannot use %s as field name, it is reserved, try %ser", field.Name, field.Name),
								field.Pos))
						}
					}
				}
			}
		}
	}

	return errors
}

//No reserved model name (query)
func noReservedModelNames(inputs []Input) []error {
	var errors []error
	for _, input := range inputs {
		schema := input.ParsedSchema
		for _, name := range ReservedModels {
			for _, dec := range schema.Declarations {
				if dec.Model == nil {
					continue
				}
				if strings.EqualFold(name, dec.Model.Name) {
					errors = append(errors, validationError(fmt.Sprintf("you have a reserved model name %s", dec.Model.Name),
						fmt.Sprintf("%s is reserved", dec.Model.Name),
						fmt.Sprintf("You cannot use %s as a model name, it is reserved, try %ser", dec.Model.Name, dec.Model.Name),
						dec.Model.Pos))

				}
			}
		}
	}

	return errors
}

//GET operation must take a unique field as an input (or a unique combinations of inputs)
func operationUniqueFieldInput(inputs []Input) []error {
	var errors []error
	var fields []*parser.ModelField

	for _, input := range inputs {
		schema := input.ParsedSchema

		for _, dec := range schema.Declarations {
			if dec.Model == nil {
				continue
			}

			for _, section := range dec.Model.Sections {
				fields = append(fields, section.Fields...)
			}
		}
	}

	for _, input := range inputs {
		schema := input.ParsedSchema
		for _, dec := range schema.Declarations {
			if dec.Model == nil {
				continue
			}

			for _, section := range dec.Model.Sections {
				if len(section.Operations) == 0 {
					continue
				}
				nonFieldAttrs := make(map[string]bool, 0)
				for _, operation := range section.Operations {
					nonFieldAttrs[operation.Name] = false

					if operation.Type != parser.ActionTypeGet {
						continue
					}

					isValid := false

					for _, field := range fields {
						if len(operation.Arguments) != 1 && len(operation.Attributes) > 0 {
							validAttrs := checkAttributeExpressions(operation.Attributes, dec.Model.Name, field)
							if validAttrs {
								nonFieldAttrs[operation.Name] = true
								isValid = true
							}
						}

						if !nonFieldAttrs[operation.Name] && len(operation.Arguments) != 1 {
							continue
						}

						if !nonFieldAttrs[operation.Name] {
							isValid = checkFuncArgsUnique(operation, fields)
						}
					}

					if !isValid {
						errors = append(errors, validationError(
							fmt.Sprintf("operation %s must take a unique field as an input", operation.Name),
							fmt.Sprintf("%s requires a unique field", operation.Name),
							"Are you sure you are using a unique field?",
							operation.Pos))
					}
				}
			}
		}
	}

	return errors
}

func checkAttributeExpressions(input []*parser.Attribute, model string, field *parser.ModelField) bool {
	var isValid bool

	for _, attr := range input {
		for _, attrArg := range attr.Arguments {
			if len(field.Attributes) == 0 {
				continue
			}
			for _, at := range field.Attributes {
				if at.Name != "unique" {
					continue
				}
				ok := expressions.IsAssignment(attrArg.Expression)
				if !ok {
					continue
				}
				if len(attrArg.Expression.Or) == 0 {
					continue
				}

				condition, err := expressions.ToAssignmentCondition(attrArg.Expression)
				if err != nil {
					continue
				}

				lhsOk := checkAssignmentFields(condition.LHS, model, field)
				if lhsOk {
					isValid = true
				}
				rhsOk := checkAssignmentFields(condition.RHS, model, field)
				if rhsOk {
					isValid = true
				}
			}
		}
	}

	return isValid
}

func checkAssignmentFields(indents *expressions.Value, model string, field *parser.ModelField) bool {
	if indents.Ident[0] != strings.ToLower(model) {
		return false
	}
	return indents.Ident[1] == field.Name
}

func checkFuncArgsUnique(function *parser.ModelAction, fields []*parser.ModelField) bool {
	isValid := false
	arg := function.Arguments[0]

	for _, field := range fields {
		if field.Name != arg.Name {
			continue
		}

		for _, attr := range field.Attributes {
			if attr.Name == "unique" {
				isValid = true
			}
			if attr.Name == "primaryKey" {
				isValid = true
			}
		}
	}

	return isValid
}

//Supported field types
func supportedFieldTypes(inputs []Input) []error {
	var errors []error

	var fieldTypes = map[string]bool{"Text": true, "Date": true, "Timestamp": true, "Image": true, "Boolean": true, "Enum": true, "Identity": true, parser.FieldTypeID: true}

	for _, input := range inputs {
		schema := input.ParsedSchema

		// Append all model names to the supported types definition
		for _, dec := range schema.Declarations {
			if dec.Model != nil {
				fieldTypes[dec.Model.Name] = true
			}
		}

		for _, dec := range schema.Declarations {
			if dec.Model == nil {
				continue
			}

			for _, section := range dec.Model.Sections {
				for _, field := range section.Fields {
					if _, ok := fieldTypes[field.Type]; !ok {
						availableTypes := []string{}

						for fieldType := range fieldTypes {
							if len(fieldType) > 0 {
								availableTypes = append(availableTypes, fieldType)
							}
						}

						sort.Strings(availableTypes)

						hint := NewCorrectionHint(availableTypes, field.Type)

						errors = append(errors, validationError(
							fmt.Sprintf("field %s has an unsupported type %s", field.Name, field.Type),
							fmt.Sprintf("%s isn't supported", field.Type),
							hint.ToString(),
							field.Pos))
					}
				}
			}
		}
	}

	return errors
}

func findModels(inputs []Input) []*parser.Model {
	models := []*parser.Model{}
	for _, input := range inputs {
		for _, decl := range input.ParsedSchema.Declarations {
			if decl.Model != nil {
				models = append(models, decl.Model)
			}
		}
	}
	return models
}

//Models are globally unique
func modelsGloballyUnique(inputs []Input) []error {
	var errors []error
	seenModelNames := map[string]bool{}

	for _, model := range findModels(inputs) {
		if _, ok := seenModelNames[model.Name]; ok {
			errors = append(errors, validationError(
				fmt.Sprintf("you have duplicate Models Model:%s Pos:%s", model.Name, model.Pos),
				fmt.Sprintf("%s is duplicated", model.Name),
				fmt.Sprintf("Remove %s", model.Name),
				model.Pos))
			continue
		}
		seenModelNames[model.Name] = true
	}

	return errors
}

func supportedAttributeTypes(inputs []Input) []error {
	var errors []error

	for _, input := range inputs {
		schema := input.ParsedSchema

		for _, dec := range schema.Declarations {
			if dec.Model != nil {
				for _, section := range dec.Model.Sections {
					if section.Attribute != nil {
						errors = append(errors, checkAttributes([]*parser.Attribute{section.Attribute}, "model", dec.Model.Name)...)
					}

					if section.Operations != nil {
						for _, op := range section.Operations {
							errors = append(errors, checkAttributes(op.Attributes, "operation", op.Name)...)
						}
					}

					if section.Functions != nil {
						for _, function := range section.Functions {
							errors = append(errors, checkAttributes(function.Attributes, "function", function.Name)...)
						}
					}

					if section.Fields != nil {
						for _, field := range section.Fields {
							errors = append(errors, checkAttributes(field.Attributes, "field", field.Name)...)
						}
					}
				}
			}

			// Validate attributes defined within api sections
			if dec.API != nil {
				for _, section := range dec.API.Sections {
					if section.Attribute != nil {
						errors = append(errors, checkAttributes([]*parser.Attribute{section.Attribute}, "api", dec.API.Name)...)
					}
				}
			}
		}
	}

	return errors
}

func checkAttributes(attributes []*parser.Attribute, definedOn string, parentName string) []error {
	var supportedAttributes = map[string][]string{
		parser.KeywordModel:     {parser.AttributePermission},
		parser.KeywordApi:       {parser.AttributeGraphQL},
		parser.KeywordField:     {parser.AttributeUnique, parser.AttributeOptional},
		parser.KeywordOperation: {parser.AttributeSet, parser.AttributeWhere, parser.AttributePermission},
		parser.KeywordFunction:  {parser.AttributePermission},
	}

	var builtIns = map[string][]string{
		parser.KeywordModel:     {},
		parser.KeywordApi:       {},
		parser.KeywordOperation: {},
		parser.KeywordFunction:  {},
		parser.KeywordField:     {parser.AttributePrimaryKey},
	}

	errors := make([]error, 0)

	for _, attr := range attributes {
		if contains(builtIns[definedOn], attr.Name) {
			continue
		}

		if !contains(supportedAttributes[definedOn], attr.Name) {
			hintOptions := supportedAttributes[definedOn]

			for i, hint := range hintOptions {
				hintOptions[i] = fmt.Sprintf("@%s", hint)
			}

			hint := NewCorrectionHint(hintOptions, attr.Name)

			errors = append(
				errors,
				validationError(
					fmt.Sprintf("%s '%s' has an unrecognised attribute @%s", definedOn, parentName, attr.Name),
					fmt.Sprintf("Unrecognised attribute @%s", attr.Name),
					hint.ToString(),
					attr.Pos,
				),
			)
		}
	}

	return errors
}

func findDuplicates(s []string) []string {
	inResult := make(map[string]bool)
	var result []string

	for _, str := range s {
		if _, ok := inResult[str]; !ok {
			inResult[str] = true
		} else {
			result = append(result, str)
		}
	}
	return result
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}

	return false
}

func buildErrorInvalidInputs(fields map[string]*operationFunctionInputFields) []error {
	var errors []error
	if len(fields) > 0 {
		for functionName, functionInput := range fields {
			for _, field := range functionInput.Fields {
				message := fmt.Sprintf("model:%s, field:%v", functionName, field.Name)
				errors = append(errors, validationError(fmt.Sprintf("you are using inputs that are not fields %s", message),
					fmt.Sprintf("Replace %s", field.Name),
					fmt.Sprintf("Check inputs for %s", functionName),
					field.Pos,
				))
			}
		}
	}
	return errors
}

func findInvalidOpsFunctionInputs(inputs []Input, operationInput map[string]*operationFunctionInputFields) map[string]*operationFunctionInputFields {
	for _, input := range inputs {
		schema := input.ParsedSchema
		for _, input := range schema.Declarations {
			if input.Model == nil {
				continue
			}
			for _, modelName := range input.Model.Sections {
				for _, field := range modelName.Fields {
					for operationName, operationField := range operationInput {
						for _, operationFieldName := range operationField.Fields {
							if operationFieldName.Name == field.Name {
								delete(operationInput, operationName)
							}
						}
					}
				}
			}
		}
	}
	return operationInput
}
