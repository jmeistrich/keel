package jsonschema

import (
	"context"
	"fmt"
	"time"

	"github.com/samber/lo"
	"github.com/teamkeel/keel/proto"
	"github.com/teamkeel/keel/schema/parser"
	"github.com/xeipuuv/gojsonschema"
)

var (
	AnyTypes = []string{"string", "object", "array", "integer", "number", "boolean", "null"}
)

var (
	pageInfoSchema = JSONSchema{
		Properties: map[string]JSONSchema{
			"count": {
				Type: "number",
			},
			"startCursor": {
				Type: "string",
			},
			"endCursor": {
				Type: "string",
			},
			"totalCount": {
				Type: "number",
			},
			"hasNextPage": {
				Type: "boolean",
			},
		},
	}
)

type JSONSchema struct {
	// Type is generally just a string, but when we need a type to be
	// null it is a list containing the type and the string "null".
	// In JSON output for most cases we just want a string, not a list
	// of one string, so we use any here so it can be either
	Type any `json:"type,omitempty"`

	// The enum field needs to be able to contains strings and null,
	// so we use *string here
	Enum []*string `json:"enum,omitempty"`

	// Validation for strings
	Format string `json:"format,omitempty"`

	// Validation for objects
	Properties           map[string]JSONSchema `json:"properties,omitempty"`
	AdditionalProperties *bool                 `json:"additionalProperties,omitempty"`
	Required             []string              `json:"required,omitempty"`
	OneOf                []JSONSchema          `json:"oneOf,omitempty"`

	// For arrays
	Items *JSONSchema `json:"items,omitempty"`

	// Used to link to a type defined in the root $defs
	Ref string `json:"$ref,omitempty"`

	// Only used in the root JSONSchema object to define types that
	// can then be referenced using $ref
	Components *Components `json:"components,omitempty"`
}

type Components struct {
	Schemas map[string]JSONSchema `json:"schemas"`
}

// ValidateRequest validates that the input is valid for the given action and schema.
// If validation errors are found they will be contained in the returned result. If an error
// is returned then validation could not be completed, likely to do an invalid JSON schema
// being created.
func ValidateRequest(ctx context.Context, schema *proto.Schema, action *proto.Action, input any) (*gojsonschema.Result, error) {
	requestSchema := JSONSchemaForActionInput(ctx, schema, action)

	// We want to allow ISO8601 format WITH a compulsary date component to be permitted for the date format
	gojsonschema.FormatCheckers.Add("date", RelaxedDateFormatChecker{})

	return gojsonschema.Validate(gojsonschema.NewGoLoader(requestSchema), gojsonschema.NewGoLoader(input))
}

func ValidateResponse(ctx context.Context, schema *proto.Schema, action *proto.Action, response any) (JSONSchema, *gojsonschema.Result, error) {
	responseSchema := JSONSchemaForActionResponse(ctx, schema, action)
	result, err := gojsonschema.Validate(gojsonschema.NewGoLoader(responseSchema), gojsonschema.NewGoLoader(response))
	return responseSchema, result, err
}

func JSONSchemaForActionInput(ctx context.Context, schema *proto.Schema, action *proto.Action) JSONSchema {
	inputMessage := proto.FindMessage(schema.Messages, action.InputMessageName)
	return JSONSchemaForMessage(ctx, schema, action, inputMessage)
}

func JSONSchemaForActionResponse(ctx context.Context, schema *proto.Schema, action *proto.Action) JSONSchema {
	if action.ResponseMessageName != "" {
		responseMsg := proto.FindMessage(schema.Messages, action.ResponseMessageName)

		return JSONSchemaForMessage(ctx, schema, action, responseMsg)
	}

	// If we've reached this point then we know that we are dealing with built-in actions
	switch action.Type {
	case proto.ActionType_ACTION_TYPE_CREATE, proto.ActionType_ACTION_TYPE_GET, proto.ActionType_ACTION_TYPE_UPDATE:
		// these action types return the serialized model

		model := proto.FindModel(schema.Models, action.ModelName)

		return jsonSchemaForModel(ctx, schema, model, false)
	case proto.ActionType_ACTION_TYPE_LIST:
		// array of models

		model := proto.FindModel(schema.Models, action.ModelName)

		modelSchema := jsonSchemaForModel(ctx, schema, model, true)

		// as there are nested components within the modelSchema, we need to merge these into the top level
		components := Components{
			Schemas: map[string]JSONSchema{},
		}
		for key, prop := range modelSchema.Components.Schemas {
			components.Schemas[key] = prop
		}
		modelSchema.Components = nil

		wrapperSchema := JSONSchema{
			Properties: map[string]JSONSchema{
				"results":  modelSchema,
				"pageInfo": pageInfoSchema,
			},
			Components: &components,
		}
		return wrapperSchema
	case proto.ActionType_ACTION_TYPE_DELETE:
		// string id of deleted record

		return JSONSchema{
			Type: "string",
		}
	default:
		return JSONSchema{}
	}
}

// Generates JSONSchema for an operation by generating properties for the root input message.
// Any subsequent nested messages are referenced.
func JSONSchemaForMessage(ctx context.Context, schema *proto.Schema, action *proto.Action, message *proto.Message) JSONSchema {
	components := Components{
		Schemas: map[string]JSONSchema{},
	}

	messageIsNil := message == nil
	isAny := !messageIsNil && message.Name == parser.MessageFieldTypeAny

	root := JSONSchema{
		Type:                 "object",
		Properties:           map[string]JSONSchema{},
		AdditionalProperties: boolPtr(isAny),
	}

	if isAny {
		root.Type = AnyTypes
	}

	if !isAny {
		for _, field := range message.Fields {
			prop := jsonSchemaForField(ctx, schema, action, field.Type, field.Nullable)

			// Merge components from this request schema into OpenAPI components
			if prop.Components != nil {
				for name, comp := range prop.Components.Schemas {
					components.Schemas[name] = comp
				}
				prop.Components = nil
			}

			root.Properties[field.Name] = prop

			// If the input is not optional then mark it required in the JSON schema
			if !field.Optional {
				root.Required = append(root.Required, field.Name)
			}
		}
	}

	if len(components.Schemas) > 0 {
		root.Components = &components
	}

	return root
}

func jsonSchemaForModel(ctx context.Context, schema *proto.Schema, model *proto.Model, isRepeated bool) JSONSchema {
	definitionSchema := JSONSchema{
		Properties: map[string]JSONSchema{},
	}

	s := JSONSchema{}
	components := &Components{
		Schemas: map[string]JSONSchema{},
	}

	if isRepeated {
		s.Type = "array"
		s.Items = &JSONSchema{Ref: fmt.Sprintf("#/components/schemas/%s", model.Name)}
	} else {
		s = JSONSchema{Ref: fmt.Sprintf("#/components/schemas/%s", model.Name)}
	}

	for _, field := range model.Fields {
		// if the field of model type, then we don't want to include this because JSON-based
		// apis don't serialize nested relations
		if field.Type.Type == proto.Type_TYPE_MODEL {
			continue
		}

		fieldSchema := jsonSchemaForField(ctx, schema, nil, field.Type, field.Optional)

		definitionSchema.Properties[field.Name] = fieldSchema

		// If the field is not optional then mark it as required in the JSON schema
		if !field.Optional {
			definitionSchema.Required = append(definitionSchema.Required, field.Name)
		}
	}

	schemas := map[string]JSONSchema{}

	components.Schemas[model.Name] = definitionSchema

	schemas[model.Name] = definitionSchema

	s.Components = components

	return s
}

func jsonSchemaForField(ctx context.Context, schema *proto.Schema, action *proto.Action, t *proto.TypeInfo, isNullableField bool) JSONSchema {
	components := &Components{
		Schemas: map[string]JSONSchema{},
	}
	prop := JSONSchema{}

	switch t.Type {
	case proto.Type_TYPE_ANY:
		prop.Type = AnyTypes
	case proto.Type_TYPE_MESSAGE:
		// Add the nested message to schema components.
		message := proto.FindMessage(schema.Messages, t.MessageName.Value)
		component := JSONSchemaForMessage(ctx, schema, action, message)

		// If that nested message component has ref fields itself, then its components must be bundled.
		if component.Components != nil {
			for cName, comp := range component.Components.Schemas {
				components.Schemas[cName] = comp
			}
			component.Components = nil
		}

		name := t.MessageName.Value
		if isNullableField {
			component.allowNull()
			name = "Nullable" + name
		}

		if t.Repeated {
			prop.Type = "array"
			prop.Items = &JSONSchema{Ref: fmt.Sprintf("#/components/schemas/%s", name)}
		} else {
			prop = JSONSchema{Ref: fmt.Sprintf("#/components/schemas/%s", name)}
		}

		components.Schemas[name] = component

	case proto.Type_TYPE_UNION:
		// Union types can be modelled using oneOf.
		oneOf := []JSONSchema{}
		for _, m := range t.UnionNames {
			// Add the nested message to schema components.
			message := proto.FindMessage(schema.Messages, m.Value)
			component := JSONSchemaForMessage(ctx, schema, action, message)

			// If that nested message component has ref fields itself, then its components must be bundled.
			if component.Components != nil {
				for cName, comp := range component.Components.Schemas {
					components.Schemas[cName] = comp
				}
				component.Components = nil
			}

			name := message.Name
			if isNullableField {
				component.allowNull()
				name = "Nullable" + name
			}

			j := JSONSchema{Ref: fmt.Sprintf("#/components/schemas/%s", name)}
			oneOf = append(oneOf, j)

			components.Schemas[name] = component
		}

		if t.Repeated {
			prop.Type = "array"
			prop.Items = &JSONSchema{OneOf: oneOf}
		} else {
			prop = JSONSchema{OneOf: oneOf}
		}

	case proto.Type_TYPE_ID, proto.Type_TYPE_STRING:
		prop.Type = "string"
	case proto.Type_TYPE_BOOL:
		prop.Type = "boolean"
	case proto.Type_TYPE_INT:
		prop.Type = "number"
	case proto.Type_TYPE_MODEL:
		model := proto.FindModel(schema.Models, t.ModelName.Value)

		modelSchema := jsonSchemaForModel(ctx, schema, model, t.Repeated)

		// If that nested message component has ref fields itself, then its components must be bundled.
		if modelSchema.Components != nil {
			for cName, comp := range modelSchema.Components.Schemas {
				components.Schemas[cName] = comp
			}
			modelSchema.Components = nil
		}

		if t.Repeated {
			prop.Items = &JSONSchema{Ref: fmt.Sprintf("#/components/schemas/%s", model.Name)}
			prop.Type = "array"
		} else {
			prop = JSONSchema{Ref: fmt.Sprintf("#/components/schemas/%s", model.Name)}
		}
	case proto.Type_TYPE_DATETIME, proto.Type_TYPE_TIMESTAMP:
		// date-time format allows both YYYY-MM-DD and full ISO8601/RFC3339 format
		prop.Type = "string"
		prop.Format = "date-time"
	case proto.Type_TYPE_DATE:
		prop.Type = "string"
		prop.Format = "date"
	case proto.Type_TYPE_ENUM:
		// For enum's we actually don't need to set the `type` field at all
		enum, _ := lo.Find(schema.Enums, func(e *proto.Enum) bool {
			return e.Name == t.EnumName.Value
		})

		for _, v := range enum.Values {
			prop.Enum = append(prop.Enum, &v.Name)
		}

		if isNullableField {
			prop.allowNull()
		}
	case proto.Type_TYPE_SORT_DIRECTION:
		prop.Type = "string"
		asc := "asc"
		desc := "desc"
		prop.Enum = []*string{&asc, &desc}
	}

	if t.Repeated && (t.Type != proto.Type_TYPE_MESSAGE && t.Type != proto.Type_TYPE_MODEL && t.Type != proto.Type_TYPE_UNION) {
		prop.Items = &JSONSchema{Type: prop.Type, Enum: prop.Enum}
		prop.Enum = nil
		prop.Type = "array"
	}

	if isNullableField {
		prop.allowNull()
	}

	if len(components.Schemas) > 0 {
		prop.Components = components
	}

	return prop
}

// allowNull makes sure that s allows null, either by modifying
// the type field or the enum field
//
// This is an area where OpenAPI differs from JSON Schema, from
// the OpenAPI spec:
//
//	| Note that there is no null type; instead, the nullable
//	| attribute is used as a modifier of the base type.
//
// We currently only support JSON schema
func (s *JSONSchema) allowNull() {
	t := s.Type
	switch t := t.(type) {
	case string:
		s.Type = []string{t, "null"}
	case []string:
		if lo.Contains(t, "null") {
			return
		}
		t = append(t, "null")
		s.Type = t
	}

	if len(s.Enum) > 0 && !lo.Contains(s.Enum, nil) {
		s.Enum = append(s.Enum, nil)
	}
}

func boolPtr(v bool) *bool {
	return &v
}

func ErrorsToString(errs []gojsonschema.ResultError) (ret string) {
	for _, err := range errs {
		ret += fmt.Sprintf("%s\n", err.String())
	}

	return ret
}

type RelaxedDateFormatChecker struct{}

// Checks that the value matches the a ISO8601 except the date component is mandatory
func (f RelaxedDateFormatChecker) IsFormat(input interface{}) bool {
	asString, ok := input.(string)
	if !ok {
		return false
	}

	formats := []string{
		"2006-01-02",
		time.RFC3339,
		time.RFC3339Nano,
	}

	for _, format := range formats {
		if _, err := time.Parse(format, asString); err == nil {
			return true
		}
	}

	return false
}
