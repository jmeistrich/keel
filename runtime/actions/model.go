package actions

import (
	"fmt"
	"time"

	"github.com/iancoleman/strcase"
	"github.com/segmentio/ksuid"
	"github.com/teamkeel/keel/proto"
	"github.com/teamkeel/keel/schema/parser"
	"golang.org/x/crypto/bcrypt"
)

// initialValueForModel provides a map[string]any that corresponds to all the fields
// that exist in the given proto.Model - with their value set to schema-default value if
// one is specified for this field in the schema, or failing that our built-in default value for
// the corresponding type. E.g. emtpy string for string fields, or integer zero for a Number field.
func initialValueForModel(pModel *proto.Model, schema *proto.Schema) (map[string]any, error) {
	zeroValue := map[string]any{}
	var err error
	for _, field := range pModel.Fields {

		if zeroValue[strcase.ToSnake(field.Name)], err = initialValueForField(field, schema.Enums); err != nil {
			return nil, err
		}
	}
	return zeroValue, nil
}

// initialValueForField provides a suitable initial value for the
// given field. It first tries to use its schema-default.
// After that it tries to use our built-in default for the field's type.
// But it can also return nil without an error when it cannot do either of those things.
func initialValueForField(field *proto.Field, enums []*proto.Enum) (zeroV any, err error) {
	zeroV = nil

	switch {
	case field.DefaultValue != nil && field.DefaultValue.Expression != nil:
		v, err := schemaDefault(field) // Will need more arguments / context later.
		if err != nil {
			return nil, err
		}
		return v, nil
	case field.DefaultValue != nil && field.DefaultValue.UseZeroValue:
		v, err := builtinDefault(field, enums)
		if err != nil {
			return nil, err
		}
		return v, nil
	default:
		// We cannot provide a sensibly initialized value, but that is not an error, because the
		// value will likely be provided later from the operation input values.
		return nil, nil
	}
}

func builtinDefault(field *proto.Field, enums []*proto.Enum) (any, error) {
	fType := field.Type.Type
	rpt := field.Type.Repeated
	now := time.Now()
	kid, err := ksuid.NewRandomWithTime(now)
	if err != nil {
		return nil, err
	}

	switch {

	case fType == proto.Type_TYPE_STRING && !rpt:
		return "", nil
	case fType == proto.Type_TYPE_STRING && rpt:
		return []string{}, nil

	case fType == proto.Type_TYPE_BOOL && !rpt:
		return false, nil
	case fType == proto.Type_TYPE_BOOL && rpt:
		return []bool{}, nil

	case fType == proto.Type_TYPE_INT && !rpt:
		return 0, nil
	case fType == proto.Type_TYPE_INT && rpt:
		return []int{}, nil

	case fType == proto.Type_TYPE_TIMESTAMP && !rpt:
		return now, nil
	case fType == proto.Type_TYPE_TIMESTAMP && rpt:
		return []time.Time{}, nil

	case fType == proto.Type_TYPE_DATE && !rpt:
		return now, nil
	case fType == proto.Type_TYPE_DATE && rpt:
		return []time.Time{}, nil

	case fType == proto.Type_TYPE_ID && !rpt:
		return kid, nil
	case fType == proto.Type_TYPE_ID && rpt:
		return []ksuid.KSUID{}, nil

	case fType == proto.Type_TYPE_MODEL && !rpt:
		return "", nil
	case fType == proto.Type_TYPE_MODEL && rpt:
		return []string{}, nil

	case fType == proto.Type_TYPE_CURRENCY && !rpt:
		return "", nil
	case fType == proto.Type_TYPE_CURRENCY && rpt:
		return []string{}, nil

	case fType == proto.Type_TYPE_DATETIME && !rpt:
		return now, nil
	case fType == proto.Type_TYPE_DATETIME && rpt:
		return []time.Time{}, nil

	default:
		// When we cannot provide a built-in default - we assing nil as the value
		// to use.
		return nil, nil
	}
}

func schemaDefault(field *proto.Field) (any, error) {
	source := field.DefaultValue.Expression.Source
	expr, err := parser.ParseExpression(source)
	if err != nil {
		return nil, fmt.Errorf("cannot Parse this expression: %s", source)
	}
	switch {
	case expr.IsValue():
		v, err := expr.ToValue()
		if err != nil {
			return nil, err
		}
		return toNative(v, field.Type.Type)
	default:
		return nil, fmt.Errorf("expressions that are not simple values are not yet supported")
	}
}

// toMap provides casts / interprets the given proto.OperationInput value, into a value that
// is good to insert into the corresponding DB column (using Gorm).
// todo: combine with parseTimeOperand
func toMap(in any, inputType proto.Type) (any, error) {
	switch inputType {

	// Start with some special cases that require some intervention.

	case proto.Type_TYPE_DATETIME, proto.Type_TYPE_TIMESTAMP:

		// The input is expected to be a map[string]any, that contains a "seconds" field.
		obj, ok := in.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("cannot cast %+v to a TimestampInput", in)
		}
		seconds, ok := obj["seconds"]
		if !ok {
			return nil, fmt.Errorf("this input object: %v, does not have a seconds key", obj)
		}
		asInt, ok := seconds.(int)
		if !ok {
			return nil, fmt.Errorf("cannot cast this seconds value: %+v to an int", seconds)
		}
		return time.Unix(int64(asInt), 0), nil

	case proto.Type_TYPE_DATE:
		// The input is expected to be a map[string]any, that contains a year,month,day fields.
		obj, ok := in.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("cannot cast %+v to a DateInput", in)
		}
		var year int
		var month int
		var day int

		if err := parseInt("year", obj, &year); err != nil {
			return nil, err
		}
		if err := parseInt("month", obj, &month); err != nil {
			return nil, err
		}
		if err := parseInt("day", obj, &day); err != nil {
			return nil, err
		}

		date := time.Date(year, time.Month(month), day, 0, 0, 0, 0, time.UTC)
		return date, nil
	case proto.Type_TYPE_SECRET:
		return nil, fmt.Errorf("secret data type not yet implemented")

	case proto.Type_TYPE_PASSWORD:
		hashedBytes, err := bcrypt.GenerateFromPassword([]byte(in.(string)), bcrypt.DefaultCost)

		if err != nil {
			return nil, err
		}

		return string(hashedBytes), nil

	// The general case is to return the input unchanged.
	default:
		return in, nil
	}
}

func parseInt(key string, source map[string]any, dest *int) error {
	v, ok := source[key]
	if !ok {
		return fmt.Errorf("this input object: %v, does not have a %s key", source, key)
	}
	asInt, ok := v.(int)
	if !ok {
		return fmt.Errorf("cannot cast this value: %+v to an int", v)
	}
	*dest = asInt
	return nil
}
