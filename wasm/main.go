//go:build wasm

package main

import (
	"encoding/json"
	"syscall/js"

	"github.com/fatih/color"
	"github.com/teamkeel/keel/schema"
	"github.com/teamkeel/keel/schema/completions"
	"github.com/teamkeel/keel/schema/format"
	"github.com/teamkeel/keel/schema/node"
	"github.com/teamkeel/keel/schema/parser"
	"github.com/teamkeel/keel/schema/reader"
	"github.com/teamkeel/keel/schema/validation/errorhandling"
)

func init() {
	// we have to declare our functions in an init func otherwise they aren't
	// available in JS land at the call time.
	js.Global().Set("keel", js.ValueOf(map[string]interface{}{
		"validate":    js.FuncOf(validate),
		"format":      js.FuncOf(formatSchema),
		"completions": js.FuncOf(provideCompletions),
	}))
}

func main() {
	done := make(chan bool)
	<-done
}

func provideCompletions(this js.Value, args []js.Value) interface{} {
	line := args[1].Get("line").Int()
	column := args[1].Get("column").Int()

	// A partial ast is returned from parser.Parse if there is a parse error
	// the partial ast will include anything up to the parse error.
	ast, _ := parser.Parse(
		&reader.SchemaFile{
			FileName: "schema.keel",
			Contents: args[0].String(),
		},
	)

	completions := completions.ProvideCompletions(ast, node.Position{
		Column: column,
		Line:   line,
	})

	astMap, _ := toMap(ast)

	var untypedCompletions []interface{} = toUntypedArray(completions)

	return js.ValueOf(
		map[string]interface{}{
			"completions": js.ValueOf(untypedCompletions),
			"ast":         astMap,
		},
	)
}

func formatSchema(this js.Value, args []js.Value) interface{} {
	ast, err := parser.Parse(&reader.SchemaFile{
		FileName: "schema.keel",
		Contents: args[0].String(),
	})
	if err != nil {
		// if the schema can't be parsed then just return it as-is
		return js.ValueOf(args[0].String())
	}

	return js.ValueOf(format.Format(ast))
}

// Type definition for this function:
//   validate(schema: string, options?: {color: boolean})
func validate(this js.Value, args []js.Value) interface{} {

	if len(args) > 1 {
		withColor := args[1].Get("color").Truthy()
		if withColor {
			color.NoColor = false
		}
	}

	schemaFile := reader.SchemaFile{
		FileName: "schema.keel",
		Contents: args[0].String(),
	}

	builder := schema.Builder{}
	var validationErrors map[string]interface{}
	var validationOutput string

	_, err := builder.MakeFromInputs(&reader.Inputs{
		SchemaFiles: []reader.SchemaFile{schemaFile},
	})

	if err != nil {
		errs, ok := err.(errorhandling.ValidationErrors)
		if ok {
			validationErrors, err = toMap(errs)
			if err != nil {
				return js.ValueOf(map[string]interface{}{
					"error": err.Error(),
				})
			}

			validationOutput, err = errs.ToAnnotatedSchema([]reader.SchemaFile{
				schemaFile,
			})
			if err != nil {
				return js.ValueOf(map[string]interface{}{
					"error": err.Error(),
				})
			}
		} else {
			return js.ValueOf(map[string]interface{}{
				"error": err.Error(),
			})
		}
	}

	var astMap map[string]interface{}
	asts := builder.ASTs()
	if len(asts) > 0 {
		astMap, err = toMap(asts[0])
		if err != nil {
			return js.ValueOf(map[string]interface{}{
				"error": err.Error(),
			})
		}
	}

	return js.ValueOf(map[string]interface{}{
		"ast":              astMap,
		"validationErrors": validationErrors,
		"validationOutput": validationOutput,
	})
}

// js.ValueOf can only marshall map[string]interface{} to a JS object
// so for structs we need to do the struct->json->map[string]interface{} dance
func toMap(v interface{}) (map[string]interface{}, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}

	var res map[string]interface{}
	err = json.Unmarshal(b, &res)
	return res, err
}

func toUntypedArray(items []*completions.CompletionItem) (i []interface{}) {
	for _, item := range items {
		b, err := json.Marshal(item)

		if err != nil {
			continue
		}
		var res interface{}
		err = json.Unmarshal(b, &res)

		if err != nil {
			continue
		}
		i = append(i, res)
	}

	return i
}
