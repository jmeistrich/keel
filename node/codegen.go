package node

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/iancoleman/strcase"
	"github.com/samber/lo"
	"github.com/teamkeel/keel/proto"
	"github.com/teamkeel/keel/schema"
	"github.com/teamkeel/keel/schema/parser"
)

type GeneratedFile struct {
	Contents string
	Path     string
}

type GeneratedFiles []*GeneratedFile

func (files GeneratedFiles) Write() error {
	for _, f := range files {
		err := os.MkdirAll(filepath.Dir(f.Path), 0777)
		if err != nil {
			return fmt.Errorf("error creating directory: %w", err)
		}
		err = os.WriteFile(f.Path, []byte(f.Contents), 0777)
		if err != nil {
			return fmt.Errorf("error writing file: %w", err)
		}
	}
	return nil
}

type generateOptions struct {
	developmentServer bool
}

// WithDevelopmentServer enables or disables the generation of the development
// server entry point. By default this is disabled.
func WithDevelopmentServer(b bool) func(o *generateOptions) {
	return func(o *generateOptions) {
		o.developmentServer = b
	}
}

// Generate generates and returns a list of objects that represent files to be written
// to a project. Calling .Write() on the result will cause those files be written to disk.
func Generate(ctx context.Context, dir string, opts ...func(o *generateOptions)) (GeneratedFiles, error) {
	options := &generateOptions{}
	for _, o := range opts {
		o(options)
	}

	builder := schema.Builder{}

	schema, err := builder.MakeFromDirectory(dir)
	if err != nil {
		return nil, err
	}

	if !IsEnabled(dir, schema) {
		return GeneratedFiles{}, nil
	}

	files := generateSdkPackage(dir, schema)
	files = append(files, generateTestingPackage(dir, schema)...)
	files = append(files, generateTestingSetup(dir)...)

	if options.developmentServer {
		files = append(files, generateDevelopmentServer(dir, schema)...)
	}

	return files, nil
}

func generateSdkPackage(dir string, schema *proto.Schema) GeneratedFiles {
	sdk := &Writer{}
	sdk.Writeln(`const runtime = require("@teamkeel/functions-runtime")`)
	sdk.Writeln("")

	sdkTypes := &Writer{}
	sdkTypes.Writeln(`import { Kysely, Generated } from "kysely"`)
	sdkTypes.Writeln(`import * as runtime from "@teamkeel/functions-runtime"`)
	sdkTypes.Writeln(`import { Headers } from 'node-fetch'`)
	sdkTypes.Writeln("")

	writeMessages(sdkTypes, schema)

	for _, enum := range schema.Enums {
		writeEnum(sdkTypes, enum)
		writeEnumWhereCondition(sdkTypes, enum)
		writeEnumObject(sdk, enum)
	}

	for _, model := range schema.Models {
		writeTableInterface(sdkTypes, model)
		writeModelInterface(sdkTypes, model)
		writeCreateValuesInterface(sdkTypes, model)
		writeWhereConditionsInterface(sdkTypes, model)
		writeUniqueConditionsInterface(sdkTypes, model)
		writeModelAPIDeclaration(sdkTypes, model)
		writeModelQueryBuilderDeclaration(sdkTypes, model)
		writeModelDefaultValuesFunction(sdk, model)

		for _, op := range model.Operations {
			// We only care about custom functions for the SDK
			if op.Implementation != proto.OperationImplementation_OPERATION_IMPLEMENTATION_CUSTOM {
				continue
			}

			writeCustomFunctionWrapperType(sdkTypes, model, op)

			sdk.Writef("module.exports.%s = (fn) => fn;", strcase.ToCamel(op.Name))
			sdk.Writeln("")
		}
	}

	writeTableConfig(sdk, schema.Models)

	writeAPIFactory(sdk, schema)

	writeDatabaseInterface(sdkTypes, schema)
	writeAPIDeclarations(sdkTypes, schema)

	sdk.Writeln("module.exports.getDatabase = runtime.getDatabase;")

	return []*GeneratedFile{
		{
			Path:     filepath.Join(dir, "node_modules/@teamkeel/sdk/index.js"),
			Contents: sdk.String(),
		},
		{
			Path:     filepath.Join(dir, "node_modules/@teamkeel/sdk/index.d.ts"),
			Contents: sdkTypes.String(),
		},
		{
			Path:     filepath.Join(dir, "node_modules/@teamkeel/sdk/package.json"),
			Contents: `{"name": "@teamkeel/sdk"}`,
		},
	}
}

func writeTableInterface(w *Writer, model *proto.Model) {
	w.Writef("export interface %sTable {\n", model.Name)
	w.Indent()
	for _, field := range model.Fields {
		if field.Type.Type == proto.Type_TYPE_MODEL {
			continue
		}
		w.Write(strcase.ToSnake(field.Name))
		w.Write(": ")
		t := toTypeScriptType(field.Type)
		if field.DefaultValue != nil {
			t = fmt.Sprintf("Generated<%s>", t)
		}
		w.Write(t)
		if field.Optional {
			w.Write(" | null")
		}
		w.Writeln("")
	}
	w.Dedent()
	w.Writeln("}")
}

func writeModelInterface(w *Writer, model *proto.Model) {
	w.Writef("export interface %s {\n", model.Name)
	w.Indent()
	for _, field := range model.Fields {
		if field.Type.Type == proto.Type_TYPE_MODEL {
			continue
		}
		w.Write(field.Name)
		w.Write(": ")
		t := toTypeScriptType(field.Type)
		w.Write(t)
		if field.Optional {
			w.Write(" | null")
		}
		w.Writeln("")
	}
	w.Dedent()
	w.Writeln("}")
}

func writeCreateValuesInterface(w *Writer, model *proto.Model) {
	w.Writef("export interface %sCreateValues {\n", model.Name)
	w.Indent()
	for _, field := range model.Fields {
		// For now you can't create related models when creating a record
		if field.Type.Type == proto.Type_TYPE_MODEL {
			continue
		}
		w.Write(field.Name)
		if field.Optional || field.DefaultValue != nil {
			w.Write("?")
		}
		w.Write(": ")
		t := toTypeScriptType(field.Type)
		w.Write(t)
		if field.Optional {
			w.Write(" | null")
		}
		w.Writeln("")
	}
	w.Dedent()
	w.Writeln("}")
}

func writeWhereConditionsInterface(w *Writer, model *proto.Model) {
	w.Writef("export interface %sWhereConditions {\n", model.Name)
	w.Indent()
	for _, field := range model.Fields {
		w.Write(field.Name)
		w.Write("?")
		w.Write(": ")
		if field.Type.Type == proto.Type_TYPE_MODEL {
			// Embed related models where conditions
			w.Writef("%sWhereConditions | null;", field.Type.ModelName.Value)
		} else {
			w.Write(toTypeScriptType(field.Type))
			w.Write(" | ")
			w.Write(toWhereConditionType(field))
			w.Write(" | null;")
		}

		w.Writeln("")
	}
	w.Dedent()
	w.Writeln("}")
}

func writeMessages(w *Writer, schema *proto.Schema) {
	for _, msg := range schema.Messages {
		if msg.Name == parser.MessageFieldTypeAny {
			continue
		}
		writeMessage(w, schema, msg)
	}
}

func writeMessage(w *Writer, schema *proto.Schema, message *proto.Message) {
	w.Writef("export interface %s {\n", message.Name)
	w.Indent()

	for _, field := range message.Fields {
		w.Write(field.Name)

		if field.Optional {
			w.Write("?")
		}

		w.Write(": ")

		w.Write(toTypeScriptType(field.Type))

		if field.Type.Repeated {
			w.Write("[]")
		}

		nullable := false

		// If a field isn't tied to a model field and it's optional then it's allowed to be null
		if field.Type.FieldName == nil && field.Optional {
			nullable = true
		}

		// If an input is tied to a model field and that field is nullable then the input is also nullable
		if field.Type.FieldName != nil {
			f := proto.FindField(schema.Models, field.Type.ModelName.Value, field.Type.FieldName.Value)
			if f.Optional {
				nullable = true
			}
		}

		if nullable {
			w.Write(" | null")
		}

		w.Writeln(";")
	}

	w.Dedent()

	w.Writeln("}")
}

func writeUniqueConditionsInterface(w *Writer, model *proto.Model) {
	w.Writef("export type %sUniqueConditions = ", model.Name)
	w.Indent()
	for _, f := range model.Fields {
		var tsType string

		switch {
		case f.Unique || f.PrimaryKey:
			tsType = toTypeScriptType(f.Type)
		case proto.IsHasMany(f):
			// If a model "has one" of another model then you can
			// do a lookup on any of that models unique fields
			tsType = fmt.Sprintf("%sUniqueConditions", f.Type.ModelName.Value)
		default:
			// TODO: support f.UniqueWith for compound unique constraints
			continue
		}

		w.Writeln("")
		w.Writef("| {%s: %s}", f.Name, tsType)
	}
	w.Writeln(";")
	w.Dedent()
}

func writeModelAPIDeclaration(w *Writer, model *proto.Model) {
	w.Writef("export type %sAPI = {\n", model.Name)
	w.Indent()
	w.Writef("create(values: %sCreateValues): Promise<%s>;\n", model.Name, model.Name)
	w.Writef("update(where: %sUniqueConditions, values: Partial<%s>): Promise<%s>;\n", model.Name, model.Name, model.Name)
	w.Writef("delete(where: %sUniqueConditions): Promise<string>;\n", model.Name)
	w.Writef("findOne(where: %sUniqueConditions): Promise<%s | null>;\n", model.Name, model.Name)
	w.Writef("findMany(where: %sWhereConditions): Promise<%s[]>;\n", model.Name, model.Name)
	w.Writef("where(where: %sWhereConditions): %sQueryBuilder;\n", model.Name, model.Name)
	w.Dedent()
	w.Writeln("}")
}

func writeModelQueryBuilderDeclaration(w *Writer, model *proto.Model) {
	w.Writef("export type %sQueryBuilder = {\n", model.Name)
	w.Indent()
	w.Writef("where(where: %sWhereConditions): %sQueryBuilder;\n", model.Name, model.Name)
	w.Writef("orWhere(where: %sWhereConditions): %sQueryBuilder;\n", model.Name, model.Name)
	w.Writef("findMany(): Promise<%s[]>;\n", model.Name)
	w.Dedent()
	w.Writeln("}")
}

func writeEnumObject(w *Writer, enum *proto.Enum) {
	w.Writef("module.exports.%s = {\n", enum.Name)
	w.Indent()
	for _, v := range enum.Values {
		w.Write(v.Name)
		w.Write(": ")
		w.Writef(`"%s"`, v.Name)
		w.Writeln(",")
	}
	w.Dedent()
	w.Writeln("};")
}

func writeEnum(w *Writer, enum *proto.Enum) {
	w.Writef("export enum %s {\n", enum.Name)
	w.Indent()
	for _, v := range enum.Values {
		w.Write(v.Name)
		w.Write(" = ")
		w.Writef(`"%s"`, v.Name)
		w.Writeln(",")
	}
	w.Dedent()
	w.Writeln("}")
}

func writeEnumWhereCondition(w *Writer, enum *proto.Enum) {
	w.Writef("export interface %sWhereCondition {\n", enum.Name)
	w.Indent()
	w.Write("equals?: ")
	w.Write(enum.Name)
	w.Writeln(" | null;")
	w.Write("oneOf?: ")
	w.Write(enum.Name)
	w.Write("[]")
	w.Writeln(" | null;")
	w.Dedent()
	w.Writeln("}")
}

func writeDatabaseInterface(w *Writer, schema *proto.Schema) {
	w.Writeln("interface database {")
	w.Indent()
	for _, model := range schema.Models {
		w.Writef("%s: %sTable;", strcase.ToSnake(model.Name), model.Name)
		w.Writeln("")
	}
	w.Dedent()
	w.Writeln("}")
	w.Write("export declare function getDatabase(): Kysely<database>;")
}

func writeAPIDeclarations(w *Writer, schema *proto.Schema) {
	w.Writeln("export type ModelsAPI = {")
	w.Indent()
	for _, model := range schema.Models {
		w.Write(strcase.ToLowerCamel(model.Name))
		w.Write(": ")
		w.Writef(`%sAPI`, model.Name)
		w.Writeln(";")
	}
	w.Dedent()
	w.Writeln("}")

	w.Writeln("export type FunctionAPI = {")
	w.Indent()
	w.Writeln("models: ModelsAPI;")
	w.Writeln("fetch(input: RequestInfo | URL, init?: RequestInit | undefined): Promise<Response>;")
	w.Writeln("headers: Headers;")
	w.Writeln("permissions: runtime.Permissions;")
	w.Dedent()

	w.Writeln("}")

	w.Writeln("type Environment = {")

	w.Indent()

	for _, variable := range schema.EnvironmentVariables {
		w.Writef("%s: string;\n", variable.Name)
	}

	w.Dedent()
	w.Writeln("}")
	w.Writeln("type Secrets = {")

	w.Indent()

	for _, secret := range schema.Secrets {
		w.Writef("%s: string;\n", secret.Name)
	}

	w.Dedent()
	w.Writeln("}")
	w.Writeln("")

	w.Writeln("export interface ContextAPI extends runtime.ContextAPI {")
	w.Indent()
	w.Writeln("secrets: Secrets;")
	w.Writeln("env: Environment;")
	w.Writeln("identity?: Identity;")
	w.Writeln("now(): Date;")
	w.Dedent()
	w.Writeln("}")
}

func writeAPIFactory(w *Writer, schema *proto.Schema) {
	w.Writeln("function createFunctionAPI({ headers, db }) {")
	w.Indent()

	w.Writeln("const models = {")
	w.Indent()
	for _, model := range schema.Models {
		w.Write(strcase.ToLowerCamel(model.Name))
		w.Write(": ")
		w.Writef(`new runtime.ModelAPI("%s", %sDefaultValues, db, tableConfigMap)`, strcase.ToSnake(model.Name), strcase.ToLowerCamel(model.Name))
		w.Writeln(",")
	}
	w.Dedent()
	w.Writeln("};")

	w.Writeln("const wrappedFetch = fetch;") // We'll likely extend it later.

	w.Writeln("return { models, headers, fetch: wrappedFetch, permissions: new runtime.Permissions() };")

	w.Dedent()
	w.Writeln("};")

	w.Writeln("function createContextAPI(meta) {")
	w.Indent()
	w.Writeln("const headers = new runtime.RequestHeaders(meta.headers);")
	w.Writeln("const now = () => { return new Date(); };")
	w.Writeln("const { identity } = meta;")
	w.Writeln("const env = {")
	w.Indent()

	for _, variable := range schema.EnvironmentVariables {
		// fetch the value of the env var from the process.env (will pull the value based on the current environment)
		// outputs "key: process.env["key"] || []"
		w.Writef("%s: process.env[\"%s\"] || \"\",\n", variable.Name, variable.Name)
	}

	w.Dedent()
	w.Writeln("};")
	w.Writeln("const secrets = {")
	w.Indent()

	for _, secret := range schema.Secrets {
		w.Writef("%s: meta.secrets.%s || \"\",\n", secret.Name, secret.Name)
	}

	w.Dedent()
	w.Writeln("};")

	w.Writeln("return { headers, identity, env, now, secrets };")
	w.Dedent()
	w.Writeln("}")
	w.Writeln("module.exports.createFunctionAPI = createFunctionAPI;")
	w.Writeln("module.exports.createContextAPI = createContextAPI;")
}

func writeTableConfig(w *Writer, models []*proto.Model) {
	w.Write("const tableConfigMap = ")

	// In case the words map and string over and over aren't clear enough
	// for you see the packages/functions-runtime/src/ModelAPI.js file for
	// docs on how this object is expected to be structured
	tableConfigMap := map[string]map[string]map[string]string{}

	for _, model := range models {
		for _, field := range model.Fields {
			if field.Type.Type != proto.Type_TYPE_MODEL {
				continue
			}

			relationshipConfig := map[string]string{
				"referencesTable": strcase.ToSnake(field.Type.ModelName.Value),
				"foreignKey":      strcase.ToSnake(proto.GetForignKeyFieldName(models, field)),
			}

			switch {
			case proto.IsHasOne(field):
				relationshipConfig["relationshipType"] = "hasOne"
			case proto.IsHasMany(field):
				relationshipConfig["relationshipType"] = "hasMany"
			case proto.IsBelongsTo(field):
				relationshipConfig["relationshipType"] = "belongsTo"
			}

			tableConfig, ok := tableConfigMap[strcase.ToSnake(model.Name)]
			if !ok {
				tableConfig = map[string]map[string]string{}
				tableConfigMap[strcase.ToSnake(model.Name)] = tableConfig
			}

			tableConfig[field.Name] = relationshipConfig
		}
	}

	b, _ := json.MarshalIndent(tableConfigMap, "", "    ")
	w.Write(string(b))
	w.Writeln(";")
}

func writeModelDefaultValuesFunction(w *Writer, model *proto.Model) {
	w.Writef("function %sDefaultValues() {", strcase.ToLowerCamel(model.Name))
	w.Writeln("")
	w.Indent()
	w.Writeln("const r = {};")
	for _, field := range model.Fields {
		if field.DefaultValue == nil {
			continue
		}
		if field.DefaultValue.UseZeroValue {
			w.Writef("r.%s = ", field.Name)
			switch field.Type.Type {
			case proto.Type_TYPE_ID:
				w.Write("runtime.ksuid()")
			case proto.Type_TYPE_STRING:
				w.Write(`""`)
			case proto.Type_TYPE_BOOL:
				w.Write(`false`)
			case proto.Type_TYPE_INT:
				w.Write(`0`)
			case proto.Type_TYPE_DATETIME, proto.Type_TYPE_DATE, proto.Type_TYPE_TIMESTAMP:
				w.Write("new Date()")
			}
			w.Writeln(";")
			continue
		}
		// TODO: support expressions
	}
	w.Writeln("return r;")
	w.Dedent()
	w.Writeln("}")
}

func writeCustomFunctionWrapperType(w *Writer, model *proto.Model, op *proto.Operation) {
	w.Writef("export declare function %s", strcase.ToCamel(op.Name))

	inputType := op.InputMessageName
	if inputType == parser.MessageFieldTypeAny {
		inputType = "any"
	}

	w.Writef("(fn: (inputs: %s, api: FunctionAPI, ctx: ContextAPI) => ", inputType)
	w.Write(toCustomFunctionReturnType(model, op, false))
	w.Write("): ")
	w.Write(toCustomFunctionReturnType(model, op, false))
	w.Writeln(";")
}

func toCustomFunctionReturnType(model *proto.Model, op *proto.Operation, isTestingPackage bool) string {
	returnType := "Promise<"
	sdkPrefix := ""
	if isTestingPackage {
		sdkPrefix = "sdk."
	}
	switch op.Type {
	case proto.OperationType_OPERATION_TYPE_CREATE:
		returnType += sdkPrefix + model.Name
	case proto.OperationType_OPERATION_TYPE_UPDATE:
		returnType += sdkPrefix + model.Name
	case proto.OperationType_OPERATION_TYPE_GET:
		returnType += sdkPrefix + model.Name + " | null"
	case proto.OperationType_OPERATION_TYPE_LIST:
		returnType += sdkPrefix + model.Name + "[]"
	case proto.OperationType_OPERATION_TYPE_DELETE:
		returnType += "string"
	case proto.OperationType_OPERATION_TYPE_READ, proto.OperationType_OPERATION_TYPE_WRITE:
		isAny := op.ResponseMessageName == parser.MessageFieldTypeAny

		if isAny {
			returnType += "any"
		} else {
			returnType += op.ResponseMessageName
		}
	}
	returnType += ">"
	return returnType
}

func toActionReturnType(model *proto.Model, op *proto.Operation) string {
	returnType := "Promise<"
	sdkPrefix := "sdk."

	switch op.Type {
	case proto.OperationType_OPERATION_TYPE_CREATE:
		returnType += sdkPrefix + model.Name
	case proto.OperationType_OPERATION_TYPE_UPDATE:
		returnType += sdkPrefix + model.Name
	case proto.OperationType_OPERATION_TYPE_GET:
		returnType += sdkPrefix + model.Name + " | null"
	case proto.OperationType_OPERATION_TYPE_LIST:
		returnType += "{results: " + sdkPrefix + model.Name + "[], hasNextPage: boolean, startCursor: string, endCursor: string}"
	case proto.OperationType_OPERATION_TYPE_DELETE:
		// todo: create ID type
		returnType += "string"
	case proto.OperationType_OPERATION_TYPE_READ, proto.OperationType_OPERATION_TYPE_WRITE:
		returnType += op.ResponseMessageName
	}

	returnType += ">"
	return returnType
}

func generateDevelopmentServer(dir string, schema *proto.Schema) GeneratedFiles {
	w := &Writer{}
	w.Writeln(`import { handleRequest } from '@teamkeel/functions-runtime';`)
	w.Writeln(`import { createFunctionAPI, createContextAPI } from '@teamkeel/sdk';`)
	w.Writeln(`import { createServer } from "http";`)

	functionNames := []string{}
	for _, model := range schema.Models {
		for _, op := range model.Operations {
			if op.Implementation != proto.OperationImplementation_OPERATION_IMPLEMENTATION_CUSTOM {
				continue
			}
			functionNames = append(functionNames, op.Name)
			// namespace import to avoid naming clashes
			w.Writef(`import function_%s from "../functions/%s.ts"`, op.Name, op.Name)
			w.Writeln(";")
		}
	}

	w.Writeln("const functions = {")
	w.Indent()
	for _, name := range functionNames {
		w.Writef("%s: function_%s,", name, name)
		w.Writeln("")
	}
	w.Dedent()
	w.Writeln("}")

	w.Writeln(`
const listener = async (req, res) => {
	const u = new URL(req.url, "http://" + req.headers.host);
	if (req.method === "GET" && u.pathname === "/_health") {
		res.statusCode = 200;
		res.end();
		return;
	}

	if (req.method === "POST") {
		const buffers = [];
		for await (const chunk of req) {
			buffers.push(chunk);
		}
		const data = Buffer.concat(buffers).toString();
		const json = JSON.parse(data);

		const rpcResponse = await handleRequest(json, {
			functions,
			createFunctionAPI,
			createContextAPI,
		});

		res.statusCode = 200;
		res.setHeader('Content-Type', 'application/json');
		res.write(JSON.stringify(rpcResponse));
		res.end();
		return;
	}

	res.statusCode = 400;
	res.end();
};

const server = createServer(listener);
const port = (process.env.PORT && parseInt(process.env.PORT, 10)) || 3001;
server.listen(port);`)

	return []*GeneratedFile{
		{
			Path:     filepath.Join(dir, ".build/server.js"),
			Contents: w.String(),
		},
	}
}

func generateTestingPackage(dir string, schema *proto.Schema) GeneratedFiles {
	js := &Writer{}
	types := &Writer{}

	// The testing package uses ES modules as it only used in the context of running tests
	// with Vitest
	js.Writeln(`import { getDatabase, createFunctionAPI } from "@teamkeel/sdk"`)
	js.Writeln(`import { ActionExecutor, sql } from "@teamkeel/testing-runtime";`)
	js.Writeln("")

	js.Writeln("const db = getDatabase();")

	js.Writeln(`export const actions = new ActionExecutor({});`)
	js.Writeln("export const models = createFunctionAPI({ headers: new Headers(), db }).models;")

	js.Writeln("export async function resetDatabase() {")
	js.Indent()
	js.Write("await sql`TRUNCATE TABLE ")
	tableNames := []string{}
	for _, model := range schema.Models {
		tableNames = append(tableNames, strcase.ToSnake(model.Name))
	}
	js.Writef("%s CASCADE", strings.Join(tableNames, ","))
	js.Writeln("`.execute(db);")
	js.Dedent()
	js.Writeln("}")

	writeTestingTypes(types, schema)

	return GeneratedFiles{
		{
			Path:     filepath.Join(dir, "node_modules/@teamkeel/testing/index.mjs"),
			Contents: js.String(),
		},
		{
			Path:     filepath.Join(dir, "node_modules/@teamkeel/testing/index.d.ts"),
			Contents: types.String(),
		},
		{
			Path:     filepath.Join(dir, "node_modules/@teamkeel/testing/package.json"),
			Contents: `{"name": "@teamkeel/testing", "type": "module", "exports": "./index.mjs"}`,
		},
	}
}

func generateTestingSetup(dir string) GeneratedFiles {
	return GeneratedFiles{
		{
			Path: filepath.Join(dir, ".build/vitest.config.mjs"),
			Contents: `
import { defineConfig } from "vitest/config";

export default defineConfig({
	test: {
		setupFiles: [__dirname + "/vitest.setup"],
	},
});
			`,
		},
		{
			Path: filepath.Join(dir, ".build/vitest.setup.mjs"),
			Contents: `
import { expect } from "vitest";
import { toHaveError, toHaveAuthorizationError } from "@teamkeel/testing-runtime";

expect.extend({
	toHaveError,
	toHaveAuthorizationError,
});
			`,
		},
	}
}

func writeTestingTypes(w *Writer, schema *proto.Schema) {
	w.Writeln(`import * as sdk from "@teamkeel/sdk";`)
	w.Writeln(`import * as runtime from "@teamkeel/functions-runtime";`)

	// We need to import the testing-runtime package to get
	// the types for the extended vitest matchers e.g. expect(v).toHaveAuthorizationError()
	w.Writeln(`import "@teamkeel/testing-runtime";`)
	w.Writeln("")

	// For the testing package we need input and response types for all actions
	writeMessages(w, schema)

	w.Writeln("declare class ActionExecutor {")
	w.Indent()
	w.Writeln("withIdentity(identity: sdk.Identity): ActionExecutor;")
	w.Writeln("withAuthToken(token: string): ActionExecutor;")
	for _, model := range schema.Models {
		for _, op := range model.Operations {
			msg := proto.FindMessage(schema.Messages, op.InputMessageName)

			w.Writef("%s(i", op.Name)

			// Check that all of the top level fields in the matching message are optional
			// If so, then we can make it so you don't even need to specify the key
			// example, this allows for:
			// await actions.listActivePublishersWithActivePosts();
			// instead of:
			// const { results: publishers } =
			// await actions.listActivePublishersWithActivePosts({ where: {} });
			if lo.EveryBy(msg.Fields, func(f *proto.MessageField) bool {
				return f.Optional
			}) {
				w.Write("?")
			}

			w.Writef(`: %s): %s`, op.InputMessageName, toActionReturnType(model, op))
			w.Writeln(";")
		}
	}
	w.Dedent()
	w.Writeln("}")
	w.Writeln("export declare const actions: ActionExecutor;")
	w.Writeln("export declare const models: sdk.ModelsAPI;")
	w.Writeln("export declare function resetDatabase(): Promise<void>;")
}

func toTypeScriptType(t *proto.TypeInfo) (ret string) {
	switch t.Type {
	case proto.Type_TYPE_ID:
		ret = "string"
	case proto.Type_TYPE_STRING:
		ret = "string"
	case proto.Type_TYPE_BOOL:
		ret = "boolean"
	case proto.Type_TYPE_INT:
		ret = "number"
	case proto.Type_TYPE_DATE, proto.Type_TYPE_DATETIME, proto.Type_TYPE_TIMESTAMP:
		ret = "Date"
	case proto.Type_TYPE_ENUM:
		ret = t.EnumName.Value
	case proto.Type_TYPE_MESSAGE:
		ret = t.MessageName.Value
	case proto.Type_TYPE_MODEL:
		ret = t.ModelName.Value
	default:
		ret = "any"
	}

	return ret
}

func toWhereConditionType(f *proto.Field) string {
	switch f.Type.Type {
	case proto.Type_TYPE_ID:
		return "runtime.IDWhereCondition"
	case proto.Type_TYPE_STRING:
		return "runtime.StringWhereCondition"
	case proto.Type_TYPE_BOOL:
		return "runtime.BooleanWhereCondition"
	case proto.Type_TYPE_INT:
		return "runtime.NumberWhereCondition"
	case proto.Type_TYPE_DATE, proto.Type_TYPE_DATETIME, proto.Type_TYPE_TIMESTAMP:
		return "runtime.DateWhereCondition"
	case proto.Type_TYPE_ENUM:
		return fmt.Sprintf("%sWhereCondition", f.Type.EnumName.Value)
	default:
		return "any"
	}
}
