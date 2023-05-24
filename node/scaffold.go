package node

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/teamkeel/keel/casing"
	"github.com/teamkeel/keel/codegen"
	"github.com/teamkeel/keel/proto"
)

const (
	FUNCTIONS_DIR = "functions"
)

func Scaffold(dir string, schema *proto.Schema) (codegen.GeneratedFiles, error) {
	files, err := Generate(context.TODO(), schema)

	if err != nil {
		return nil, err
	}

	err = files.Write(dir)

	if err != nil {
		return nil, err
	}

	functionsDir := filepath.Join(dir, FUNCTIONS_DIR)
	if err := ensureDir(functionsDir); err != nil {
		return nil, err
	}

	generatedFiles := codegen.GeneratedFiles{}

	functions := proto.FilterOperations(schema, func(op *proto.Operation) bool {
		return op.Implementation == proto.OperationImplementation_OPERATION_IMPLEMENTATION_CUSTOM
	})

	for _, fn := range functions {
		path := filepath.Join(FUNCTIONS_DIR, fmt.Sprintf("%s.ts", fn.Name))

		_, err = os.Stat(filepath.Join(dir, path))

		if os.IsNotExist(err) {
			generatedFiles = append(generatedFiles, &codegen.GeneratedFile{
				Path:     path,
				Contents: writeFunctionWrapper(fn),
			})
		}

	}

	return generatedFiles, nil
}

func ensureDir(dirName string) error {
	err := os.Mkdir(dirName, 0700)

	if err == nil || os.IsExist(err) {
		return nil
	} else {
		return err
	}
}

func writeFunctionWrapper(function *proto.Operation) string {
	functionName := casing.ToCamel(function.Name)

	suggestedImplementation := ""
	modelName := casing.ToLowerCamel(function.ModelName)

	requiresModelsInput := true

	switch function.Type {
	case proto.OperationType_OPERATION_TYPE_CREATE:
		suggestedImplementation = fmt.Sprintf(`const %s = await models.%s.create(inputs);
	return %s;`, modelName, modelName, modelName)
	case proto.OperationType_OPERATION_TYPE_LIST:
		// todo: fix bang! below
		suggestedImplementation = fmt.Sprintf(`const %ss = await models.%s.findMany(inputs.where!);
	return %ss;`, modelName, modelName, modelName)
	case proto.OperationType_OPERATION_TYPE_GET:
		suggestedImplementation = fmt.Sprintf(`const %s = await models.%s.findOne(inputs);
	return %s;`, modelName, modelName, modelName)
	case proto.OperationType_OPERATION_TYPE_UPDATE:
		suggestedImplementation = fmt.Sprintf(`const %s = await models.%s.update(inputs.where, inputs.values);
	return %s;`, modelName, modelName, modelName)
	case proto.OperationType_OPERATION_TYPE_DELETE:
		suggestedImplementation = fmt.Sprintf(`const %s = await models.%s.delete(inputs);
	return %s;`, modelName, modelName, modelName)
	case proto.OperationType_OPERATION_TYPE_READ, proto.OperationType_OPERATION_TYPE_WRITE:
		suggestedImplementation = "// Build something cool"
		requiresModelsInput = false
	}

	extraImports := ""

	if requiresModelsInput {
		// import models from the sdk for those scaffolded functions who's default
		// implementation hits the database via the model api
		extraImports += ", models"
	}

	return fmt.Sprintf(`import { %s%s } from '@teamkeel/sdk';

export default %s(async (ctx, inputs) => {
	%s
});
	`, functionName, extraImports, functionName, suggestedImplementation)
}
