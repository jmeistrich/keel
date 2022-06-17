package query

import (
	"github.com/gertd/go-pluralize"
	"github.com/teamkeel/keel/schema/node"
	"github.com/teamkeel/keel/schema/parser"
	"github.com/teamkeel/keel/util/str"
)

func APIs(asts []*parser.AST) (res []*parser.APINode) {
	for _, ast := range asts {
		for _, decl := range ast.Declarations {
			if decl.API != nil {
				res = append(res, decl.API)
			}
		}
	}
	return res
}

func Models(asts []*parser.AST) (res []*parser.ModelNode) {
	for _, ast := range asts {
		for _, decl := range ast.Declarations {
			if decl.Model != nil {
				res = append(res, decl.Model)
			}
		}
	}
	return res
}

func Model(asts []*parser.AST, name string) *parser.ModelNode {
	for _, ast := range asts {
		for _, decl := range ast.Declarations {
			if decl.Model != nil && decl.Model.Name.Value == name {
				return decl.Model
			}
		}
	}
	return nil
}

func ModelAttributes(model *parser.ModelNode) (res []*parser.AttributeNode) {
	for _, section := range model.Sections {
		if section.Attribute != nil {
			res = append(res, section.Attribute)
		}
	}
	return res
}

func Enums(asts []*parser.AST) (res []*parser.EnumNode) {
	for _, ast := range asts {
		for _, decl := range ast.Declarations {
			if decl.Enum != nil {
				res = append(res, decl.Enum)
			}
		}
	}
	return res
}

func Enum(asts []*parser.AST, name string) *parser.EnumNode {
	for _, ast := range asts {
		for _, decl := range ast.Declarations {
			if decl.Enum != nil && decl.Enum.Name.Value == name {
				return decl.Enum
			}
		}
	}
	return nil
}

func Roles(asts []*parser.AST) (res []*parser.RoleNode) {
	for _, ast := range asts {
		for _, decl := range ast.Declarations {
			if decl.Role != nil {
				res = append(res, decl.Role)
			}
		}
	}
	return res
}

func IsUserDefinedType(asts []*parser.AST, name string) bool {
	return Model(asts, name) != nil || Enum(asts, name) != nil
}

func UserDefinedTypes(asts []*parser.AST) (res []string) {
	for _, model := range Models(asts) {
		res = append(res, model.Name.Value)
	}
	for _, enum := range Enums(asts) {
		res = append(res, enum.Name.Value)
	}
	return res
}

func ModelActions(model *parser.ModelNode) (res []*parser.ActionNode) {
	for _, section := range model.Sections {
		res = append(res, section.Functions...)
		res = append(res, section.Operations...)
	}
	return res
}

func ModelFields(model *parser.ModelNode) (res []*parser.FieldNode) {
	for _, section := range model.Sections {
		res = append(res, section.Fields...)
	}
	return res
}

func ModelField(model *parser.ModelNode, name string) *parser.FieldNode {
	for _, section := range model.Sections {
		for _, field := range section.Fields {
			if field.Name.Value == name {
				return field
			}
		}
	}
	return nil
}

func FieldHasAttribute(field *parser.FieldNode, name string) bool {
	for _, attr := range field.Attributes {
		if attr.Name.Value == name {
			return true
		}
	}
	return false
}

func FieldIsUnique(field *parser.FieldNode) bool {
	return FieldHasAttribute(field, parser.AttributePrimaryKey) || FieldHasAttribute(field, parser.AttributeUnique)
}

type AssociationResolutionError struct {
	ErrorFragment string
	ContextModel  *parser.ModelNode
	Type          string
	Parent        string
	StartCol      int
}

func (err *AssociationResolutionError) Error() string {
	return err.ErrorFragment
}

func ResolveAssociation(asts []*parser.AST, contextModel *parser.ModelNode, fragments []string, currentFragmentIndex int) (*node.Node, error) {
	field := ModelField(contextModel, fragments[currentFragmentIndex])

	if field == nil {
		pluralize := pluralize.NewClient()
		title := str.AsTitle(pluralize.Singular(fragments[currentFragmentIndex-1]))
		previousContextModel := Model(asts, title)

		col := 0

		for i, frag := range fragments {
			if i > currentFragmentIndex {
				break
			}

			col += len(frag) + 2
		}

		if previousContextModel != nil {
			return nil, &AssociationResolutionError{
				ErrorFragment: fragments[currentFragmentIndex],
				ContextModel:  previousContextModel,
				Type:          "association",
				Parent:        fragments[currentFragmentIndex-1],
				StartCol:      col,
			}
		}

		panic("sjjssj")
	}

	newContextModelName := str.AsTitle(fragments[currentFragmentIndex+1])
	newContextModel := Model(asts, newContextModelName)

	return ResolveAssociation(asts, newContextModel, fragments, currentFragmentIndex+1)
}

func ModelFieldNames(asts []*parser.AST, model *parser.ModelNode) []string {
	names := []string{}
	for _, field := range ModelFields(model) {
		names = append(names, field.Name.Value)
	}
	return names
}
