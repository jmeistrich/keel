package parser

import (
	"fmt"
	"strings"
	"text/scanner"

	"github.com/alecthomas/participle/v2"
	"github.com/alecthomas/participle/v2/lexer"
	"github.com/iancoleman/strcase"
	"github.com/teamkeel/keel/schema/node"
	"github.com/teamkeel/keel/schema/reader"
)

type AST struct {
	node.Node

	Declarations         []*DeclarationNode `@@*`
	EnvironmentVariables []string
	Secrets              []string
}

type DeclarationNode struct {
	node.Node

	Model   *ModelNode   `("model" @@`
	Role    *RoleNode    `| "role" @@`
	API     *APINode     `| "api" @@`
	Enum    *EnumNode    `| "enum" @@`
	Message *MessageNode `| "message" @@)`
}

type ModelNode struct {
	node.Node

	Name     NameNode            `@@`
	Sections []*ModelSectionNode `"{" @@* "}"`
	BuiltIn  bool
}

type ModelSectionNode struct {
	node.Node

	Fields     []*FieldNode   `( "fields" "{" @@* "}"`
	Functions  []*ActionNode  `| "functions" "{" @@* "}"`
	Operations []*ActionNode  `| "operations" "{" @@* "}"`
	Attribute  *AttributeNode `| @@)`
}

type NameNode struct {
	node.Node

	Value string `@Ident`
}

type AttributeNameToken struct {
	node.Node

	Value string `"@" @Ident`
}

type FieldNode struct {
	node.Node

	Name       NameNode         `@@`
	Type       string           `@Ident`
	Repeated   bool             `( @( "[" "]" )`
	Optional   bool             `| @( "?" ))?`
	Attributes []*AttributeNode `( "{" @@+ "}" | @@+ )?`

	// Some fields are added implicitly after parsing the schema
	// For these fields this value is set to true so we can distinguish
	// them from fields defined by the user in the schema
	BuiltIn bool

	// This field is set only for fields that are either our auto-generated
	// foreign key fields, or their sibling "owner" fields.
	FkInfo *ForeignKeyAssociation
}

// ForeignKeyAssociation encapsulates everything relevant to the foreign key fields we auto
// generate into the AST for some models. The generated fields are derived from an "Owning"
// field (of type Model) defined explicitly in the keel schema, and with topology HasOne.
type ForeignKeyAssociation struct {
	OwningModel     *ModelNode
	OwningField     *FieldNode // A field in the OwningModel that is of type MODEL, and topology HasOne.
	ForeignKeyField *FieldNode // Field on owning model that carries the foreign key values.

	ReferredToModel           *ModelNode
	ReferredToModelPrimaryKey *FieldNode // Which field in the ReferredToModel is its Primary Key
}

type APINode struct {
	node.Node

	Name     NameNode          `@@`
	Sections []*APISectionNode `"{" @@* "}"`
}

type APISectionNode struct {
	node.Node

	Models    []*ModelsNode  `("models" "{" @@* "}"`
	Attribute *AttributeNode `| @@)`
}

type RoleNode struct {
	node.Node

	Name     NameNode           `@@`
	Sections []*RoleSectionNode `"{" @@* "}"`
}

type RoleSectionNode struct {
	node.Node

	Domains []*DomainNode `("domains" "{" @@* "}"`
	Emails  []*EmailsNode `| "emails" "{" @@* "}")`
}

type DomainNode struct {
	node.Node

	Domain string `@String`
}

type EmailsNode struct {
	node.Node

	Email string `@String`
}

type ModelsNode struct {
	node.Node

	Name NameNode `@@`
}

// Attributes:
// - @permission
// - @set
// - @validate
// - @where
// - @unique
// - @default
type AttributeNode struct {
	node.Node

	Name AttributeNameToken `@@`

	// This supports:
	// - no parenthesis at all
	// - empty parenthesis
	// - parenthesis with args
	Arguments []*AttributeArgumentNode `(( "(" @@ ( "," @@ )* ")" ) | ( "(" ")" ) )?`
}

type AttributeArgumentNode struct {
	node.Node

	Label      *NameNode   `(@@ ":")?`
	Expression *Expression `@@`
}

type ActionNode struct {
	node.Node

	Type       NameNode           `@@`
	Name       NameNode           `@@`
	Inputs     []*ActionInputNode `"(" ( @@ ( "," @@ )* )? ")"`
	With       []*ActionInputNode `( ( "with" "(" ( @@ ( "," @@ )* ) ")" )`
	Returns    []*ActionInputNode `| ( "returns" "(" ( @@ ( "," @@ )* ) ")" ) )?`
	Attributes []*AttributeNode   `( "{" @@+ "}" )?`
}

func (a *ActionNode) IsArbitraryFunction() bool {
	return len(a.Returns) > 0 && (a.Type.Value == ActionTypeRead || a.Type.Value == ActionTypeWrite)
}

type ActionInputNode struct {
	node.Node

	Label    *NameNode `(@@ ":")?`
	Type     Ident     `@@`
	Repeated bool      `( @( "[" "]" )`
	Optional bool      `| @( "?" ))?`
}

func (a *ActionInputNode) Name() string {
	if a.Label != nil {
		return a.Label.Value
	}

	// if label is not provided then it's computed from the type
	// e.g. if type is `post.author.name` then the input is called `postAuthorName`
	builder := strings.Builder{}
	for _, frag := range a.Type.Fragments {
		builder.WriteString(strcase.ToCamel(frag.Fragment))
	}

	return strcase.ToLowerCamel(builder.String())
}

type EnumNode struct {
	node.Node

	Name   NameNode         `@@`
	Values []*EnumValueNode `"{" @@* "}"`
}

type EnumValueNode struct {
	node.Node

	Name NameNode `@@`
}

type MessageNode struct {
	node.Node

	Name NameNode `@@`

	// todo: can we use field node here
	Fields []*FieldNode `"{" @@* "}"`
}

type Error struct {
	err participle.Error
}

// compile-time check that Error inplements node.ParserNode
var _ node.ParserNode = Error{}

func (e Error) Error() string {
	msg := e.err.Error()
	pos := e.err.Position()

	// error messages start with "{filename}:{line}:{column}:" and we don't
	// really need that bit so we can remove it
	return strings.TrimPrefix(msg, fmt.Sprintf("%s:%d:%d:", pos.Filename, pos.Line, pos.Column))
}

func (e Error) GetPositionRange() (start lexer.Position, end lexer.Position) {
	pos := e.err.Position()
	return pos, pos
}

func (e Error) InRange(position node.Position) bool {
	// Just use Node's implementation of InRange
	return node.Node{Pos: e.err.Position()}.InRange(position)
}

func (e Error) HasEndPosition() bool {
	// Just use Node's implementation of HasEndPosition
	return node.Node{Pos: e.err.Position()}.HasEndPosition()
}

func (e Error) GetTokens() []lexer.Token {
	return []lexer.Token{}
}

func Parse(s *reader.SchemaFile) (*AST, error) {
	// Customise the lexer to not ignore comments
	lex := lexer.NewTextScannerLexer(func(s *scanner.Scanner) {
		s.Mode =
			scanner.ScanIdents |
				scanner.ScanFloats |
				scanner.ScanChars |
				scanner.ScanStrings |
				scanner.ScanComments
	})

	parser, err := participle.Build[AST](participle.Lexer(lex), participle.Elide("Comment"))
	if err != nil {
		return nil, err
	}

	schema, err := parser.ParseString(s.FileName, s.Contents)
	if err != nil {

		// If the error is a participle.Error (which it should be)
		// then return an error that also implements the node.Node
		// interface so that we can later on turn it into a validation
		// error
		perr, ok := err.(participle.Error)
		if ok {
			return schema, Error{perr}
		}

		return schema, err
	}

	return schema, nil
}
