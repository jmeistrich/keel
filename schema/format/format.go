package format

import (
	"fmt"
	"regexp"
	"strings"
	"text/scanner"

	"github.com/alecthomas/participle/v2/lexer"
	"github.com/iancoleman/strcase"
	"github.com/samber/lo"
	"github.com/teamkeel/keel/schema/node"
	"github.com/teamkeel/keel/schema/parser"
)

const (
	indentSize = 4
)

type Writer struct {
	b          strings.Builder
	currIndent int

	// We keep a stack of comments as when ending a block
	// we will print any trailing comments inside the closing
	// paren
	commentStack [][]lexer.Token

	// We keep a cache of which comments we've already printed
	// as the same comment tokens can appear on different nodes
	commentCache map[string]bool
}

func (w *Writer) WriteLine(s string, args ...any) {
	if w.isStartOfLine() && s != "" {
		w.b.WriteString(strings.Repeat(" ", w.currIndent))
	}
	w.b.WriteString(fmt.Sprintf(s+"\n", args...))
}

func (w *Writer) Write(s string, args ...any) {
	if w.isStartOfLine() && s != "" {
		w.b.WriteString(strings.Repeat(" ", w.currIndent))
	}
	w.b.WriteString(fmt.Sprintf(s, args...))
}

func (w *Writer) Indent() {
	w.currIndent += indentSize
}

func (w *Writer) Dedent() {
	w.currIndent -= indentSize
	if w.currIndent < 0 {
		w.currIndent = 0
	}
}

func (w *Writer) Block(fn func()) {
	w.WriteLine(" {")
	w.Indent()
	fn()
	if len(w.commentStack) > 0 {
		tokens := w.commentStack[len(w.commentStack)-1]
		w.trailingComments(tokens)
	}
	w.Dedent()
	w.WriteLine("}")
}

func (w *Writer) Comments(node node.ParserNode, fn func()) {
	tokens := node.GetTokens()
	w.commentStack = append(w.commentStack, tokens)

	w.leadingComments(tokens)
	fn()
	w.trailingComments(tokens)

	w.commentStack = w.commentStack[0 : len(w.commentStack)-1]
}

func (w *Writer) leadingComments(tokens []lexer.Token) {
	for _, t := range tokens {
		if t.Type != scanner.Comment {
			return
		}
		if !w.seenToken(t) {
			w.WriteLine(t.Value)
		}
	}
}

func (w *Writer) trailingComments(tokens []lexer.Token) {
	comments := []lexer.Token{}
	for i := len(tokens) - 1; i >= 0; i-- {
		t := tokens[i]
		if t.Type == '}' {
			continue
		}
		if t.Type != scanner.Comment {
			break
		}
		comments = append(comments, t)
	}
	for _, t := range lo.Reverse(comments) {
		if !w.seenToken(t) {
			w.WriteLine(t.Value)
		}
	}
}

func (w *Writer) seenToken(t lexer.Token) bool {
	key := fmt.Sprintf("%d:%d", t.Pos.Line, t.Pos.Column)
	_, seen := w.commentCache[key]
	if !seen {
		w.commentCache[key] = true
	}
	return seen
}

func (w *Writer) String() string {
	return w.b.String()
}

func (w *Writer) isStartOfLine() bool {
	s := w.b.String()
	return len(s) > 0 && s[len(s)-1] == '\n'
}

func Format(ast *parser.AST) string {
	writer := &Writer{
		commentStack: [][]lexer.Token{},
		commentCache: map[string]bool{},
	}

	for i, decl := range ast.Declarations {
		if i > 0 {
			writer.WriteLine("")
		}
		writer.Comments(decl, func() {
			switch {
			case decl.Model != nil:
				printModel(writer, decl.Model)
			case decl.Enum != nil:
				printEnum(writer, decl.Enum)
			case decl.Role != nil:
				printRole(writer, decl.Role)
			case decl.API != nil:
				printApi(writer, decl.API)
			}
		})
	}

	return writer.String()
}

func printModel(writer *Writer, model *parser.ModelNode) {
	writer.Comments(model, func() {
		writer.Write("model %s", camel(model.Name.Value))
		writer.Block(func() {

			fieldSections := []*parser.ModelSectionNode{}
			operationSections := []*parser.ModelSectionNode{}
			functionSections := []*parser.ModelSectionNode{}
			attributeSections := []*parser.ModelSectionNode{}

			for _, section := range model.Sections {
				if section.Fields != nil {
					fieldSections = append(fieldSections, section)
				}
				if section.Operations != nil {
					operationSections = append(operationSections, section)
				}
				if section.Functions != nil {
					functionSections = append(functionSections, section)
				}
				if section.Attribute != nil {
					attributeSections = append(attributeSections, section)
				}
			}

			sections := 0

			for _, section := range fieldSections {
				fields := section.Fields
				writer.Comments(section, func() {
					writer.Write("fields")
					writer.Block(func() {
						for _, field := range fields {
							if field.BuiltIn {
								continue
							}

							fieldType := camel(field.Type)
							if field.Optional {
								fieldType += "?"
							}
							if field.Repeated {
								fieldType += "[]"
							}

							writer.Comments(field, func() {
								writer.Write(
									"%s %s",
									lowerCamel(field.Name.Value),
									fieldType,
								)

								hasComments := false
								for _, attr := range field.Attributes {
									if attr.Tokens[0].Type == scanner.Comment {
										hasComments = true
									}
								}

								// TODO: this needs a lot more thought, but for now
								// we omit the curly braces if there is just one
								// attribute and no comments, otherwise the attributes
								// get wrapper in a block
								if len(field.Attributes) == 1 && !hasComments {
									writer.Write(" ")
									printAttributes(writer, field.Attributes)
								} else {
									printAttributesBlock(writer, field.Attributes)
								}
							})
						}
					})
				})
				sections++
			}

			for _, section := range operationSections {
				if sections > 0 {
					writer.WriteLine("")
				}
				printActionsBlock(writer, section)
				sections++
			}

			for _, section := range functionSections {
				if sections > 0 {
					writer.WriteLine("")
				}
				printActionsBlock(writer, section)
				sections++
			}

			for _, section := range attributeSections {
				if sections > 0 {
					writer.WriteLine("")
				}
				writer.Comments(section, func() {
					printAttributes(writer, []*parser.AttributeNode{section.Attribute})
				})
				sections++
			}
		})
	})
}

func printActionsBlock(writer *Writer, section *parser.ModelSectionNode) {
	writer.Comments(section, func() {

		actions := []*parser.ActionNode{}
		if section.Operations != nil {
			actions = section.Operations
			writer.Write("operations")
		}
		if section.Functions != nil {
			actions = section.Functions
			writer.Write("functions")
		}

		writer.Block(func() {
			for _, op := range actions {
				writer.Comments(op, func() {
					writer.Write(
						"%s %s",
						lowerCamel(op.Type.Value),
						lowerCamel(op.Name.Value),
					)

					printOperationInputs(writer, op.Inputs)

					if len(op.With) > 0 {
						writer.Write(" with ")
						printOperationInputs(writer, op.With)
					}

					printAttributesBlock(writer, op.Attributes)
				})
			}
		})
	})
}

func printOperationInputs(writer *Writer, inputs []*parser.ActionInputNode) {
	writer.Write("(")
	for i, arg := range inputs {
		if i > 0 {
			writer.Write(", ")
		}

		if arg.Label != nil {
			// explicit input
			writer.Write("%s: %s", arg.Label.Value, arg.Type.Fragments[0].Fragment)
		} else {

			// Note: not using arg.Type.ToString() here as we want to try
			// and fix any casing issues
			for i, fragment := range arg.Type.Fragments {
				if i > 0 {
					writer.Write(".")
				}
				writer.Write(lowerCamel(fragment.Fragment))
			}
		}

		if arg.Optional {
			writer.Write("?")
		}
		if arg.Repeated {
			writer.Write("[]")
		}
	}

	writer.Write(")")
}

func printRole(writer *Writer, role *parser.RoleNode) {
	writer.Comments(role, func() {

		writer.Write("role %s", camel(role.Name.Value))
		writer.Block(func() {
			sections := 0
			// domains
			for _, section := range role.Sections {
				if len(section.Domains) > 0 {
					sections++
					writer.Comments(section, func() {
						writer.Write("domains")
						writer.Block((func() {
							for _, domain := range section.Domains {
								writer.Comments(domain, func() {
									writer.WriteLine(domain.Domain)
								})
							}
						}))
					})
				}
			}

			// emails
			for _, section := range role.Sections {
				if len(section.Emails) > 0 {
					if sections > 0 {
						writer.WriteLine("")
					}
					writer.Comments(section, func() {
						writer.Write("emails")
						writer.Block(func() {
							for _, email := range section.Emails {
								writer.Comments(email, func() {
									writer.WriteLine(email.Email)
								})
							}
						})
					})
				}
			}
		})
	})
}

func printApi(writer *Writer, api *parser.APINode) {
	writer.Comments(api, func() {
		writer.Write("api %s", camel(api.Name.Value))
		writer.Block(func() {
			for i, section := range api.Sections {
				if i > 0 {
					writer.WriteLine("")
				}
				writer.Comments(section, func() {
					switch {
					case len(section.Models) > 0:
						writer.Write("models")
						writer.Block(func() {
							for _, model := range section.Models {
								writer.Comments(model, func() {
									writer.WriteLine(camel(model.Name.Value))
								})
							}
						})
					case section.Attribute != nil:
						printAttributes(writer, []*parser.AttributeNode{section.Attribute})
					}
				})
			}
		})
	})
}

func printAttributesBlock(writer *Writer, attributes []*parser.AttributeNode) {
	if len(attributes) == 0 {
		writer.WriteLine("")
		return
	}

	writer.Block(func() {
		printAttributes(writer, attributes)
	})
}

func printAttributes(writer *Writer, attributes []*parser.AttributeNode) {
	for _, attr := range attributes {
		writer.Comments(attr, func() {
			writer.Write("@%s", lowerCamel(attr.Name.Value))

			if len(attr.Arguments) > 0 {
				writer.Write("(")

				isMultiline := len(attr.Arguments) > 1
				if isMultiline {
					writer.WriteLine("")
					writer.Indent()
				}

				for i, arg := range attr.Arguments {
					if i > 0 {
						if isMultiline {
							writer.WriteLine(",")
						} else {
							writer.Write(", ")
						}
					}
					writer.Comments(arg, func() {
						if arg.Label != nil {
							writer.Write("%s: ", lowerCamel(arg.Label.Value))
						}
						expr, _ := arg.Expression.ToString()
						writer.Write(expr)
					})
				}

				if isMultiline {
					writer.WriteLine("")
					writer.Dedent()
				}

				writer.Write(")")
			}

			writer.WriteLine("")
		})
	}
}

var allCapsRe = regexp.MustCompile("^[A-Z]+$")

func camel(s string) string {
	// Special case if the string is "FOOBAR" we want "Foobar" but
	// to get there we have to first lower case the string so
	// strcase.ToCamel does the right thing
	if allCapsRe.MatchString(s) {
		s = strings.ToLower(s)
	}

	return strcase.ToCamel(s)
}

func lowerCamel(s string) string {
	// Special case if the string is "FOOBAR" we want "foobar"
	if allCapsRe.MatchString(s) {
		return strings.ToLower(s)
	}

	return strcase.ToLowerCamel(s)
}

func printEnum(writer *Writer, enum *parser.EnumNode) {
	writer.Comments(enum, func() {
		writer.Write("enum %s", camel(enum.Name.Value))
		writer.Block(func() {
			for _, v := range enum.Values {
				writer.Comments(v, func() {
					writer.WriteLine(camel(v.Name.Value))
				})
			}
		})
	})
}
