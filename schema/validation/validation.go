package validation

import (
	"github.com/teamkeel/keel/schema/parser"
	"github.com/teamkeel/keel/schema/validation/errorhandling"
	"github.com/teamkeel/keel/schema/validation/rules/actions"
	"github.com/teamkeel/keel/schema/validation/rules/api"
	"github.com/teamkeel/keel/schema/validation/rules/attribute"
	"github.com/teamkeel/keel/schema/validation/rules/enum"
	"github.com/teamkeel/keel/schema/validation/rules/field"
	"github.com/teamkeel/keel/schema/validation/rules/messages"
	"github.com/teamkeel/keel/schema/validation/rules/model"
	"github.com/teamkeel/keel/schema/validation/rules/relationships"
	"github.com/teamkeel/keel/schema/validation/rules/role"
)

type Validator struct {
	asts []*parser.AST
}

func NewValidator(asts []*parser.AST) *Validator {
	return &Validator{
		asts: asts,
	}
}

// A Validator knows how to validate a parsed Keel schema.
//
// Conceptually we are validating a single schema.
// But the Validator supports it being "delivered" as a collection
// of *parser.Schema objects - to match up with a user's schema likely
// being written across N files.

type validationFunc func(asts []*parser.AST) errorhandling.ValidationErrors

var validatorFuncs = []validationFunc{
	model.ReservedModelNamesRule,
	model.ModelNamingRule,
	model.UniqueModelNamesRule,
	actions.ActionNamingRule,
	actions.ActionTypesRule,
	actions.UniqueOperationNamesRule,
	actions.ValidActionInputTypesRule,
	actions.ValidOperationInputUsagesRule,
	actions.GetOperationUniqueConstraintRule,
	actions.DeleteOperationUniqueConstraintRule,
	actions.ListActionModelInputsRule,
	actions.UpdateOperationUniqueConstraintRule,
	actions.CreateOperationNoReadInputsRule,
	actions.CreateOperationRequiredFieldsRule,
	actions.ReservedActionNameRule,
	field.ReservedNameRule,
	field.ValidFieldTypesRule,
	field.UniqueFieldNamesRule,
	field.FieldNamingRule,
	attribute.AttributeLocationsRule,
	attribute.PermissionAttributeRule,
	attribute.SetWhereAttributeRule,
	attribute.ValidateActionAttributeRule,
	attribute.ValidateFieldAttributeRule,
	attribute.UniqueAttributeArgsRule,
	role.UniqueRoleNamesRule,
	api.UniqueAPINamesRule,
	api.NamesCorrespondToModels,
	enum.UniqueEnumsRule,
	relationships.InvalidOneToOneRelationshipRule,
	relationships.InvalidImplicitBelongsToWithHasManyRule,
	// todo this rule should obsolete MoreThanOneReverseMany (below), once it is finished.
	relationships.RelationAttributeRule,
	relationships.MoreThanOneReverseMany, // todo this should become obsolete
	messages.MessageNamesRule,
}

func (v *Validator) RunAllValidators() (errs *errorhandling.ValidationErrors) {
	errs = &errorhandling.ValidationErrors{}

	for _, vf := range validatorFuncs {
		errs.Concat(vf(v.asts))
	}

	if len(errs.Errors) == 0 {
		return nil
	}

	return errs
}
