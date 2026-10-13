package validator

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/grokify/ocsf-schema-go/ocsf/ocsfdata"
	"github.com/grokify/ocsf-schema-go/validate"
)

// OCSFValidator validates events against the compiled OCSF schema embedded
// in ocsf-schema-go: required attributes (profile-aware), attribute types,
// enum membership, nested objects, at_least_one/just_one constraints, and
// class_uid/category_uid/type_uid consistency.
type OCSFValidator struct {
	v    *validate.Validator
	mode Mode
}

// structuralCodes are the issues that make an event unusable for storage
// regardless of validation mode: without a parseable payload and a known
// class, the lake cannot index the event.
var structuralCodes = map[validate.Code]bool{
	validate.CodeInvalidJSON:     true,
	validate.CodeMissingClassUID: true,
	validate.CodeUnknownClass:    true,
}

// NewOCSFValidator creates a schema-backed validator with the given mode.
// Additional validate options (e.g. validate.WithUnknownAttributes) tune the
// underlying semantic validator.
func NewOCSFValidator(mode Mode, opts ...validate.Option) *OCSFValidator {
	return &OCSFValidator{
		v:    validate.New(ocsfdata.MustSchema(), opts...),
		mode: mode,
	}
}

// Validate checks an OCSF event against the schema, dispatching on the
// payload's class_uid.
func (v *OCSFValidator) Validate(ctx context.Context, event json.RawMessage) error {
	if v.mode == ModeDisabled {
		return nil
	}
	return v.toError(v.v.ValidateEvent(event))
}

// ValidateClass validates an event against a specific event class schema.
func (v *OCSFValidator) ValidateClass(ctx context.Context, classUID int, event json.RawMessage) error {
	if v.mode == ModeDisabled {
		return nil
	}
	cls, ok := v.v.Class(classUID)
	if !ok {
		return fmt.Errorf("%w: %d", ErrSchemaNotFound, classUID)
	}
	result, err := v.v.ValidateEventClass(cls.Name, event)
	if err != nil {
		return err
	}
	return v.toError(result)
}

// toError converts a validation result into an error according to the mode.
func (v *OCSFValidator) toError(result *validate.Result) error {
	errs := result.Errors()
	if len(errs) == 0 {
		return nil
	}
	if v.mode == ModePermissive {
		structural := errs[:0:0]
		for _, issue := range errs {
			if structuralCodes[issue.Code] {
				structural = append(structural, issue)
			}
		}
		if len(structural) == 0 {
			return nil
		}
		errs = structural
	}

	out := &ValidationResult{ClassUID: result.ClassUID}
	for _, issue := range errs {
		out.Errors = append(out.Errors, ValidationError{
			Field:   issue.Path,
			Path:    issue.Path,
			Message: issue.String(),
		})
	}
	return out
}

// Result returns the full validation result (including warnings) for an
// event, independent of mode. Useful for surfacing diagnostics without
// failing ingestion.
func (v *OCSFValidator) Result(event json.RawMessage) *validate.Result {
	return v.v.ValidateEvent(event)
}
