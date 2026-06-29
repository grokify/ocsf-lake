package validator

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// SchemaValidator validates OCSF events using JSON Schema.
type SchemaValidator struct {
	compiler *jsonschema.Compiler
	schemas  map[int]*jsonschema.Schema // class_uid -> compiled schema
	mode     Mode
}

// NewSchemaValidator creates a new schema-based validator.
func NewSchemaValidator(opts Options) *SchemaValidator {
	return &SchemaValidator{
		compiler: jsonschema.NewCompiler(),
		schemas:  make(map[int]*jsonschema.Schema),
		mode:     opts.Mode,
	}
}

// Validate checks an OCSF event against the schema.
func (v *SchemaValidator) Validate(ctx context.Context, event json.RawMessage) error {
	if v.mode == ModeDisabled {
		return nil
	}

	// First, validate that required fields exist
	if err := v.validateRequiredFields(event); err != nil {
		if v.mode == ModeStrict {
			return err
		}
		// In permissive mode, log but continue
		return nil
	}

	return nil
}

// ValidateClass validates an event against a specific event class schema.
func (v *SchemaValidator) ValidateClass(ctx context.Context, classUID int, event json.RawMessage) error {
	if v.mode == ModeDisabled {
		return nil
	}

	// First validate required fields
	if err := v.validateRequiredFields(event); err != nil {
		if v.mode == ModeStrict {
			return err
		}
	}

	// Then validate against class-specific schema if available
	schema, ok := v.schemas[classUID]
	if !ok {
		// No schema loaded for this class
		if v.mode == ModeStrict {
			return fmt.Errorf("%w: %d", ErrSchemaNotFound, classUID)
		}
		return nil
	}

	// Unmarshal to interface for schema validation
	var data any
	if err := json.Unmarshal(event, &data); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidJSON, err)
	}

	// Validate against schema
	if err := schema.Validate(data); err != nil {
		if v.mode == ModeStrict {
			return fmt.Errorf("schema validation failed: %w", err)
		}
	}

	return nil
}

// validateRequiredFields checks that all required OCSF fields are present.
func (v *SchemaValidator) validateRequiredFields(event json.RawMessage) error {
	var parsed map[string]any
	if err := json.Unmarshal(event, &parsed); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidJSON, err)
	}

	// Check class_uid
	if _, ok := parsed["class_uid"]; !ok {
		return ErrMissingClassUID
	}
	if !isValidIntField(parsed["class_uid"]) {
		return fmt.Errorf("class_uid must be an integer")
	}

	// Check category_uid
	if _, ok := parsed["category_uid"]; !ok {
		return ErrMissingCategoryUID
	}
	if !isValidIntField(parsed["category_uid"]) {
		return fmt.Errorf("category_uid must be an integer")
	}

	// Check activity_id
	if _, ok := parsed["activity_id"]; !ok {
		return ErrMissingActivityID
	}
	if !isValidIntField(parsed["activity_id"]) {
		return fmt.Errorf("activity_id must be an integer")
	}

	// Check type_uid
	if _, ok := parsed["type_uid"]; !ok {
		return ErrMissingTypeUID
	}
	if !isValidIntField(parsed["type_uid"]) {
		return fmt.Errorf("type_uid must be an integer")
	}

	// Check time
	if _, ok := parsed["time"]; !ok {
		return ErrMissingTime
	}
	if !isValidIntField(parsed["time"]) {
		return fmt.Errorf("time must be an integer (epoch milliseconds)")
	}

	return nil
}

// RegisterSchema registers a JSON Schema for a specific class UID.
func (v *SchemaValidator) RegisterSchema(classUID int, schemaJSON []byte) error {
	schemaID := "ocsf://class/" + strconv.Itoa(classUID)

	// Unmarshal the JSON schema to any
	var schemaDoc any
	if err := json.Unmarshal(schemaJSON, &schemaDoc); err != nil {
		return fmt.Errorf("failed to parse schema JSON for class %d: %w", classUID, err)
	}

	// Add the schema as a resource
	if err := v.compiler.AddResource(schemaID, schemaDoc); err != nil {
		return fmt.Errorf("failed to add schema resource for class %d: %w", classUID, err)
	}

	// Compile the schema
	schema, err := v.compiler.Compile(schemaID)
	if err != nil {
		return fmt.Errorf("failed to compile schema for class %d: %w", classUID, err)
	}

	v.schemas[classUID] = schema
	return nil
}

// isValidIntField checks if a value is a valid integer field.
func isValidIntField(v any) bool {
	switch val := v.(type) {
	case int, int32, int64:
		return true
	case float64:
		// JSON numbers are float64 by default
		return val == float64(int64(val))
	default:
		return false
	}
}

// BasicValidator performs minimal validation without JSON Schema.
// Use this when OCSF schemas are not available.
type BasicValidator struct {
	mode Mode
}

// NewBasicValidator creates a validator that only checks required fields.
func NewBasicValidator(mode Mode) *BasicValidator {
	return &BasicValidator{mode: mode}
}

// Validate checks that required OCSF fields are present.
func (v *BasicValidator) Validate(ctx context.Context, event json.RawMessage) error {
	if v.mode == ModeDisabled {
		return nil
	}

	var parsed map[string]any
	if err := json.Unmarshal(event, &parsed); err != nil {
		if v.mode == ModeStrict {
			return fmt.Errorf("%w: %v", ErrInvalidJSON, err)
		}
		return nil
	}

	// Check required fields
	requiredFields := []string{"class_uid", "category_uid", "activity_id", "type_uid", "time"}
	var errors []ValidationError

	for _, field := range requiredFields {
		if _, ok := parsed[field]; !ok {
			errors = append(errors, ValidationError{
				Field:   field,
				Message: fmt.Sprintf("missing required field: %s", field),
			})
		}
	}

	if len(errors) > 0 && v.mode == ModeStrict {
		return &ValidationResult{
			Valid:  false,
			Errors: errors,
		}
	}

	return nil
}

// ValidateClass performs the same validation as Validate for BasicValidator.
func (v *BasicValidator) ValidateClass(ctx context.Context, classUID int, event json.RawMessage) error {
	return v.Validate(ctx, event)
}
