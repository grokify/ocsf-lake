// Package validator provides OCSF event validation for the lake, backed by
// the compiled OCSF schema embedded in github.com/grokify/ocsf-schema-go.
package validator

import (
	"context"
	"encoding/json"
	"errors"
)

// Common validation errors.
var (
	ErrInvalidJSON    = errors.New("invalid JSON")
	ErrSchemaNotFound = errors.New("schema not found for class_uid")
)

// Validator validates OCSF events.
type Validator interface {
	// Validate checks an OCSF event against the schema.
	// Returns nil if valid, or an error describing the validation failure.
	Validate(ctx context.Context, event json.RawMessage) error

	// ValidateClass validates an event against a specific event class schema.
	ValidateClass(ctx context.Context, classUID int, event json.RawMessage) error
}

// ValidationResult contains detailed validation results.
type ValidationResult struct {
	Valid    bool              `json:"valid"`
	Errors   []ValidationError `json:"errors,omitempty"`
	ClassUID int               `json:"class_uid,omitempty"`
}

// ValidationError represents a single validation error.
type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
	Path    string `json:"path,omitempty"`
}

// Error implements the error interface for ValidationResult.
func (r *ValidationResult) Error() string {
	if len(r.Errors) == 0 {
		return "validation failed"
	}
	return r.Errors[0].Message
}

// Mode specifies the validation strictness.
type Mode int

const (
	// ModeStrict rejects events with any schema violation (missing required
	// attributes, wrong types, invalid enum values, constraint violations,
	// inconsistent classification UIDs).
	ModeStrict Mode = iota
	// ModePermissive rejects only structurally unusable events (malformed
	// JSON, missing class_uid, unknown event class); other schema
	// violations are tolerated.
	ModePermissive
	// ModeDisabled skips validation entirely.
	ModeDisabled
)
