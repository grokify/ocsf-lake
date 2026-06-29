// Package validator provides OCSF event validation against JSON Schema.
package validator

import (
	"context"
	"encoding/json"
	"errors"
)

// Common validation errors.
var (
	ErrMissingClassUID    = errors.New("missing required field: class_uid")
	ErrMissingCategoryUID = errors.New("missing required field: category_uid")
	ErrMissingActivityID  = errors.New("missing required field: activity_id")
	ErrMissingTypeUID     = errors.New("missing required field: type_uid")
	ErrMissingTime        = errors.New("missing required field: time")
	ErrInvalidJSON        = errors.New("invalid JSON")
	ErrSchemaNotFound     = errors.New("schema not found for class_uid")
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
	// ModeStrict rejects any invalid events.
	ModeStrict Mode = iota
	// ModePermissive accepts events with warnings for non-critical issues.
	ModePermissive
	// ModeDisabled skips validation entirely.
	ModeDisabled
)

// Options configures the validator behavior.
type Options struct {
	Mode          Mode
	SchemaVersion string
}

// DefaultOptions returns the default validator options.
func DefaultOptions() Options {
	return Options{
		Mode:          ModeStrict,
		SchemaVersion: "1.3.0",
	}
}
