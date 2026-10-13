package validator

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

var validEvent = json.RawMessage(`{
	"activity_id": 1,
	"category_uid": 3,
	"class_uid": 3002,
	"severity_id": 1,
	"time": 1704067200000,
	"type_uid": 300201,
	"metadata": {"version": "1.3.0", "product": {"name": "test"}},
	"user": {"name": "jdoe", "type_id": 1},
	"dst_endpoint": {"hostname": "auth.example.com"}
}`)

// Missing required attributes (metadata, user, ...) but structurally sound.
var incompleteEvent = json.RawMessage(`{"class_uid": 3002, "category_uid": 3, "activity_id": 1, "type_uid": 300201, "time": 1}`)

// No class_uid at all: unusable in every mode.
var structurallyBroken = json.RawMessage(`{"message": "no class"}`)

func TestOCSFValidatorStrict(t *testing.T) {
	ctx := context.Background()
	v := NewOCSFValidator(ModeStrict)

	if err := v.Validate(ctx, validEvent); err != nil {
		t.Errorf("valid event rejected: %v", err)
	}

	err := v.Validate(ctx, incompleteEvent)
	if err == nil {
		t.Fatal("strict mode should reject event missing required attributes")
	}
	var result *ValidationResult
	if !errors.As(err, &result) {
		t.Fatalf("error type = %T, want *ValidationResult", err)
	}
	if result.ClassUID != 3002 || len(result.Errors) == 0 {
		t.Errorf("result = %+v, want class 3002 with errors", result)
	}

	if err := v.Validate(ctx, structurallyBroken); err == nil {
		t.Error("strict mode should reject event without class_uid")
	}
}

func TestOCSFValidatorPermissive(t *testing.T) {
	ctx := context.Background()
	v := NewOCSFValidator(ModePermissive)

	if err := v.Validate(ctx, incompleteEvent); err != nil {
		t.Errorf("permissive mode should tolerate missing attributes: %v", err)
	}
	if err := v.Validate(ctx, structurallyBroken); err == nil {
		t.Error("permissive mode should still reject event without class_uid")
	}
	if err := v.Validate(ctx, json.RawMessage(`{"class_uid": 999999}`)); err == nil {
		t.Error("permissive mode should still reject unknown class_uid")
	}
	if err := v.Validate(ctx, json.RawMessage(`not json`)); err == nil {
		t.Error("permissive mode should still reject malformed JSON")
	}
}

func TestOCSFValidatorDisabled(t *testing.T) {
	ctx := context.Background()
	v := NewOCSFValidator(ModeDisabled)
	if err := v.Validate(ctx, structurallyBroken); err != nil {
		t.Errorf("disabled mode should accept anything: %v", err)
	}
}

func TestOCSFValidatorValidateClass(t *testing.T) {
	ctx := context.Background()
	v := NewOCSFValidator(ModeStrict)

	if err := v.ValidateClass(ctx, 3002, validEvent); err != nil {
		t.Errorf("ValidateClass(3002) rejected valid event: %v", err)
	}
	if err := v.ValidateClass(ctx, 999999, validEvent); !errors.Is(err, ErrSchemaNotFound) {
		t.Errorf("ValidateClass(999999) = %v, want ErrSchemaNotFound", err)
	}
}
