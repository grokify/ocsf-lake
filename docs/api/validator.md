# Validator API

The validator package provides OCSF event validation against JSON Schema.

## Package

```go
import "github.com/grokify/ocsf-lake/pkg/validator"
```

## Validator Interface

```go
type Validator interface {
    Validate(ctx context.Context, event json.RawMessage) error
    ValidateClass(ctx context.Context, classUID int, event json.RawMessage) error
}
```

## Validation Modes

```go
type Mode int

const (
    ModeStrict     Mode = iota  // Reject invalid events
    ModePermissive              // Accept with warnings
    ModeDisabled                // Skip validation
)
```

### ModeStrict

Rejects any event that doesn't meet OCSF requirements:

- Missing required fields
- Invalid field types
- Schema violations

### ModePermissive

Accepts events but logs warnings for non-critical issues. Use this when ingesting events from sources that may not be fully OCSF-compliant.

### ModeDisabled

Skips validation entirely. Use with caution - invalid events may cause query issues.

## BasicValidator

Performs minimal validation without JSON Schema. Checks only that required fields are present.

### NewBasicValidator

```go
func NewBasicValidator(mode Mode) *BasicValidator
```

Creates a validator that only checks required fields.

**Example:**

```go
v := validator.NewBasicValidator(validator.ModeStrict)

event := json.RawMessage(`{"class_uid": 3002, ...}`)
err := v.Validate(ctx, event)
```

## SchemaValidator

Validates events against full OCSF JSON Schema.

### NewSchemaValidator

```go
func NewSchemaValidator(opts Options) *SchemaValidator
```

Creates a schema-based validator.

### RegisterSchema

```go
func (v *SchemaValidator) RegisterSchema(classUID int, schemaJSON []byte) error
```

Registers a JSON Schema for a specific class UID.

**Example:**

```go
opts := validator.Options{
    Mode:          validator.ModeStrict,
    SchemaVersion: "1.3.0",
}
v := validator.NewSchemaValidator(opts)

// Register authentication schema
authSchema, _ := os.ReadFile("schemas/authentication.json")
v.RegisterSchema(ocsf.ClassUIDAuthentication, authSchema)

// Validate against registered schema
err := v.ValidateClass(ctx, ocsf.ClassUIDAuthentication, event)
```

## Validation Errors

### Common Errors

```go
var (
    ErrMissingClassUID    = errors.New("missing required field: class_uid")
    ErrMissingCategoryUID = errors.New("missing required field: category_uid")
    ErrMissingActivityID  = errors.New("missing required field: activity_id")
    ErrMissingTypeUID     = errors.New("missing required field: type_uid")
    ErrMissingTime        = errors.New("missing required field: time")
    ErrInvalidJSON        = errors.New("invalid JSON")
    ErrSchemaNotFound     = errors.New("schema not found for class_uid")
)
```

### ValidationResult

Detailed validation results:

```go
type ValidationResult struct {
    Valid    bool              `json:"valid"`
    Errors   []ValidationError `json:"errors,omitempty"`
    ClassUID int               `json:"class_uid,omitempty"`
}

type ValidationError struct {
    Field   string `json:"field"`
    Message string `json:"message"`
    Path    string `json:"path,omitempty"`
}
```

## Options

```go
type Options struct {
    Mode          Mode
    SchemaVersion string
}
```

### DefaultOptions

```go
func DefaultOptions() Options
```

Returns the default validator options:

- Mode: `ModeStrict`
- SchemaVersion: `"1.3.0"`

## Required Fields

Every OCSF event must include these fields:

| Field | Type | Description |
|-------|------|-------------|
| `class_uid` | int | Event class identifier |
| `category_uid` | int | Event category identifier |
| `activity_id` | int | Activity type identifier |
| `type_uid` | int | Unique type ID |
| `time` | int64 | Event timestamp (epoch ms) |

## Validation Flow

```
┌─────────────────┐
│   Raw JSON      │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Parse JSON      │──▶ ErrInvalidJSON
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Check Required  │──▶ ErrMissing*
│ Fields          │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Type Validation │──▶ Type errors
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Schema Valid.   │──▶ Schema errors
│ (if registered) │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│    Valid ✓      │
└─────────────────┘
```
