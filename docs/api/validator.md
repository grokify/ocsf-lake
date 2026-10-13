# Validator

The `validator` package validates OCSF events against the compiled OCSF schema embedded
in [ocsf-schema-go](https://github.com/grokify/ocsf-schema-go) — no schema files are
needed at runtime.

## Package

```go
import "github.com/grokify/ocsf-lake/pkg/validator"
```

## Validator Interface

```go
type Validator interface {
    // Validate checks an OCSF event against the schema.
    Validate(ctx context.Context, event json.RawMessage) error

    // ValidateClass validates an event against a specific event class schema.
    ValidateClass(ctx context.Context, classUID int, event json.RawMessage) error
}
```

## Modes

```go
const (
    ModeStrict     Mode = iota // reject any schema violation
    ModePermissive             // reject only structurally unusable events
    ModeDisabled               // skip validation entirely
)
```

- **ModeStrict** rejects events with any schema violation: missing required attributes
  (profile-aware), wrong attribute types, invalid enum values, violated
  `at_least_one`/`just_one` constraints, and inconsistent
  `class_uid`/`category_uid`/`type_uid` values.
- **ModePermissive** rejects only events the lake cannot index: malformed JSON, missing
  `class_uid`, or an unknown event class.
- **ModeDisabled** accepts everything.

## OCSFValidator

Schema-backed validator built on `validate.New(ocsfdata.MustSchema())` from
ocsf-schema-go.

### NewOCSFValidator

```go
func NewOCSFValidator(mode Mode) *OCSFValidator
```

Example:

```go
v := validator.NewOCSFValidator(validator.ModeStrict)
if err := v.Validate(ctx, eventJSON); err != nil {
    var result *validator.ValidationResult
    if errors.As(err, &result) {
        for _, e := range result.Errors {
            log.Println(e.Message)
        }
    }
}
```

### Result

```go
func (v *OCSFValidator) Result(event json.RawMessage) *validate.Result
```

Returns the full validation result (including warnings such as unknown or deprecated
attributes), independent of mode. Useful for surfacing diagnostics without failing
ingestion.

## ValidationResult

Returned (as an `error`) when validation fails:

```go
type ValidationResult struct {
    Valid    bool
    Errors   []ValidationError
    ClassUID int
}

type ValidationError struct {
    Field   string
    Message string
    Path    string
}
```
