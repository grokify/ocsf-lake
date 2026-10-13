# Lake API

The `Lake` type is the main facade for storing and querying OCSF events.

## Package

```go
import "github.com/grokify/ocsf-lake/pkg/lake"
```

## Creating a Lake

### New

```go
func New(ctx context.Context, opts ...Option) (*Lake, error)
```

Creates a new Lake with the given options.

**Example:**

```go
l, err := lake.New(ctx,
    lake.WithSQLiteMemory(),
    lake.WithStrictValidation(),
)
if err != nil {
    log.Fatal(err)
}
defer l.Close()
```

## Configuration Options

### WithSQLiteMemory

```go
func WithSQLiteMemory() Option
```

Configures the Lake to use in-memory SQLite. Data is lost when the process exits.

### WithSQLiteFile

```go
func WithSQLiteFile(path string) Option
```

Configures the Lake to use file-based SQLite.

### WithPostgres

```go
func WithPostgres(connStr string) Option
```

Configures the Lake to use PostgreSQL.

**Connection string format:**

```
postgres://user:password@host:port/database?sslmode=disable
```

### WithStrictValidation

```go
func WithStrictValidation() Option
```

Rejects events with any schema violation (missing required attributes, wrong
types, invalid enums, violated constraints, inconsistent UIDs). This is the
default mode.

### WithPermissiveValidation

```go
func WithPermissiveValidation() Option
```

Rejects only structurally unusable events (malformed JSON, missing or unknown
`class_uid`); other schema violations are tolerated.

### WithNoValidation

```go
func WithNoValidation() Option
```

Skips validation entirely.

### WithSchemaVersion

```go
func WithSchemaVersion(version string) Option
```

Sets the OCSF schema version recorded on stored events. Defaults to
`events.SchemaVersion` from ocsf-schema-go (the version the bindings were
generated from).

### WithDefaultSource

```go
func WithDefaultSource(source string) Option
```

Sets the default source for events that don't specify one.

### WithUnknownAttributes

```go
func WithUnknownAttributes(m validate.UnknownMode) Option
```

Controls how attributes absent from the OCSF schema are treated during validation:
`validate.UnknownWarn` (default), `validate.UnknownIgnore`, or
`validate.UnknownError` (strict mode then rejects them).

### WithRawDataRetention

```go
func WithRawDataRetention() Option
```

Stores each event's original JSON bytes as received (before any lake attestation)
in `StoredEvent.RawData`, preserving forensic evidence at the cost of roughly
doubling per-event storage.

### WithIngestIntegrity

```go
func WithIngestIntegrity(mode IngestIntegrityMode, policy integrity.Policy) Option
```

Verifies producer `record_integrity` attestations during ingestion.
`IngestIntegrityMonitor` stamps `integrity_status` on stored events without
rejecting; `IngestIntegrityEnforce` rejects failing events with
`*IntegrityRejectionError`. See [Integrity](integrity.md).

### WithIngestAttestation

```go
func WithIngestAttestation(a AttestationOptions) Option
```

Makes the lake sign every ingested event with its own attestation, optionally
chaining events tamper-evidently (`ChainUID`). The chain tail is process-local;
persist `Lake.ChainTail()` and pass it back as `InitialChainTail` to continue a
chain across restarts.

## Methods

### Ingest

```go
func (l *Lake) Ingest(ctx context.Context, events ...json.RawMessage) error
```

Validates and stores one or more OCSF events.

**Example:**

```go
event := json.RawMessage(`{
    "class_uid": 3002,
    "category_uid": 3,
    "activity_id": 1,
    "type_uid": 300201,
    "time": 1704067200000
}`)

err := l.Ingest(ctx, event)
```

### IngestWithID

```go
func (l *Lake) IngestWithID(ctx context.Context, id string, event json.RawMessage) error
```

Ingests an event with a specific ID (instead of auto-generating one).

### IngestTyped

```go
func (l *Lake) IngestTyped(ctx context.Context, events ...any) error
```

Ingests typed events, such as the generated structs from
`github.com/grokify/ocsf-schema-go/ocsf/events` (e.g. `events.Authentication`),
through the same validation and indexing pipeline as `Ingest`.

### Get

```go
func (l *Lake) Get(ctx context.Context, id string) (*ocsf.StoredEvent, error)
```

Retrieves a single event by ID.

### Query

```go
func (l *Lake) Query(ctx context.Context, q *storage.Query) ([]*ocsf.StoredEvent, error)
```

Retrieves events matching the query parameters.

### QueryBuilder

```go
func (l *Lake) QueryBuilder() *storage.QueryBuilder
```

Returns a new query builder for constructing queries.

### Count

```go
func (l *Lake) Count(ctx context.Context, q *storage.Query) (int, error)
```

Returns the number of events matching the query.

### Delete

```go
func (l *Lake) Delete(ctx context.Context, q *storage.Query) (int, error)
```

Removes events matching the query. Returns the number of deleted events.

### Close

```go
func (l *Lake) Close() error
```

Closes the Lake and releases resources.

## Convenience Methods

### QueryByClassUID

```go
func (l *Lake) QueryByClassUID(ctx context.Context, classUID int) ([]*ocsf.StoredEvent, error)
```

### QueryByCategoryUID

```go
func (l *Lake) QueryByCategoryUID(ctx context.Context, categoryUID int) ([]*ocsf.StoredEvent, error)
```

### QueryBySeverityID

```go
func (l *Lake) QueryBySeverityID(ctx context.Context, severityID int) ([]*ocsf.StoredEvent, error)
```

### QueryBySource

```go
func (l *Lake) QueryBySource(ctx context.Context, source string) ([]*ocsf.StoredEvent, error)
```

### QueryByTimeRange

```go
func (l *Lake) QueryByTimeRange(ctx context.Context, from, to int64) ([]*ocsf.StoredEvent, error)
```

## Integrity Methods

### IntegrityChecker

```go
func (l *Lake) IntegrityChecker(policy integrity.Policy) *integrity.Checker
```

Returns a record-integrity checker over this lake's storage. See
[Integrity](integrity.md) for check modes.

### IntegrityReports

```go
func (l *Lake) IntegrityReports(ctx context.Context, kind string, limit int) ([]*ocsf.IntegrityCheckRecord, error)
```

Returns persisted check runs, newest first, optionally filtered by kind
(`event`, `all`, `incremental`, `sample`, `chain`).

### ChainTail

```go
func (l *Lake) ChainTail() []byte
```

The last attested event JSON when attest-on-ingest chaining is enabled; persist it
to continue the chain across restarts.

## Errors

```go
var (
    ErrInvalidBackend = errors.New("invalid storage backend configuration")
    ErrClosed         = errors.New("lake is closed")
)
```

`IntegrityRejectionError` is returned by ingestion when `IngestIntegrityEnforce`
rejects an event; it carries the failing `integrity.EventResult`.
