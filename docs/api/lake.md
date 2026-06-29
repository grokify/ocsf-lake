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

Rejects events missing required OCSF fields. This is the default mode.

### WithPermissiveValidation

```go
func WithPermissiveValidation() Option
```

Accepts events with warnings for non-critical issues.

### WithNoValidation

```go
func WithNoValidation() Option
```

Skips validation entirely.

### WithSchemaVersion

```go
func WithSchemaVersion(version string) Option
```

Sets the OCSF schema version. Default: `"1.3.0"`.

### WithDefaultSource

```go
func WithDefaultSource(source string) Option
```

Sets the default source for events that don't specify one.

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

## Errors

```go
var (
    ErrInvalidBackend = errors.New("invalid storage backend configuration")
    ErrClosed         = errors.New("lake is closed")
)
```
