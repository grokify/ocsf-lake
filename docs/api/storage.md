# Storage API

The storage package provides the interface and implementations for OCSF event storage.

## Package

```go
import "github.com/grokify/ocsf-lake/pkg/storage"
```

## Storage Interface

```go
type Storage interface {
    Insert(ctx context.Context, events ...*ocsf.StoredEvent) error
    Get(ctx context.Context, id string) (*ocsf.StoredEvent, error)
    Query(ctx context.Context, q *Query) ([]*ocsf.StoredEvent, error)
    Count(ctx context.Context, q *Query) (int, error)
    Delete(ctx context.Context, q *Query) (int, error)
    Close() error
}
```

## Query Builder

The `QueryBuilder` provides a fluent interface for constructing queries.

### Creating a Query

```go
q := storage.NewQuery().
    WithClassUID(3002).
    WithSeverityID(4).
    WithTimeRange(from, to).
    WithLimit(100).
    OrderByTime(true).
    Build()
```

### Query Builder Methods

#### WithClassUID

```go
func (qb *QueryBuilder) WithClassUID(uid int) *QueryBuilder
```

Filters events by OCSF class UID.

#### WithCategoryUID

```go
func (qb *QueryBuilder) WithCategoryUID(uid int) *QueryBuilder
```

Filters events by OCSF category UID.

#### WithTypeUID

```go
func (qb *QueryBuilder) WithTypeUID(uid int) *QueryBuilder
```

Filters events by OCSF type UID.

#### WithActivityID

```go
func (qb *QueryBuilder) WithActivityID(id int) *QueryBuilder
```

Filters events by activity ID.

#### WithSeverityID

```go
func (qb *QueryBuilder) WithSeverityID(id int) *QueryBuilder
```

Filters events by severity level.

#### WithStatusID

```go
func (qb *QueryBuilder) WithStatusID(id int) *QueryBuilder
```

Filters events by status.

#### WithSource

```go
func (qb *QueryBuilder) WithSource(source string) *QueryBuilder
```

Filters events by source system.

#### WithTimeRange

```go
func (qb *QueryBuilder) WithTimeRange(from, to int64) *QueryBuilder
```

Filters events within a time range (epoch milliseconds).

#### WithTimeFrom

```go
func (qb *QueryBuilder) WithTimeFrom(from int64) *QueryBuilder
```

Filters events after a timestamp.

#### WithTimeTo

```go
func (qb *QueryBuilder) WithTimeTo(to int64) *QueryBuilder
```

Filters events before a timestamp.

#### WithLimit

```go
func (qb *QueryBuilder) WithLimit(limit int) *QueryBuilder
```

Sets the maximum number of results. Default: 100.

#### WithOffset

```go
func (qb *QueryBuilder) WithOffset(offset int) *QueryBuilder
```

Sets the result offset for pagination.

#### OrderByTime

```go
func (qb *QueryBuilder) OrderByTime(desc bool) *QueryBuilder
```

Orders results by event time.

#### OrderByIngestedAt

```go
func (qb *QueryBuilder) OrderByIngestedAt(desc bool) *QueryBuilder
```

Orders results by ingestion time.

#### Build

```go
func (qb *QueryBuilder) Build() *Query
```

Returns the constructed Query.

## Query Structure

```go
type Query struct {
    ClassUID    *int
    CategoryUID *int
    TypeUID     *int
    ActivityID  *int
    SeverityID  *int
    StatusID    *int
    Source      *string
    TimeFrom    *int64
    TimeTo      *int64
    Limit       int
    Offset      int
    OrderBy     string
    OrderDesc   bool
}
```

## Errors

```go
var (
    ErrNotFound         = errors.New("event not found")
    ErrDuplicateID      = errors.New("duplicate event ID")
    ErrConnectionFailed = errors.New("storage connection failed")
)
```

## EntStorage Implementation

The `EntStorage` type provides a storage implementation using Ent ORM.

### Creating Storage Directly

You can create storage instances directly if you need more control:

```go
// In-memory SQLite
store, err := storage.NewSQLiteMemoryStorage(ctx)

// File-based SQLite
store, err := storage.NewSQLiteFileStorage(ctx, "/path/to/db")

// PostgreSQL
store, err := storage.NewPostgresStorage(ctx, connStr)
```

### Accessing the Ent Client

For advanced operations:

```go
entStore := l.Storage().(*storage.EntStorage)
client := entStore.Client()

// Use Ent client directly for complex queries
events, err := client.Event.Query().
    Where(event.ClassUIDIn(3002, 3003)).
    Order(event.ByTime(entsql.OrderDesc())).
    All(ctx)
```
