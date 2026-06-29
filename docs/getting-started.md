# Getting Started

This guide walks you through setting up ocsf-lake and performing basic operations.

## Installation

```bash
go get github.com/grokify/ocsf-lake
```

### SQLite Driver (CGO required)

For SQLite support, you need CGO enabled:

```bash
go get github.com/mattn/go-sqlite3
```

### PostgreSQL Driver

For PostgreSQL support:

```bash
go get github.com/lib/pq
```

## Creating a Lake

The `Lake` type is the main entry point for all operations.

### In-Memory SQLite

Best for testing and development:

```go
import (
    "context"
    "github.com/grokify/ocsf-lake/pkg/lake"
    _ "github.com/mattn/go-sqlite3"
)

ctx := context.Background()
l, err := lake.New(ctx, lake.WithSQLiteMemory())
if err != nil {
    log.Fatal(err)
}
defer l.Close()
```

### File-Based SQLite

Best for persistent single-node storage:

```go
l, err := lake.New(ctx, lake.WithSQLiteFile("/path/to/events.db"))
```

### PostgreSQL

Best for production deployments:

```go
connStr := "postgres://user:pass@localhost/ocsf?sslmode=disable"
l, err := lake.New(ctx, lake.WithPostgres(connStr))
```

## Ingesting Events

Events are JSON documents following the OCSF schema:

```go
import "encoding/json"

// OCSF Authentication event
event := json.RawMessage(`{
    "class_uid": 3002,
    "category_uid": 3,
    "activity_id": 1,
    "type_uid": 300201,
    "time": 1704067200000,
    "severity_id": 1,
    "status_id": 1,
    "message": "User john.doe logged in successfully",
    "metadata": {
        "version": "1.3.0",
        "product": {
            "name": "auth-service",
            "vendor_name": "My Company"
        }
    }
}`)

err := l.Ingest(ctx, event)
if err != nil {
    log.Printf("Ingest failed: %v", err)
}
```

### Required Fields

Every OCSF event must include:

| Field | Type | Description |
|-------|------|-------------|
| `class_uid` | int | Event class identifier |
| `category_uid` | int | Event category identifier |
| `activity_id` | int | Activity type identifier |
| `type_uid` | int | Unique type ID (class_uid * 100 + activity_id) |
| `time` | int64 | Event timestamp (epoch milliseconds) |

### Batch Ingestion

Ingest multiple events at once:

```go
events := []json.RawMessage{event1, event2, event3}
err := l.Ingest(ctx, events...)
```

## Querying Events

### Using Query Builder

```go
import "github.com/grokify/ocsf-lake/pkg/ocsf"

// Query high-severity authentication events
q := l.QueryBuilder().
    WithClassUID(ocsf.ClassUIDAuthentication).
    WithSeverityID(ocsf.SeverityIDHigh).
    WithLimit(100).
    OrderByTime(true). // descending
    Build()

events, err := l.Query(ctx, q)
```

### Convenience Methods

```go
// Query by class
events, _ := l.QueryByClassUID(ctx, ocsf.ClassUIDAuthentication)

// Query by category
events, _ := l.QueryByCategoryUID(ctx, ocsf.CategoryUIDNetworkActivity)

// Query by severity
events, _ := l.QueryBySeverityID(ctx, ocsf.SeverityIDCritical)

// Query by source
events, _ := l.QueryBySource(ctx, "aws-cloudtrail")

// Query by time range
from := time.Now().Add(-24 * time.Hour).UnixMilli()
to := time.Now().UnixMilli()
events, _ := l.QueryByTimeRange(ctx, from, to)
```

### Time Range Queries

```go
from := time.Now().Add(-1 * time.Hour).UnixMilli()
to := time.Now().UnixMilli()

q := l.QueryBuilder().
    WithTimeRange(from, to).
    Build()

events, err := l.Query(ctx, q)
```

## Counting Events

```go
count, err := l.Count(ctx, l.QueryBuilder().
    WithCategoryUID(ocsf.CategoryUIDIAMActivity).
    Build())

fmt.Printf("Total IAM events: %d\n", count)
```

## Deleting Events

```go
// Delete all events older than 30 days
cutoff := time.Now().Add(-30 * 24 * time.Hour).UnixMilli()

deleted, err := l.Delete(ctx, l.QueryBuilder().
    WithTimeTo(cutoff).
    Build())

fmt.Printf("Deleted %d old events\n", deleted)
```

## Validation Modes

### Strict Mode (Default)

Rejects events missing required OCSF fields:

```go
l, err := lake.New(ctx,
    lake.WithSQLiteMemory(),
    lake.WithStrictValidation(),
)
```

### Permissive Mode

Accepts events with warnings:

```go
l, err := lake.New(ctx,
    lake.WithSQLiteMemory(),
    lake.WithPermissiveValidation(),
)
```

### Disabled

Skips validation entirely:

```go
l, err := lake.New(ctx,
    lake.WithSQLiteMemory(),
    lake.WithNoValidation(),
)
```

## Configuration Options

All options can be combined:

```go
l, err := lake.New(ctx,
    lake.WithSQLiteFile("/data/ocsf.db"),
    lake.WithStrictValidation(),
    lake.WithSchemaVersion("1.3.0"),
    lake.WithDefaultSource("my-app"),
)
```

## Next Steps

- [API Reference](api/lake.md) - Detailed API documentation
- [Examples](examples.md) - Real-world usage examples
- [OCSF Types](api/ocsf.md) - Available constants and types
