# ocsf-lake

A Go library for storing, validating, and querying [OCSF](https://ocsf.io/) (Open Cybersecurity Schema Framework) events with pluggable storage backends.

[![GoDoc](https://godoc.org/github.com/grokify/ocsf-lake?status.svg)](https://godoc.org/github.com/grokify/ocsf-lake)
[![Go Report Card](https://goreportcard.com/badge/github.com/grokify/ocsf-lake)](https://goreportcard.com/report/github.com/grokify/ocsf-lake)
[![Docs](https://img.shields.io/badge/docs-MkDocs-blue)](https://grokify.github.io/ocsf-lake/)

## Features

- **OCSF Event Storage**: Store OCSF events with automatic extraction of key fields for indexing
- **Pluggable Backends**: SQLite (in-memory or file) and PostgreSQL support via Ent ORM
- **Event Validation**: Validate events against OCSF schema (strict or permissive modes)
- **Flexible Querying**: Query by class, category, severity, source, time range, and more
- **Type-Safe**: Go types for OCSF classifications, severities, and statuses

## Installation

```bash
go get github.com/grokify/ocsf-lake
```

For SQLite support, you need CGO enabled and the SQLite driver:

```bash
go get github.com/mattn/go-sqlite3
```

## Quick Start

```go
package main

import (
    "context"
    "encoding/json"
    "fmt"
    "log"

    "github.com/grokify/ocsf-lake/pkg/lake"
    "github.com/grokify/ocsf-lake/pkg/ocsf"

    _ "github.com/mattn/go-sqlite3"
)

func main() {
    ctx := context.Background()

    // Create a lake with in-memory SQLite
    l, err := lake.New(ctx, lake.WithSQLiteMemory())
    if err != nil {
        log.Fatal(err)
    }
    defer l.Close()

    // Ingest an OCSF Authentication event
    event := json.RawMessage(`{
        "class_uid": 3002,
        "category_uid": 3,
        "activity_id": 1,
        "type_uid": 300201,
        "time": 1704067200000,
        "severity_id": 1,
        "message": "User logged in successfully"
    }`)

    if err := l.Ingest(ctx, event); err != nil {
        log.Fatal(err)
    }

    // Query authentication events
    events, err := l.QueryByClassUID(ctx, ocsf.ClassUIDAuthentication)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Found %d authentication events\n", len(events))
}
```

## Storage Backends

### SQLite In-Memory

```go
l, err := lake.New(ctx, lake.WithSQLiteMemory())
```

### SQLite File

```go
l, err := lake.New(ctx, lake.WithSQLiteFile("/path/to/events.db"))
```

### PostgreSQL

```go
l, err := lake.New(ctx, lake.WithPostgres("postgres://user:pass@host/db?sslmode=disable"))
```

## Validation Modes

### Strict (default)

Rejects events missing required OCSF fields:

```go
l, err := lake.New(ctx, lake.WithStrictValidation())
```

### Permissive

Accepts events with warnings for non-critical issues:

```go
l, err := lake.New(ctx, lake.WithPermissiveValidation())
```

### Disabled

Skips validation entirely:

```go
l, err := lake.New(ctx, lake.WithNoValidation())
```

## Querying Events

### Using Query Builder

```go
// Query high-severity IAM events from the last hour
from := time.Now().Add(-1 * time.Hour).UnixMilli()
to := time.Now().UnixMilli()

q := l.QueryBuilder().
    WithCategoryUID(ocsf.CategoryUIDIAMActivity).
    WithSeverityID(ocsf.SeverityIDHigh).
    WithTimeRange(from, to).
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
events, _ := l.QueryByTimeRange(ctx, fromMs, toMs)
```

## OCSF Classification Constants

The package provides constants for OCSF categories, classes, severities, and statuses:

```go
// Categories
ocsf.CategoryUIDSystemActivity     // 1
ocsf.CategoryUIDFindingsActivity   // 2
ocsf.CategoryUIDIAMActivity        // 3
ocsf.CategoryUIDNetworkActivity    // 4

// Classes
ocsf.ClassUIDAuthentication        // 3002
ocsf.ClassUIDNetworkActivity       // 4001
ocsf.ClassUIDSecurityFinding       // 2001

// Severities
ocsf.SeverityIDInformational       // 1
ocsf.SeverityIDLow                 // 2
ocsf.SeverityIDMedium              // 3
ocsf.SeverityIDHigh                // 4
ocsf.SeverityIDCritical            // 5
```

## Documentation

Full documentation is available at [grokify.github.io/ocsf-lake](https://grokify.github.io/ocsf-lake/).

- [Getting Started](https://grokify.github.io/ocsf-lake/getting-started/)
- [API Reference](https://grokify.github.io/ocsf-lake/api/lake/)
- [Examples](https://grokify.github.io/ocsf-lake/examples/)

## Architecture

```
ocsf-lake/
├── docs/                 # MkDocs documentation
├── ent/                  # Ent ORM schema and generated code
│   └── schema/
│       └── event.go      # Event entity schema
├── pkg/
│   ├── lake/             # Main facade
│   │   ├── lake.go       # Lake type and methods
│   │   └── options.go    # Configuration options
│   ├── ocsf/             # OCSF types and constants
│   │   ├── event.go      # Base event types
│   │   ├── classification.go  # UIDs and constants
│   │   └── metadata.go   # Metadata types
│   ├── storage/          # Storage interface and implementations
│   │   ├── storage.go    # Storage interface
│   │   └── ent_storage.go # Ent-based implementation
│   └── validator/        # Event validation
│       ├── validator.go  # Validator interface
│       └── schema_validator.go # Implementation
└── schema/               # OCSF JSON Schema files (future)
```

## License

MIT License - see [LICENSE](LICENSE) for details.
