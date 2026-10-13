# ocsf-lake

A Go library for storing, validating, and querying [OCSF](https://ocsf.io/) (Open Cybersecurity Schema Framework) events with pluggable storage backends.

## Features

- **OCSF Event Storage** - Store OCSF events with automatic extraction of key fields for indexing
- **Pluggable Backends** - SQLite (in-memory or file) and PostgreSQL support via Ent ORM
- **Real Schema Validation** - events checked against the compiled OCSF schema (required attributes, types, enums, constraints, UID consistency) embedded in [ocsf-schema-go](https://github.com/grokify/ocsf-schema-go)
- **Record Integrity** - verify signed events (`record_integrity` profile): on-demand, full, incremental, sampled, and chain checks; verify or attest at ingest; persisted check reports
- **Type-Safe** - generated OCSF structs and constants from ocsf-schema-go, with typed ingest and class-UID decode
- **Flexible Querying** - Query by class, category, severity, source, time range, and more
- **CLI** - [`ocsflake`](cli.md): ingest, query, check, seed, sign, verify
- **Test Data** - deterministic, schema-valid seeding with signed/tampered/chained mixes

## Quick Example

```go
package main

import (
    "context"
    "encoding/json"
    "fmt"
    "log"

    "github.com/grokify/ocsf-lake/pkg/lake"
    "github.com/grokify/ocsf-schema-go/ocsf/events"

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
        "message": "User logged in successfully",
        "metadata": {"version": "1.10.0", "product": {"name": "my-idp"}},
        "user": {"name": "john.doe"},
        "dst_endpoint": {"hostname": "auth.example.com"}
    }`)

    if err := l.Ingest(ctx, event); err != nil {
        log.Fatal(err)
    }

    // Query authentication events
    stored, err := l.QueryByClassUID(ctx, events.ClassUIDAuthentication)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Found %d authentication events\n", len(stored))
}
```

## Installation

```bash
go get github.com/grokify/ocsf-lake
```

For SQLite support (requires CGO):

```bash
go get github.com/mattn/go-sqlite3
```

## What is OCSF?

The [Open Cybersecurity Schema Framework (OCSF)](https://ocsf.io/) is an open-source project that provides an extensible framework for developing schemas and a vendor-agnostic core security schema. OCSF enables security teams to normalize and analyze security data across different tools and vendors.

Key OCSF concepts:

- **Categories** - High-level groupings (System Activity, IAM, Network Activity, etc.)
- **Classes** - Specific event types within categories (Authentication, DNS Activity, etc.)
- **Activity IDs** - Actions performed (Login, Logout, Create, Delete, etc.)
- **Type UIDs** - Unique identifier combining class and activity

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         Lake                                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │  Validator  │  │   Storage   │  │     Query Builder   │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                            │
         ┌──────────────────┼──────────────────┐
         │                  │                  │
    ┌────▼────┐       ┌────▼────┐       ┌────▼────┐
    │ SQLite  │       │ SQLite  │       │Postgres │
    │ Memory  │       │  File   │       │         │
    └─────────┘       └─────────┘       └─────────┘
```

## License

MIT License - see [LICENSE](https://github.com/grokify/ocsf-lake/blob/main/LICENSE) for details.
