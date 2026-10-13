# Examples

Real-world usage examples for ocsf-lake.

## Basic Usage

### Ingesting Events from AWS CloudTrail

```go
package main

import (
    "context"
    "encoding/json"
    "log"

    "github.com/grokify/ocsf-lake/pkg/lake"
    "github.com/grokify/ocsf-schema-go/ocsf/events"

    _ "github.com/mattn/go-sqlite3"
)

func main() {
    ctx := context.Background()

    l, err := lake.New(ctx,
        lake.WithSQLiteFile("cloudtrail-events.db"),
        lake.WithDefaultSource("aws-cloudtrail"),
    )
    if err != nil {
        log.Fatal(err)
    }
    defer l.Close()

    // CloudTrail event converted to OCSF Authentication format
    event := json.RawMessage(`{
        "class_uid": 3002,
        "class_name": "Authentication",
        "category_uid": 3,
        "activity_id": 1,
        "type_uid": 300201,
        "time": 1704067200000,
        "severity_id": 1,
        "status_id": 1,
        "message": "ConsoleLogin succeeded for user admin@example.com",
        "metadata": {
            "version": "1.3.0",
            "product": {
                "name": "AWS CloudTrail",
                "vendor_name": "Amazon Web Services"
            }
        },
        "user": {"name": "admin@example.com"},
        "dst_endpoint": {"svc_name": "signin.amazonaws.com"},
        "unmapped": {
            "eventSource": "signin.amazonaws.com",
            "eventName": "ConsoleLogin",
            "awsRegion": "us-east-1"
        }
    }`)

    if err := l.Ingest(ctx, event); err != nil {
        log.Fatal(err)
    }

    log.Println("Event ingested successfully")
}
```

## Querying Events

### Finding Failed Authentication Attempts

```go
package main

import (
    "context"
    "fmt"
    "log"
    "time"

    "github.com/grokify/ocsf-lake/pkg/lake"
    "github.com/grokify/ocsf-schema-go/ocsf/events"

    _ "github.com/mattn/go-sqlite3"
)

func main() {
    ctx := context.Background()

    l, err := lake.New(ctx, lake.WithSQLiteFile("events.db"))
    if err != nil {
        log.Fatal(err)
    }
    defer l.Close()

    // Query failed authentication events in the last hour
    from := time.Now().Add(-1 * time.Hour).UnixMilli()
    to := time.Now().UnixMilli()

    q := l.QueryBuilder().
        WithClassUID(events.ClassUIDAuthentication).
        WithStatusID(events.StatusIDFailure).
        WithTimeRange(from, to).
        OrderByTime(true).
        WithLimit(100).
        Build()

    events, err := l.Query(ctx, q)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Found %d failed auth events in the last hour\n", len(events))

    for _, e := range events {
        msg := e.Payload["message"]
        fmt.Printf("  - [%s] %v\n",
            time.UnixMilli(e.Time).Format(time.RFC3339),
            msg,
        )
    }
}
```

### Security Event Dashboard

```go
package main

import (
    "context"
    "fmt"
    "log"
    "time"

    "github.com/grokify/ocsf-lake/pkg/lake"
    "github.com/grokify/ocsf-schema-go/ocsf/events"
    "github.com/grokify/ocsf-lake/pkg/storage"

    _ "github.com/mattn/go-sqlite3"
)

func main() {
    ctx := context.Background()

    l, err := lake.New(ctx, lake.WithSQLiteFile("events.db"))
    if err != nil {
        log.Fatal(err)
    }
    defer l.Close()

    // Last 24 hours
    from := time.Now().Add(-24 * time.Hour).UnixMilli()
    to := time.Now().UnixMilli()

    // Count by severity
    fmt.Println("Events by Severity (Last 24h)")
    fmt.Println("=============================")

    severities := []struct {
        id   int
        name string
    }{
        {events.SeverityIDCritical, "Critical"},
        {events.SeverityIDHigh, "High"},
        {events.SeverityIDMedium, "Medium"},
        {events.SeverityIDLow, "Low"},
        {events.SeverityIDInformational, "Informational"},
    }

    for _, sev := range severities {
        count, _ := l.Count(ctx, &storage.Query{
            SeverityID: &sev.id,
            TimeFrom:   &from,
            TimeTo:     &to,
        })
        fmt.Printf("  %-15s %d\n", sev.name+":", count)
    }

    // Count by category
    fmt.Println("\nEvents by Category (Last 24h)")
    fmt.Println("==============================")

    categories := []struct {
        id   int
        name string
    }{
        {events.CategoryUIDSystem, "System Activity"},
        {events.CategoryUIDFindings, "Findings"},
        {events.CategoryUIDIAM, "IAM"},
        {events.CategoryUIDNetwork, "Network"},
    }

    for _, cat := range categories {
        count, _ := l.Count(ctx, &storage.Query{
            CategoryUID: &cat.id,
            TimeFrom:    &from,
            TimeTo:      &to,
        })
        fmt.Printf("  %-20s %d\n", cat.name+":", count)
    }
}
```

## Event Processing

### Batch Ingestion

```go
package main

import (
    "context"
    "encoding/json"
    "log"
    "time"

    "github.com/grokify/ocsf-lake/pkg/lake"
    "github.com/grokify/ocsf-lake/pkg/ocsf"
    "github.com/grokify/ocsf-schema-go/ocsf/events"

    _ "github.com/mattn/go-sqlite3"
)

func main() {
    ctx := context.Background()

    l, err := lake.New(ctx, lake.WithSQLiteMemory())
    if err != nil {
        log.Fatal(err)
    }
    defer l.Close()

    // Create batch of events
    var batch []json.RawMessage
    baseTime := time.Now().UnixMilli()

    for i := 0; i < 1000; i++ {
        event := map[string]any{
            "class_uid":    events.ClassUIDNetworkActivity,
            "category_uid": events.CategoryUIDNetwork,
            "activity_id":  1,
            "type_uid":     ocsf.CalculateTypeUID(events.ClassUIDNetworkActivity, 1),
            "time":         baseTime + int64(i*1000),
            "severity_id":  events.SeverityIDInformational,
        }

        data, _ := json.Marshal(event)
        batch = append(batch, data)
    }

    // Ingest batch
    start := time.Now()
    if err := l.Ingest(ctx, batch...); err != nil {
        log.Fatal(err)
    }

    log.Printf("Ingested %d events in %v", len(batch), time.Since(start))
}
```

### Event Retention Policy

```go
package main

import (
    "context"
    "log"
    "time"

    "github.com/grokify/ocsf-lake/pkg/lake"

    _ "github.com/mattn/go-sqlite3"
)

func main() {
    ctx := context.Background()

    l, err := lake.New(ctx, lake.WithSQLiteFile("events.db"))
    if err != nil {
        log.Fatal(err)
    }
    defer l.Close()

    // Delete events older than 90 days
    cutoff := time.Now().Add(-90 * 24 * time.Hour).UnixMilli()

    deleted, err := l.Delete(ctx, l.QueryBuilder().
        WithTimeTo(cutoff).
        Build())

    if err != nil {
        log.Fatal(err)
    }

    log.Printf("Cleaned up %d events older than 90 days", deleted)
}
```

## PostgreSQL Production Setup

```go
package main

import (
    "context"
    "log"
    "os"

    "github.com/grokify/ocsf-lake/pkg/lake"

    _ "github.com/lib/pq"
)

func main() {
    ctx := context.Background()

    connStr := os.Getenv("DATABASE_URL")
    if connStr == "" {
        connStr = "postgres://user:pass@localhost:5432/ocsf?sslmode=disable"
    }

    l, err := lake.New(ctx,
        lake.WithPostgres(connStr),
        lake.WithStrictValidation(),
        lake.WithSchemaVersion("1.3.0"),
    )
    if err != nil {
        log.Fatal(err)
    }
    defer l.Close()

    log.Println("Connected to PostgreSQL successfully")
}
```

## Advanced Queries Using Ent

For complex queries, access the underlying Ent client:

```go
package main

import (
    "context"
    "log"

    "entgo.io/ent/dialect/sql"
    "github.com/grokify/ocsf-lake/ent/event"
    "github.com/grokify/ocsf-lake/pkg/lake"
    "github.com/grokify/ocsf-schema-go/ocsf/events"
    "github.com/grokify/ocsf-lake/pkg/storage"

    _ "github.com/mattn/go-sqlite3"
)

func main() {
    ctx := context.Background()

    l, err := lake.New(ctx, lake.WithSQLiteMemory())
    if err != nil {
        log.Fatal(err)
    }
    defer l.Close()

    // Access Ent client for advanced queries
    entStore := l.Storage().(*storage.EntStorage)
    client := entStore.Client()

    // Complex query: Authentication or Network events, high severity
    events, err := client.Event.Query().
        Where(
            event.Or(
                event.ClassUID(events.ClassUIDAuthentication),
                event.ClassUID(events.ClassUIDNetworkActivity),
            ),
            event.SeverityIDGTE(events.SeverityIDHigh),
        ).
        Order(event.ByTime(sql.OrderDesc())).
        Limit(50).
        All(ctx)

    if err != nil {
        log.Fatal(err)
    }

    log.Printf("Found %d high-severity auth/network events", len(events))
}
```
