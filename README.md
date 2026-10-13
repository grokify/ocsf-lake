# ocsf-lake

A Go library for storing, validating, and querying [OCSF](https://ocsf.io/) (Open Cybersecurity Schema Framework) events with pluggable storage backends.

[![GoDoc](https://godoc.org/github.com/grokify/ocsf-lake?status.svg)](https://godoc.org/github.com/grokify/ocsf-lake)
[![Go Report Card](https://goreportcard.com/badge/github.com/grokify/ocsf-lake)](https://goreportcard.com/report/github.com/grokify/ocsf-lake)
[![Docs](https://img.shields.io/badge/docs-MkDocs-blue)](https://grokify.github.io/ocsf-lake/)

## Features

- **OCSF Event Storage**: Store OCSF events with automatic extraction of key fields for indexing
- **Pluggable Backends**: SQLite (in-memory or file) and PostgreSQL support via Ent ORM
- **Real Schema Validation**: Events are validated against the compiled OCSF schema
  (required attributes, types, enums, constraints, UID consistency) embedded in
  [ocsf-schema-go](https://github.com/grokify/ocsf-schema-go) — no schema files needed at runtime
- **Typed Events**: Ingest the generated structs from ocsf-schema-go (`events.Authentication`, …)
  and decode stored events back to concrete types via the class-UID registry
- **Flexible Querying**: Query by class, category, severity, source, time range, and more

ocsf-lake is the datastore/application layer; the OCSF standard itself (generated
structs, constants, caption maps, validator, schema compiler) lives in
[ocsf-schema-go](https://github.com/grokify/ocsf-schema-go).

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

Validation runs against the compiled OCSF schema embedded in ocsf-schema-go:
required attributes (profile-aware), attribute types, enum membership, nested
objects, `at_least_one`/`just_one` constraints, and
`class_uid`/`category_uid`/`type_uid` consistency.

### Strict (default)

Rejects events with any schema violation:

```go
l, err := lake.New(ctx, lake.WithStrictValidation())
```

### Permissive

Rejects only structurally unusable events (malformed JSON, missing `class_uid`,
unknown event class); other schema violations are tolerated:

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
    WithCategoryUID(events.CategoryUIDIAM).
    WithSeverityID(events.SeverityIDHigh).
    WithTimeRange(from, to).
    WithLimit(100).
    OrderByTime(true). // descending
    Build()

events, err := l.Query(ctx, q)
```

### Convenience Methods

```go
// Query by class
events, _ := l.QueryByClassUID(ctx, events.ClassUIDAuthentication)

// Query by category
events, _ := l.QueryByCategoryUID(ctx, events.CategoryUIDNetwork)

// Query by severity
events, _ := l.QueryBySeverityID(ctx, events.SeverityIDCritical)

// Query by source
events, _ := l.QueryBySource(ctx, "aws-cloudtrail")

// Query by time range
events, _ := l.QueryByTimeRange(ctx, fromMs, toMs)
```

## OCSF Classification Constants

Classification constants, enum values, and caption maps come from the generated
`github.com/grokify/ocsf-schema-go/ocsf/events` package, covering every OCSF
category, class, and enum (including platform extensions):

```go
// Categories
events.CategoryUIDSystem       // 1
events.CategoryUIDIAM          // 3

// Classes (all 90+, including extensions)
events.ClassUIDAuthentication      // 3002
events.ClassUIDRegistryKeyActivity // 201001 (win extension)

// Shared severities/statuses + captions
events.SeverityIDHigh              // 4
events.SeverityIDCaptions[4]       // "High"
events.ClassCaptions[3002]         // "Authentication"
```

## Record Integrity Checks

Events signed under the OCSF `record_integrity` profile (see
[ocsf-schema-go/recordintegrity](https://github.com/grokify/ocsf-schema-go)) can be
verified in the lake — one event on demand, everything, everything since a checkpoint,
a random sample, or a full tamper-evident chain:

```go
import (
    "github.com/grokify/ocsf-lake/pkg/integrity"
    ri "github.com/grokify/ocsf-schema-go/recordintegrity"
)

policy := integrity.DefaultPolicy() // AllowUnsigned: true (unsigned = warning)
policy.Verify = ri.VerifyOptions{
    Certificates:     signerCerts,
    PinnedCertSHA256: pins, // or Roots: caPool
}
checker := l.IntegrityChecker(policy)

res, _  := checker.CheckEvent(ctx, id)                        // one-off / on-demand
report, _ := checker.CheckAll(ctx)                            // full sweep
report, cp, _ := checker.CheckIncremental(ctx, lastCheckpoint) // since checkpoint
report, _ = checker.CheckSample(ctx, integrity.SamplePolicy{  // sampling
    Percent: 5, MaxEvents: 1000,
})
chainReport, _ := checker.CheckChain(ctx, "audit-log-2026-09") // walk prev_event links
```

Set `policy.AllowUnsigned = false` to count unsigned events as failures instead of
warnings. Reports break results into `verified` / `unsigned` / `failed` with per-event
statuses (`fingerprint_mismatch`, `signature_invalid`, `cert_untrusted`, `cert_expired`,
`chain_broken`, `malformed`). For automated checking, `RunPeriodicIncremental` and
`RunPeriodicSample` wrap the incremental and sampling modes in a ticker loop — a
monthly budget of N sampled events at a daily cadence is `MaxEvents: N/30`.

Set `policy.RecordReports = true` to persist every check run (an audit trail queryable
via `l.IntegrityReports`; incremental checkpoints then survive restarts via
`checker.ResumeIncremental`), and `policy.RecordEventStatus = true` to stamp
`integrity_status` / `integrity_checked_at` on each checked event.

### Integrity at Ingest

The pipeline can verify and/or attest events as they arrive:

```go
// Verify producer attestations at ingest: Monitor stamps integrity_status,
// Enforce rejects failing events with *lake.IntegrityRejectionError.
l, _ := lake.New(ctx,
    lake.WithIngestIntegrity(lake.IngestIntegrityEnforce, policy),
)

// Attest-on-ingest: the lake signs every event it receives, optionally
// chaining them tamper-evidently. Persist l.ChainTail() to continue the
// chain across restarts.
l, _ = lake.New(ctx,
    lake.WithIngestAttestation(lake.AttestationOptions{
        Signer: lakeKey, Certificate: lakeCert,
        AuthorityUID: "lake.example.com", ChainUID: "lake-chain",
    }),
)
```

## ocsflake CLI

`cmd/ocsflake` wraps the library for pipelines and operations:

```bash
go install github.com/grokify/ocsf-lake/cmd/ocsflake@latest

# Sign a chain of events, ingest, and verify it end to end
ocsflake sign --key key.pem --signer-cert cert.pem --chain-uid audit e1.json > s1.json
ocsflake sign --key key.pem --signer-cert cert.pem --chain-uid audit --prev s1.json e2.json > s2.json
ocsflake --db events.db ingest s1.json s2.json
ocsflake --db events.db check chain audit --cert cert.pem --pin <sha256> --record

# Query and on-demand checks
ocsflake --db events.db query --class-uid 3002 --since 2026-09-01T00:00:00Z
ocsflake --db events.db check sample --percent 5 --max 1000 --cert cert.pem --record
ocsflake --db events.db check incremental --cert cert.pem --record   # resumes last checkpoint
ocsflake --db events.db check reports

# Standalone verification, no lake needed (exit code 1 on failure)
ocsflake verify s2.json --cert cert.pem --pin <sha256> --prev s1.json
```

Check commands exit non-zero when events fail, so they slot into CI/cron directly.

## Seeding Test Data

The `pkg/seed` package generates realistic, schema-valid test data — a weighted mix of
8 event classes (authentication, network, DNS, HTTP, file, process, findings, and the
Windows-extension registry activity) spread over a time window, with configurable
proportions of signed / unsigned / tampered-after-signing events and tamper-evident
chains. Event content is deterministic per seed; signing authorities are always
generated at runtime (key material is never checked in, and ECDSA signatures are
randomized regardless).

In tests:

```go
res, _ := seed.Generate(seed.Config{Events: 200, SignedPct: 60, TamperPct: 10, Chains: 2, Seed: 11})
_ = res.Populate(ctx, l)
report, _ := l.IntegrityChecker(res.Authority.Policy()).CheckAll(ctx)
// report.Verified == res.Signed, report.Failed == res.Tampered, report.Unsigned == res.Unsigned
```

From the CLI (writes the ephemeral signing key/cert to `--keys-dir` for later checks):

```bash
ocsflake --db events.db seed --events 5000 --signed-pct 60 --tamper-pct 2 --chains 3 --seed 42
ocsflake --db events.db check all --cert seed-keys/cert.pem --pin <printed-pin> --record
ocsflake --db events.db check chain seed-chain-01 --cert seed-keys/cert.pem --pin <printed-pin>
```

`--break-chain` corrupts one chain link for exercising `chain_broken` detection, and
`--ndjson` emits the events to stdout instead of ingesting.

### Typed Ingest and Decode

```go
evt := events.Authentication{
    ClassUID:    events.ClassUIDAuthentication,
    CategoryUID: events.CategoryUIDIAM,
    ActivityID:  events.AuthenticationActivityIDLogon,
    // ...
}
err := l.IngestTyped(ctx, evt)

stored, _ := l.QueryByClassUID(ctx, events.ClassUIDAuthentication)
decoded, _ := stored[0].Decode() // *events.Authentication via class-UID registry
```

## Documentation

Full documentation is available at [grokify.github.io/ocsf-lake](https://grokify.github.io/ocsf-lake/).

- [Getting Started](https://grokify.github.io/ocsf-lake/getting-started/)
- [API Reference](https://grokify.github.io/ocsf-lake/api/lake/)
- [Examples](https://grokify.github.io/ocsf-lake/examples/)

## Architecture

```
ocsf-lake/
├── cmd/ocsflake/         # CLI: ingest, query, check, sign, verify
├── docs/                 # MkDocs documentation
├── ent/                  # Ent ORM schema and generated code
│   └── schema/
│       ├── event.go      # Event entity schema
│       └── integritycheck.go # Persisted integrity check reports
├── pkg/
│   ├── lake/             # Main facade
│   │   ├── lake.go       # Lake type and methods
│   │   └── options.go    # Configuration options
│   ├── integrity/        # Record-integrity checker (on-demand, full, incremental, sample, chain)
│   ├── seed/             # Schema-valid test data generator (signed/tampered/chained mixes)
│   ├── ocsf/             # Storage-side event envelope (StoredEvent, Decode)
│   │   └── event.go
│   ├── storage/          # Storage interface and implementations
│   │   ├── storage.go    # Storage interface
│   │   └── ent_storage.go # Ent-based implementation
│   └── validator/        # Event validation
│       ├── validator.go  # Validator interface and modes
│       └── ocsf_validator.go # Schema-backed validator (ocsf-schema-go)
└── (OCSF standard types live in github.com/grokify/ocsf-schema-go)
```

## License

MIT License - see [LICENSE](LICENSE) for details.
