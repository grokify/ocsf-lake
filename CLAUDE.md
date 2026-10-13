# CLAUDE.md — ocsf-lake

Guidance for working in this repository.

## What this repo is

ocsf-lake is the **datastore/application layer** for OCSF security events: storage
(Ent: SQLite/PostgreSQL), querying, schema validation at ingest, record-integrity
verification, and the `ocsflake` CLI.

The **OCSF standard itself lives in `github.com/grokify/ocsf-schema-go`**: generated
event/object structs, classification constants, caption maps, the class-UID registry,
the schema compiler, the semantic validator (`validate`), and the record_integrity
crypto (`recordintegrity`). Never re-implement spec-derived types or constants here —
import them. Anything about persistence, ingestion pipelines, check orchestration, or
CLI belongs here.

## Architecture

| Package | Role |
|---------|------|
| `pkg/lake` | Facade: ingest pipeline (validate → verify integrity → attest → store), queries, options |
| `pkg/storage` | `Storage` interface + Ent implementation; `StoredEvent` envelope with indexed columns |
| `pkg/validator` | `Validator` interface + `OCSFValidator` (wraps ocsf-schema-go's embedded compiled schema) |
| `pkg/integrity` | Record-integrity checker: on-demand / full / incremental / sample / chain modes, report persistence |
| `pkg/seed` | Deterministic, schema-valid test-data generator (signed/tampered/chained mixes) |
| `pkg/ocsf` | Storage-side types only: `StoredEvent`, `IntegrityCheckRecord`, `Decode()` |
| `ent/` | Generated ORM code; schemas in `ent/schema/` |
| `cmd/ocsflake` | CLI over all of the above |

## Commands

```bash
go build ./...                 # CGO required (mattn/go-sqlite3)
go test ./pkg/...              # unit tests (in-memory SQLite)
golangci-lint run
go generate ./ent              # regenerate ORM after editing ent/schema/
```

## Conventions and gotchas

- **Ent regeneration**: after changing `ent/schema/*.go`, run `go generate ./ent`.
  If codegen fails with `package "context" without types`, upgrade
  `golang.org/x/tools` (`go get golang.org/x/tools@latest && go mod tidy`).
- **Cobra output**: `cmd.Println`/`cmd.Printf` write to **stderr**. Command *data*
  (JSON, NDJSON, counts) must use `fmt.Fprintln(cmd.OutOrStdout(), ...)` or
  `printJSON` so redirects and pipes work; status/progress text may use `cmd.Print*`.
- **Never commit key material**, including test keys. Signing authorities are
  generated at runtime (`seed.NewAuthority`); the CLI writes ephemeral PEMs to a
  user-chosen directory.
- **Integrity semantics**: unsigned events are warnings under
  `Policy.AllowUnsigned=true` (default) and failures otherwise. Ingest-time
  verification runs *before* the lake's own attestation is added.
- **`replace` directive**: during local development `go.mod` may carry
  `replace github.com/grokify/ocsf-schema-go => ../ocsf-schema-go` (relative path
  only). It must be removed before pushing.
- Tests that exercise querying (not schema completeness) use permissive validation
  with minimal fixtures; tests of the ingest path use fully valid events (or
  `pkg/seed`).

## Docs

README.md is the primary reference; the MkDocs site lives in `docs/` (`mkdocs.yml`
nav must be updated when pages are added). Keep README examples compilable against
the current API — several were broken historically by constant renames.
