# ROADMAP — ocsf-lake

Status legend: `planned` | `in_progress` | `done`. Phase status is derived from member
RMI statuses. The OCSF standard layer (bindings, validator, record-integrity crypto)
is tracked separately in
[ocsf-schema-go](https://github.com/grokify/ocsf-schema-go)'s roadmap.

## Phase 1 — Core lake (initial scaffold)

| RMI | Title | Status |
|-----|-------|--------|
| RMI-OCSFLAKE-001 | Ent storage (SQLite memory/file, PostgreSQL), `StoredEvent` envelope with indexed classification columns | done |
| RMI-OCSFLAKE-002 | Lake facade: ingest, query builder, convenience queries, count, delete | done |
| RMI-OCSFLAKE-003 | Validator interface with strict/permissive/disabled modes | done |

## Phase 2 — ocsf-schema-go integration

| RMI | Title | Status |
|-----|-------|--------|
| RMI-OCSFLAKE-004 | Replace hand-written OCSF types/constants with generated ocsf-schema-go packages | done |
| RMI-OCSFLAKE-005 | Schema-backed validation via the embedded compiled schema (`OCSFValidator`) | done |
| RMI-OCSFLAKE-006 | Typed ingest (`IngestTyped`) and class-UID decode (`StoredEvent.Decode`) | done |

## Phase 3 — Record integrity

| RMI | Title | Status |
|-----|-------|--------|
| RMI-OCSFLAKE-007 | Integrity checker: on-demand, full, incremental, sample, and chain modes with unsigned-events policy | done |
| RMI-OCSFLAKE-008 | Report persistence (`IntegrityCheck` entity), event `integrity_status` stamps, resumable checkpoints | done |
| RMI-OCSFLAKE-009 | Ingest pipeline integrity: verify-on-ingest (monitor/enforce), attest-on-ingest with chaining | done |
| RMI-OCSFLAKE-010 | `ocsflake` CLI: ingest, get, query, count, check, sign, verify, seed | done |
| RMI-OCSFLAKE-011 | `pkg/seed`: deterministic schema-valid test data with signed/tampered/chained mixes | done |

## Phase 4 — Hardening quick wins

| RMI | Title | Status |
|-----|-------|--------|
| RMI-OCSFLAKE-012 | `integrity_status` query filter (API + CLI) | done |
| RMI-OCSFLAKE-013 | Raw-data retention option (original bytes as received, pre-attestation) | done |
| RMI-OCSFLAKE-014 | Unknown-attribute policy exposed through lake options and CLI | done |
| RMI-OCSFLAKE-015 | Concurrency-safe close (atomic flag, idempotent), batch ingest error positions, CLI batch ingest | done |

## Phase 5 — Durability and scale

| RMI | Title | Status |
|-----|-------|--------|
| RMI-OCSFLAKE-016 | Persist the attest-on-ingest chain tail (meta table) so lake-attested chains survive restarts without caller plumbing | planned |
| RMI-OCSFLAKE-017 | Index `metadata.uid` and attestation `chain_uid` as columns; efficient prev_event resolution and `CheckChain` without payload scans | planned |
| RMI-OCSFLAKE-018 | Aggregations: `CountBy(class/severity/source/status, timeRange)` and `ocsflake stats` | planned |
| RMI-OCSFLAKE-019 | Partial-failure batch ingest: per-event accept/reject results instead of first-error abort | planned |
| RMI-OCSFLAKE-020 | Retention: `DeleteOlderThan` + periodic runner | planned |

## Phase 6 — Production operations

| RMI | Title | Status |
|-----|-------|--------|
| RMI-OCSFLAKE-021 | PostgreSQL integration tests (build-tagged, containerized) and dialect review | planned |
| RMI-OCSFLAKE-022 | Observability: `slog` via context through ingest/check paths; failure counters | planned |
| RMI-OCSFLAKE-023 | MkDocs deploy workflow, coverage badge, release tagging per org conventions | in_progress |
