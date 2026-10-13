# ocsflake CLI

`ocsflake` wraps the library for pipelines and operations: ingest, query,
integrity-check, seed, and standalone sign/verify.

```bash
go install github.com/grokify/ocsf-lake/cmd/ocsflake@latest
```

## Global flags

| Flag | Default | Purpose |
|------|---------|---------|
| `--db` | `ocsf-lake.db` | SQLite database file |
| `--memory` | false | in-memory SQLite (single process) |
| `--dsn` | | PostgreSQL connection string (overrides `--db`) |
| `--validation` | `strict` | schema validation mode: `strict`, `permissive`, `off` |
| `--unknown-attributes` | `warn` | attributes not in the OCSF schema: `warn`, `ignore`, `error` |
| `--source` | | default source for ingested events |

## Ingesting and querying

```bash
# One JSON event per file, or NDJSON on stdin with no arguments
ocsflake ingest event1.json event2.json
cat events.ndjson | ocsflake ingest

# Optional ingest-time integrity: --integrity monitor|enforce plus trust flags
ocsflake ingest --integrity enforce --cert signer.pem --pin <sha256> events.ndjson

ocsflake get <id> [--payload-only]
ocsflake query --class-uid 3002 --since 2026-09-01T00:00:00Z --limit 50
ocsflake query --integrity-status signature_invalid   # events whose recorded check failed
ocsflake count --severity-id 5
```

`query` emits NDJSON (stored envelope, or raw payloads with `--payload-only`);
`--since`/`--until` accept RFC 3339 or epoch milliseconds.

## Integrity checks

All check commands share trust flags — `--cert` (candidate signer certificate PEM,
repeatable), `--root` (trusted root PEM), `--pin` (hex SHA-256 cert fingerprint) —
plus `--allow-unsigned` (default true) and `--record` (persist the report and stamp
`integrity_status` on checked events). They exit non-zero when events fail, so they
slot into CI and cron directly.

```bash
ocsflake check event <id> --cert cert.pem
ocsflake check all --cert cert.pem --record
ocsflake check incremental --cert cert.pem --record   # resumes last recorded checkpoint
ocsflake check sample --percent 5 --max 1000 --cert cert.pem --record
ocsflake check chain <chain-uid> --cert cert.pem
ocsflake check reports [--kind incremental] [--limit 20]
```

## Signing and verifying (no lake required)

```bash
# Sign an event under the record_integrity profile; chain via --prev
ocsflake sign --key key.pem --signer-cert cert.pem --chain-uid audit e1.json > s1.json
ocsflake sign --key key.pem --signer-cert cert.pem --chain-uid audit --prev s1.json e2.json > s2.json

# Verify content + signatures + certificate trust, and optionally the chain link
ocsflake verify s2.json --cert cert.pem --pin <sha256> --prev s1.json
```

## Seeding test data

```bash
ocsflake --db demo.db seed --events 5000 --signed-pct 60 --tamper-pct 2 --chains 3 --seed 42
# writes the ephemeral signing key/cert to --keys-dir (default seed-keys/) and prints the pin

ocsflake --db demo.db check all --cert seed-keys/cert.pem --pin <printed-pin> --record
ocsflake --db demo.db check chain seed-chain-01 --cert seed-keys/cert.pem --pin <printed-pin>
```

`--break-chain` corrupts one chain link (for exercising `chain_broken` detection);
`--ndjson` writes generated events to stdout instead of ingesting. See
[Seed](api/seed.md) for the underlying package.
