# Integrity

The `integrity` package verifies OCSF `record_integrity` attestations over stored
events, using the cryptographic primitives from
[ocsf-schema-go/recordintegrity](https://github.com/grokify/ocsf-schema-go).

## Package

```go
import (
    "github.com/grokify/ocsf-lake/pkg/integrity"
    ri "github.com/grokify/ocsf-schema-go/recordintegrity"
)
```

## Policy

```go
policy := integrity.DefaultPolicy() // AllowUnsigned: true
policy.Verify = ri.VerifyOptions{
    Certificates:     signerCerts,          // candidate signer certificates
    PinnedCertSHA256: []string{pin},        // and/or Roots: *x509.CertPool
}
policy.RecordReports = true      // persist every check run
policy.RecordEventStatus = true  // stamp integrity_status on checked events
```

- `AllowUnsigned: true` (default) reports unsigned events as warnings under
  `Report.Unsigned`; `false` counts them as failures.
- `RecordReports` builds an audit trail of check runs (queryable via
  `Lake.IntegrityReports`) and makes incremental checkpoints resumable.
- `RecordEventStatus` stamps `integrity_status` / `integrity_checked_at` on each
  checked event (indexed, so dashboards can query verification state).

## Check modes

```go
checker := l.IntegrityChecker(policy)

res, err := checker.CheckEvent(ctx, id)          // one-off, on-demand
report, err := checker.CheckAll(ctx)             // full sweep
report, cp, err := checker.CheckIncremental(ctx, checkpoint) // since checkpoint
report, err = checker.CheckSample(ctx, integrity.SamplePolicy{
    Percent: 5, MaxEvents: 1000,                 // % of events, capped per run
})
chainReport, err := checker.CheckChain(ctx, "audit-log-2026-09")
```

`CheckChain` resolves chain members by attestation `chain_uid`, verifies each event,
and validates every `prev_event` link against the resolved predecessor.

### Resuming incremental checks

```go
cp, err := checker.ResumeIncremental(ctx) // checkpoint from last persisted run
report, next, err := checker.CheckIncremental(ctx, cp)
```

### Periodic runners

```go
go checker.RunPeriodicIncremental(ctx, time.Hour, start, onReport)
go checker.RunPeriodicSample(ctx, 24*time.Hour,
    integrity.SamplePolicy{Percent: 5, MaxEvents: 500}, onReport)
```

A monthly budget of N sampled events at a daily cadence is `MaxEvents: N/30`.

## Reports

```go
type Report struct {
    StartedAt, FinishedAt time.Time
    Checked, Verified, Unsigned, Failed int
    Failures        []EventResult // events whose outcome was failed
    UnsignedEvents  []EventResult // when AllowUnsigned
    RecordingErrors []string      // persistence problems (non-fatal)
}
```

Per-event statuses come from recordintegrity: `verified`, `unsigned`,
`fingerprint_mismatch`, `signature_invalid`, `cert_untrusted`, `cert_expired`,
`chain_broken`, `malformed`.

## Integrity at ingest

See [Lake](lake.md): `lake.WithIngestIntegrity(mode, policy)` verifies producer
attestations during ingestion (`Monitor` stamps, `Enforce` rejects with
`*lake.IntegrityRejectionError`), and `lake.WithIngestAttestation` makes the lake
sign every event it receives, optionally chaining them.
