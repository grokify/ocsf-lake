# Seed

The `seed` package generates realistic, schema-valid OCSF test data for populating a
lake — usable from `_test.go` files or via `ocsflake seed`.

## Package

```go
import "github.com/grokify/ocsf-lake/pkg/seed"
```

## What it generates

A weighted mix of 8 event classes — `authentication`, `network_activity`,
`dns_activity`, `http_activity`, `file_activity`, `process_activity`,
`detection_finding`, and `registry_key_activity` (the Windows extension, class_uid
201001) — spread over a time window with weighted severities and realistic value
pools. Every template fills its class's required attributes and constraints, so all
generated events pass **strict** schema validation (guaranteed by the package's own
tests).

## Config

```go
res, err := seed.Generate(seed.Config{
    Events:      5000,          // total events (default 1000)
    Span:        30 * 24 * time.Hour,
    Seed:        42,            // content determinism
    SignedPct:   60,            // % signed by the authority
    TamperPct:   2,             // % of signed events corrupted after signing
    Chains:      3,             // tamper-evident chains woven through the data
    ChainLength: 10,
    BreakChain:  false,         // corrupt one link of the last chain
})
```

Determinism: event **content** is byte-identical for identical configs; signature
bytes are not (ECDSA signing is randomized, and authorities are generated per run).

## Signing authorities

```go
auth, err := seed.NewAuthority("my-authority") // ephemeral P-256 key + self-signed cert
auth.Pin()                                     // hex SHA-256 cert fingerprint
auth.Policy()                                  // integrity.Policy trusting this authority
keyPath, certPath, err := auth.WritePEM(dir)   // persist for cross-process use (0600)
```

Authorities are always generated at runtime — key material is never committed to the
repository, even for tests.

## Using the result

```go
// Ground truth per event and in aggregate:
type Event struct{ ID, UID string; JSON []byte; Class string; Signed, Tampered bool; ChainUID string }
res.Signed, res.Tampered, res.Unsigned // counts the integrity checker must reproduce
res.ChainUIDs                          // e.g. ["seed-chain-01", ...]

err = res.Populate(ctx, l)   // ingest into a lake
err = res.NDJSON(os.Stdout)  // or emit NDJSON for `ocsflake ingest`
```

## Typical test

```go
res, _ := seed.Generate(seed.Config{Events: 200, SignedPct: 60, TamperPct: 10, Chains: 2, Seed: 11})
l, _ := lake.New(ctx, lake.WithSQLiteMemory())
_ = res.Populate(ctx, l)

report, _ := l.IntegrityChecker(res.Authority.Policy()).CheckAll(ctx)
// report.Verified == res.Signed
// report.Failed   == res.Tampered
// report.Unsigned == res.Unsigned
```
