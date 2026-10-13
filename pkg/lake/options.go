package lake

import (
	"crypto"
	"crypto/x509"

	"github.com/grokify/ocsf-lake/pkg/integrity"
	"github.com/grokify/ocsf-lake/pkg/validator"
	"github.com/grokify/ocsf-schema-go/ocsf/events"
	"github.com/grokify/ocsf-schema-go/validate"
)

// IngestIntegrityMode controls record-integrity checking during ingestion.
type IngestIntegrityMode int

const (
	// IngestIntegrityOff performs no integrity checking at ingest (default).
	IngestIntegrityOff IngestIntegrityMode = iota
	// IngestIntegrityMonitor verifies producer attestations at ingest and
	// stamps integrity_status on the stored event, but never rejects.
	IngestIntegrityMonitor
	// IngestIntegrityEnforce rejects events whose integrity check fails
	// (per the policy's AllowUnsigned setting); passing events are stamped.
	IngestIntegrityEnforce
)

// AttestationOptions configures attest-on-ingest: the lake signs each
// incoming event with its own attestation ("the lake attests what it
// received"), optionally chaining events tamper-evidently.
type AttestationOptions struct {
	// Signer holds the lake's signing key (ECDSA or RSA). Required.
	Signer crypto.Signer
	// Certificate identifies the lake's signing credential; recorded on
	// each attestation so verifiers can locate the key.
	Certificate *x509.Certificate
	// AuthorityUID identifies the lake as the attesting party.
	AuthorityUID string
	// ChainUID, when set, chains attested events: each ingested event's
	// attestation references the previous one via prev_event. The chain
	// tail is process-local; after a restart the chain starts a new
	// segment unless InitialChainTail seeds it. Chained events must carry
	// metadata.uid.
	ChainUID string
	// InitialChainTail is the JSON of the last attested event from a
	// previous run, used to continue an existing chain across restarts.
	InitialChainTail []byte
}

// Options configures the Lake.
type Options struct {
	// Storage backend
	Backend         Backend
	SQLitePath      string // for SQLite file backend
	PostgresConnStr string // for PostgreSQL backend

	// Validation
	ValidationMode validator.Mode
	// UnknownAttributes controls how attributes absent from the OCSF schema
	// are treated during validation: warn (default), ignore, or error.
	UnknownAttributes validate.UnknownMode
	SchemaVersion     string

	// Event defaults
	DefaultSource string

	// RetainRawData stores each event's original JSON bytes as received
	// (before any lake attestation) in StoredEvent.RawData.
	RetainRawData bool

	// Ingest-time record integrity
	IngestIntegrityMode IngestIntegrityMode
	IntegrityPolicy     integrity.Policy
	Attestation         *AttestationOptions
}

// Backend specifies the storage backend type.
type Backend int

const (
	// BackendSQLiteMemory uses in-memory SQLite.
	BackendSQLiteMemory Backend = iota
	// BackendSQLiteFile uses file-based SQLite.
	BackendSQLiteFile
	// BackendPostgres uses PostgreSQL.
	BackendPostgres
)

// DefaultOptions returns the default Lake options.
func DefaultOptions() Options {
	return Options{
		Backend:        BackendSQLiteMemory,
		ValidationMode: validator.ModeStrict,
		SchemaVersion:  events.SchemaVersion,
		DefaultSource:  "unknown",
	}
}

// Option is a function that configures Options.
type Option func(*Options)

// WithSQLiteMemory configures the Lake to use in-memory SQLite.
func WithSQLiteMemory() Option {
	return func(o *Options) {
		o.Backend = BackendSQLiteMemory
	}
}

// WithSQLiteFile configures the Lake to use file-based SQLite.
func WithSQLiteFile(path string) Option {
	return func(o *Options) {
		o.Backend = BackendSQLiteFile
		o.SQLitePath = path
	}
}

// WithPostgres configures the Lake to use PostgreSQL.
func WithPostgres(connStr string) Option {
	return func(o *Options) {
		o.Backend = BackendPostgres
		o.PostgresConnStr = connStr
	}
}

// WithStrictValidation configures strict validation mode.
// Invalid events will be rejected.
func WithStrictValidation() Option {
	return func(o *Options) {
		o.ValidationMode = validator.ModeStrict
	}
}

// WithPermissiveValidation configures permissive validation mode.
// Invalid events will be accepted with warnings.
func WithPermissiveValidation() Option {
	return func(o *Options) {
		o.ValidationMode = validator.ModePermissive
	}
}

// WithNoValidation disables validation entirely.
func WithNoValidation() Option {
	return func(o *Options) {
		o.ValidationMode = validator.ModeDisabled
	}
}

// WithSchemaVersion sets the OCSF schema version.
func WithSchemaVersion(version string) Option {
	return func(o *Options) {
		o.SchemaVersion = version
	}
}

// WithDefaultSource sets the default source for events.
func WithDefaultSource(source string) Option {
	return func(o *Options) {
		o.DefaultSource = source
	}
}

// WithUnknownAttributes controls how attributes absent from the OCSF schema
// are treated during validation (validate.UnknownWarn is the default;
// validate.UnknownError makes strict mode reject them; validate.UnknownIgnore
// silences them).
func WithUnknownAttributes(m validate.UnknownMode) Option {
	return func(o *Options) {
		o.UnknownAttributes = m
	}
}

// WithRawDataRetention stores each event's original JSON bytes as received
// (before any lake attestation) in StoredEvent.RawData, preserving forensic
// evidence at the cost of roughly doubling per-event storage.
func WithRawDataRetention() Option {
	return func(o *Options) {
		o.RetainRawData = true
	}
}

// WithIngestIntegrity enables record-integrity checking during ingestion.
// The policy supplies verification inputs (certificates, trust anchors) and
// the unsigned-events stance; see integrity.Policy.
func WithIngestIntegrity(mode IngestIntegrityMode, policy integrity.Policy) Option {
	return func(o *Options) {
		o.IngestIntegrityMode = mode
		o.IntegrityPolicy = policy
	}
}

// WithIngestAttestation makes the lake sign every ingested event with its
// own attestation. When both integrity verification and attestation are
// configured, producer signatures are verified first, then the lake's
// attestation is added.
func WithIngestAttestation(a AttestationOptions) Option {
	return func(o *Options) {
		o.Attestation = &a
	}
}
