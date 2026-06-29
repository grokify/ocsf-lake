package lake

import (
	"github.com/grokify/ocsf-lake/pkg/validator"
)

// Options configures the Lake.
type Options struct {
	// Storage backend
	Backend         Backend
	SQLitePath      string // for SQLite file backend
	PostgresConnStr string // for PostgreSQL backend

	// Validation
	ValidationMode validator.Mode
	SchemaVersion  string

	// Event defaults
	DefaultSource string
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
		SchemaVersion:  "1.3.0",
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
