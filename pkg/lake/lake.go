// Package lake provides the main facade for storing and querying OCSF events.
package lake

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/grokify/ocsf-lake/pkg/integrity"
	"github.com/grokify/ocsf-lake/pkg/ocsf"
	"github.com/grokify/ocsf-lake/pkg/storage"
	"github.com/grokify/ocsf-lake/pkg/validator"
	"github.com/grokify/ocsf-schema-go/recordintegrity"
	"github.com/grokify/ocsf-schema-go/validate"
)

// Common errors.
var (
	ErrInvalidBackend = errors.New("invalid storage backend configuration")
	ErrClosed         = errors.New("lake is closed")
)

// Lake is the main entry point for storing and querying OCSF events. It is
// safe for concurrent use.
type Lake struct {
	storage       storage.Storage
	validator     validator.Validator
	opts          Options
	ingestChecker *integrity.Checker // nil unless ingest integrity enabled
	attestor      *attestor          // nil unless attest-on-ingest enabled
	closed        atomic.Bool
}

// IntegrityRejectionError is returned by ingestion when
// IngestIntegrityEnforce rejects an event.
type IntegrityRejectionError struct {
	Result integrity.EventResult
}

func (e *IntegrityRejectionError) Error() string {
	msg := fmt.Sprintf("event failed integrity check (%s)", e.Result.Status)
	if len(e.Result.Issues) > 0 {
		msg += ": " + e.Result.Issues[0].String()
	}
	return msg
}

// New creates a new Lake with the given options.
func New(ctx context.Context, opts ...Option) (*Lake, error) {
	options := DefaultOptions()
	for _, opt := range opts {
		opt(&options)
	}

	// Create storage backend
	var store storage.Storage
	var err error

	switch options.Backend {
	case BackendSQLiteMemory:
		store, err = storage.NewSQLiteMemoryStorage(ctx)
	case BackendSQLiteFile:
		if options.SQLitePath == "" {
			return nil, fmt.Errorf("%w: SQLite file path required", ErrInvalidBackend)
		}
		store, err = storage.NewSQLiteFileStorage(ctx, options.SQLitePath)
	case BackendPostgres:
		if options.PostgresConnStr == "" {
			return nil, fmt.Errorf("%w: PostgreSQL connection string required", ErrInvalidBackend)
		}
		store, err = storage.NewPostgresStorage(ctx, options.PostgresConnStr)
	default:
		return nil, fmt.Errorf("%w: unknown backend type", ErrInvalidBackend)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to create storage: %w", err)
	}

	// Create schema-backed validator (embedded compiled OCSF schema)
	v := validator.NewOCSFValidator(options.ValidationMode,
		validate.WithUnknownAttributes(options.UnknownAttributes))

	l := &Lake{
		storage:   store,
		validator: v,
		opts:      options,
	}
	if options.IngestIntegrityMode != IngestIntegrityOff {
		l.ingestChecker = integrity.NewChecker(store, options.IntegrityPolicy)
	}
	if options.Attestation != nil {
		if options.Attestation.Signer == nil {
			if cerr := store.Close(); cerr != nil {
				return nil, fmt.Errorf("lake: attestation requires a signer (and closing storage failed: %v)", cerr)
			}
			return nil, fmt.Errorf("lake: attestation requires a signer")
		}
		l.attestor = &attestor{opts: *options.Attestation, tail: options.Attestation.InitialChainTail}
	}
	return l, nil
}

// attestor adds the lake's own attestation to ingested events, maintaining
// the process-local chain tail when chaining is configured.
type attestor struct {
	mu   sync.Mutex
	opts AttestationOptions
	tail []byte
}

// attest signs eventJSON with the lake's key and returns the event with the
// attestation attached.
func (a *attestor) attest(eventJSON []byte) ([]byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	signOpts := recordintegrity.SignOptions{
		Signer:       a.opts.Signer,
		Certificate:  a.opts.Certificate,
		AuthorityUID: a.opts.AuthorityUID,
		ChainUID:     a.opts.ChainUID,
	}
	if a.opts.ChainUID != "" && len(a.tail) > 0 {
		ref, err := recordintegrity.NewPrevEventRef(a.tail)
		if err != nil {
			return nil, fmt.Errorf("lake: building chain link: %w", err)
		}
		signOpts.PrevEvent = ref
	}
	signed, _, err := recordintegrity.SignAndAttach(eventJSON, signOpts)
	if err != nil {
		return nil, fmt.Errorf("lake: attesting event: %w", err)
	}
	if a.opts.ChainUID != "" {
		a.tail = signed
	}
	return signed, nil
}

// ChainTail returns the JSON of the last attested event when attest-on-ingest
// chaining is enabled. Persist it and pass it back as
// AttestationOptions.InitialChainTail to continue the chain across restarts.
func (l *Lake) ChainTail() []byte {
	if l.attestor == nil {
		return nil
	}
	l.attestor.mu.Lock()
	defer l.attestor.mu.Unlock()
	return l.attestor.tail
}

// prepareEvent runs the ingest pipeline for one raw event: schema
// validation, integrity verification of producer attestations, lake
// attestation, and conversion to a StoredEvent.
func (l *Lake) prepareEvent(ctx context.Context, id string, eventJSON json.RawMessage) (*ocsf.StoredEvent, error) {
	// The original bytes as received, before any lake attestation mutates
	// the event; retained when RetainRawData is set.
	original := eventJSON

	if err := l.validator.Validate(ctx, eventJSON); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	// Verify producer attestations before the lake adds its own.
	var integrityStatus string
	var integrityCheckedAt *time.Time
	if l.ingestChecker != nil {
		res := l.ingestChecker.CheckJSON(id, eventJSON)
		if l.opts.IngestIntegrityMode == IngestIntegrityEnforce && res.Outcome == integrity.OutcomeFailed {
			return nil, &IntegrityRejectionError{Result: res}
		}
		integrityStatus = string(res.Status)
		now := time.Now()
		integrityCheckedAt = &now
	}

	if l.attestor != nil {
		signed, err := l.attestor.attest(eventJSON)
		if err != nil {
			return nil, err
		}
		eventJSON = signed
	}

	payload, err := ocsf.ParsePayload(eventJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to parse event payload: %w", err)
	}

	source := l.opts.DefaultSource
	if metadata, ok := payload["metadata"].(map[string]any); ok {
		if product, ok := metadata["product"].(map[string]any); ok {
			if name, ok := product["name"].(string); ok {
				source = name
			}
		}
	}

	storedEvent := storage.StoredEventFromPayload(id, payload, source, l.opts.SchemaVersion)
	storedEvent.IntegrityStatus = integrityStatus
	storedEvent.IntegrityCheckedAt = integrityCheckedAt
	if l.opts.RetainRawData {
		storedEvent.RawData = string(original)
	}
	return storedEvent, nil
}

// Ingest validates and stores one or more OCSF events. Depending on
// configuration the pipeline also verifies producer attestations
// (WithIngestIntegrity) and adds the lake's own attestation
// (WithIngestAttestation).
func (l *Lake) Ingest(ctx context.Context, events ...json.RawMessage) error {
	if l.closed.Load() {
		return ErrClosed
	}

	storedEvents := make([]*ocsf.StoredEvent, 0, len(events))
	for i, eventJSON := range events {
		storedEvent, err := l.prepareEvent(ctx, uuid.New().String(), eventJSON)
		if err != nil {
			return fmt.Errorf("event %d of %d: %w", i+1, len(events), err)
		}
		storedEvents = append(storedEvents, storedEvent)
	}

	// Store all events
	if err := l.storage.Insert(ctx, storedEvents...); err != nil {
		return fmt.Errorf("failed to store events: %w", err)
	}

	return nil
}

// IngestTyped validates and stores typed OCSF events, such as the generated
// structs from github.com/grokify/ocsf-schema-go/ocsf/events (e.g.
// *events.Authentication). Each event is marshaled and passes through the
// same validation and indexing pipeline as Ingest.
func (l *Lake) IngestTyped(ctx context.Context, events ...any) error {
	if l.closed.Load() {
		return ErrClosed
	}
	raws := make([]json.RawMessage, 0, len(events))
	for _, evt := range events {
		data, err := json.Marshal(evt)
		if err != nil {
			return fmt.Errorf("failed to marshal event: %w", err)
		}
		raws = append(raws, data)
	}
	return l.Ingest(ctx, raws...)
}

// IngestWithID validates and stores an OCSF event with a specific ID,
// running the same pipeline as Ingest.
func (l *Lake) IngestWithID(ctx context.Context, id string, eventJSON json.RawMessage) error {
	if l.closed.Load() {
		return ErrClosed
	}

	storedEvent, err := l.prepareEvent(ctx, id, eventJSON)
	if err != nil {
		return err
	}

	if err := l.storage.Insert(ctx, storedEvent); err != nil {
		return fmt.Errorf("failed to store event: %w", err)
	}

	return nil
}

// IntegrityReports returns persisted record-integrity check runs, newest
// first, optionally filtered by kind ("" = all).
func (l *Lake) IntegrityReports(ctx context.Context, kind string, limit int) ([]*ocsf.IntegrityCheckRecord, error) {
	if l.closed.Load() {
		return nil, ErrClosed
	}
	return l.storage.ListIntegrityReports(ctx, kind, limit)
}

// Get retrieves a single event by ID.
func (l *Lake) Get(ctx context.Context, id string) (*ocsf.StoredEvent, error) {
	if l.closed.Load() {
		return nil, ErrClosed
	}
	return l.storage.Get(ctx, id)
}

// Query retrieves events matching the query parameters.
func (l *Lake) Query(ctx context.Context, q *storage.Query) ([]*ocsf.StoredEvent, error) {
	if l.closed.Load() {
		return nil, ErrClosed
	}
	return l.storage.Query(ctx, q)
}

// QueryBuilder returns a new query builder.
func (l *Lake) QueryBuilder() *storage.QueryBuilder {
	return storage.NewQuery()
}

// Count returns the number of events matching the query parameters.
func (l *Lake) Count(ctx context.Context, q *storage.Query) (int, error) {
	if l.closed.Load() {
		return 0, ErrClosed
	}
	return l.storage.Count(ctx, q)
}

// Delete removes events matching the query parameters.
func (l *Lake) Delete(ctx context.Context, q *storage.Query) (int, error) {
	if l.closed.Load() {
		return 0, ErrClosed
	}
	return l.storage.Delete(ctx, q)
}

// Close closes the Lake and releases resources.
func (l *Lake) Close() error {
	if !l.closed.CompareAndSwap(false, true) {
		return nil
	}
	return l.storage.Close()
}

// Storage returns the underlying storage for advanced operations.
func (l *Lake) Storage() storage.Storage {
	return l.storage
}

// IntegrityChecker returns a record-integrity checker over this lake's
// storage. See the integrity package for check modes (on-demand, full,
// incremental, sampling, chain).
func (l *Lake) IntegrityChecker(policy integrity.Policy) *integrity.Checker {
	return integrity.NewChecker(l.storage, policy)
}

// QueryByClassUID is a convenience method to query events by class UID.
func (l *Lake) QueryByClassUID(ctx context.Context, classUID int) ([]*ocsf.StoredEvent, error) {
	q := l.QueryBuilder().WithClassUID(classUID).Build()
	return l.Query(ctx, q)
}

// QueryByCategoryUID is a convenience method to query events by category UID.
func (l *Lake) QueryByCategoryUID(ctx context.Context, categoryUID int) ([]*ocsf.StoredEvent, error) {
	q := l.QueryBuilder().WithCategoryUID(categoryUID).Build()
	return l.Query(ctx, q)
}

// QueryBySeverityID is a convenience method to query events by severity ID.
func (l *Lake) QueryBySeverityID(ctx context.Context, severityID int) ([]*ocsf.StoredEvent, error) {
	q := l.QueryBuilder().WithSeverityID(severityID).Build()
	return l.Query(ctx, q)
}

// QueryBySource is a convenience method to query events by source.
func (l *Lake) QueryBySource(ctx context.Context, source string) ([]*ocsf.StoredEvent, error) {
	q := l.QueryBuilder().WithSource(source).Build()
	return l.Query(ctx, q)
}

// QueryByTimeRange is a convenience method to query events within a time range.
func (l *Lake) QueryByTimeRange(ctx context.Context, from, to int64) ([]*ocsf.StoredEvent, error) {
	q := l.QueryBuilder().WithTimeRange(from, to).Build()
	return l.Query(ctx, q)
}
