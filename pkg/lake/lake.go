// Package lake provides the main facade for storing and querying OCSF events.
package lake

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/grokify/ocsf-lake/pkg/ocsf"
	"github.com/grokify/ocsf-lake/pkg/storage"
	"github.com/grokify/ocsf-lake/pkg/validator"
)

// Common errors.
var (
	ErrInvalidBackend = errors.New("invalid storage backend configuration")
	ErrClosed         = errors.New("lake is closed")
)

// Lake is the main entry point for storing and querying OCSF events.
type Lake struct {
	storage   storage.Storage
	validator validator.Validator
	opts      Options
	closed    bool
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

	// Create validator
	v := validator.NewBasicValidator(options.ValidationMode)

	return &Lake{
		storage:   store,
		validator: v,
		opts:      options,
	}, nil
}

// Ingest validates and stores one or more OCSF events.
func (l *Lake) Ingest(ctx context.Context, events ...json.RawMessage) error {
	if l.closed {
		return ErrClosed
	}

	storedEvents := make([]*ocsf.StoredEvent, 0, len(events))

	for _, eventJSON := range events {
		// Validate the event
		if err := l.validator.Validate(ctx, eventJSON); err != nil {
			return fmt.Errorf("validation failed: %w", err)
		}

		// Parse the payload
		payload, err := ocsf.ParsePayload(eventJSON)
		if err != nil {
			return fmt.Errorf("failed to parse event payload: %w", err)
		}

		// Generate ID if not present
		id := uuid.New().String()

		// Determine source
		source := l.opts.DefaultSource
		if metadata, ok := payload["metadata"].(map[string]any); ok {
			if product, ok := metadata["product"].(map[string]any); ok {
				if name, ok := product["name"].(string); ok {
					source = name
				}
			}
		}

		// Create stored event
		storedEvent := storage.StoredEventFromPayload(id, payload, source, l.opts.SchemaVersion)

		storedEvents = append(storedEvents, storedEvent)
	}

	// Store all events
	if err := l.storage.Insert(ctx, storedEvents...); err != nil {
		return fmt.Errorf("failed to store events: %w", err)
	}

	return nil
}

// IngestWithID validates and stores an OCSF event with a specific ID.
func (l *Lake) IngestWithID(ctx context.Context, id string, eventJSON json.RawMessage) error {
	if l.closed {
		return ErrClosed
	}

	// Validate the event
	if err := l.validator.Validate(ctx, eventJSON); err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}

	// Parse the payload
	payload, err := ocsf.ParsePayload(eventJSON)
	if err != nil {
		return fmt.Errorf("failed to parse event payload: %w", err)
	}

	// Determine source
	source := l.opts.DefaultSource
	if metadata, ok := payload["metadata"].(map[string]any); ok {
		if product, ok := metadata["product"].(map[string]any); ok {
			if name, ok := product["name"].(string); ok {
				source = name
			}
		}
	}

	// Create stored event
	storedEvent := storage.StoredEventFromPayload(id, payload, source, l.opts.SchemaVersion)

	// Store the event
	if err := l.storage.Insert(ctx, storedEvent); err != nil {
		return fmt.Errorf("failed to store event: %w", err)
	}

	return nil
}

// Get retrieves a single event by ID.
func (l *Lake) Get(ctx context.Context, id string) (*ocsf.StoredEvent, error) {
	if l.closed {
		return nil, ErrClosed
	}
	return l.storage.Get(ctx, id)
}

// Query retrieves events matching the query parameters.
func (l *Lake) Query(ctx context.Context, q *storage.Query) ([]*ocsf.StoredEvent, error) {
	if l.closed {
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
	if l.closed {
		return 0, ErrClosed
	}
	return l.storage.Count(ctx, q)
}

// Delete removes events matching the query parameters.
func (l *Lake) Delete(ctx context.Context, q *storage.Query) (int, error) {
	if l.closed {
		return 0, ErrClosed
	}
	return l.storage.Delete(ctx, q)
}

// Close closes the Lake and releases resources.
func (l *Lake) Close() error {
	if l.closed {
		return nil
	}
	l.closed = true
	return l.storage.Close()
}

// Storage returns the underlying storage for advanced operations.
func (l *Lake) Storage() storage.Storage {
	return l.storage
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
