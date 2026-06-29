package storage

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	"github.com/grokify/ocsf-lake/ent"
	"github.com/grokify/ocsf-lake/ent/event"
	"github.com/grokify/ocsf-lake/pkg/ocsf"
)

// EntStorage implements Storage using Ent ORM.
type EntStorage struct {
	client *ent.Client
}

// NewEntStorage creates a new Ent-based storage with the given client.
func NewEntStorage(client *ent.Client) *EntStorage {
	return &EntStorage{client: client}
}

// NewSQLiteMemoryStorage creates an in-memory SQLite storage.
func NewSQLiteMemoryStorage(ctx context.Context) (*EntStorage, error) {
	db, err := sql.Open("sqlite3", "file:ocsf?mode=memory&cache=shared&_fk=1")
	if err != nil {
		return nil, fmt.Errorf("%w: sqlite memory: %v", ErrConnectionFailed, err)
	}

	drv := entsql.OpenDB(dialect.SQLite, db)
	client := ent.NewClient(ent.Driver(drv))

	// Run migrations
	if err := client.Schema.Create(ctx); err != nil {
		client.Close()
		return nil, fmt.Errorf("failed to create schema: %w", err)
	}

	return NewEntStorage(client), nil
}

// NewSQLiteFileStorage creates a file-based SQLite storage.
func NewSQLiteFileStorage(ctx context.Context, path string) (*EntStorage, error) {
	dsn := fmt.Sprintf("file:%s?cache=shared&_fk=1", path)
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("%w: sqlite file: %v", ErrConnectionFailed, err)
	}

	drv := entsql.OpenDB(dialect.SQLite, db)
	client := ent.NewClient(ent.Driver(drv))

	// Run migrations
	if err := client.Schema.Create(ctx); err != nil {
		client.Close()
		return nil, fmt.Errorf("failed to create schema: %w", err)
	}

	return NewEntStorage(client), nil
}

// NewPostgresStorage creates a PostgreSQL-backed storage.
func NewPostgresStorage(ctx context.Context, connStr string) (*EntStorage, error) {
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, fmt.Errorf("%w: postgres: %v", ErrConnectionFailed, err)
	}

	drv := entsql.OpenDB(dialect.Postgres, db)
	client := ent.NewClient(ent.Driver(drv))

	// Run migrations
	if err := client.Schema.Create(ctx); err != nil {
		client.Close()
		return nil, fmt.Errorf("failed to create schema: %w", err)
	}

	return NewEntStorage(client), nil
}

// Insert stores one or more events.
func (s *EntStorage) Insert(ctx context.Context, events ...*ocsf.StoredEvent) error {
	// Use bulk create for efficiency
	bulk := make([]*ent.EventCreate, len(events))
	for i, e := range events {
		bulk[i] = s.client.Event.Create().
			SetID(e.ID).
			SetClassUID(e.ClassUID).
			SetCategoryUID(e.CategoryUID).
			SetActivityID(e.ActivityID).
			SetTypeUID(e.TypeUID).
			SetNillableSeverityID(intPtr(e.SeverityID)).
			SetNillableStatusID(intPtr(e.StatusID)).
			SetTime(e.Time).
			SetIngestedAt(e.IngestedAt).
			SetSource(e.Source).
			SetSchemaVersion(e.SchemaVersion).
			SetPayload(e.Payload).
			SetNillableRawData(strPtr(e.RawData))
	}

	_, err := s.client.Event.CreateBulk(bulk...).Save(ctx)
	if err != nil {
		// Check for duplicate key error
		if ent.IsConstraintError(err) {
			return ErrDuplicateID
		}
		return fmt.Errorf("failed to insert events: %w", err)
	}

	return nil
}

// Get retrieves a single event by ID.
func (s *EntStorage) Get(ctx context.Context, id string) (*ocsf.StoredEvent, error) {
	e, err := s.client.Event.Get(ctx, id)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("failed to get event: %w", err)
	}

	return entEventToStoredEvent(e), nil
}

// Query retrieves events matching the query parameters.
func (s *EntStorage) Query(ctx context.Context, q *Query) ([]*ocsf.StoredEvent, error) {
	query := s.buildQuery(q)

	// Apply ordering
	switch q.OrderBy {
	case "time":
		if q.OrderDesc {
			query = query.Order(event.ByTime(entsql.OrderDesc()))
		} else {
			query = query.Order(event.ByTime())
		}
	case "ingested_at":
		if q.OrderDesc {
			query = query.Order(event.ByIngestedAt(entsql.OrderDesc()))
		} else {
			query = query.Order(event.ByIngestedAt())
		}
	default:
		// Default to descending time order
		query = query.Order(event.ByTime(entsql.OrderDesc()))
	}

	// Apply pagination
	if q.Offset > 0 {
		query = query.Offset(q.Offset)
	}
	if q.Limit > 0 {
		query = query.Limit(q.Limit)
	}

	events, err := query.All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to query events: %w", err)
	}

	result := make([]*ocsf.StoredEvent, len(events))
	for i, e := range events {
		result[i] = entEventToStoredEvent(e)
	}

	return result, nil
}

// Count returns the number of events matching the query parameters.
func (s *EntStorage) Count(ctx context.Context, q *Query) (int, error) {
	query := s.buildQuery(q)

	count, err := query.Count(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to count events: %w", err)
	}

	return count, nil
}

// Delete removes events matching the query parameters.
func (s *EntStorage) Delete(ctx context.Context, q *Query) (int, error) {
	delete := s.client.Event.Delete()

	// Apply filters
	if q.ClassUID != nil {
		delete = delete.Where(event.ClassUID(*q.ClassUID))
	}
	if q.CategoryUID != nil {
		delete = delete.Where(event.CategoryUID(*q.CategoryUID))
	}
	if q.TypeUID != nil {
		delete = delete.Where(event.TypeUID(*q.TypeUID))
	}
	if q.ActivityID != nil {
		delete = delete.Where(event.ActivityID(*q.ActivityID))
	}
	if q.SeverityID != nil {
		delete = delete.Where(event.SeverityID(*q.SeverityID))
	}
	if q.StatusID != nil {
		delete = delete.Where(event.StatusID(*q.StatusID))
	}
	if q.Source != nil {
		delete = delete.Where(event.Source(*q.Source))
	}
	if q.TimeFrom != nil {
		delete = delete.Where(event.TimeGTE(*q.TimeFrom))
	}
	if q.TimeTo != nil {
		delete = delete.Where(event.TimeLTE(*q.TimeTo))
	}

	count, err := delete.Exec(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to delete events: %w", err)
	}

	return count, nil
}

// Close closes the storage connection.
func (s *EntStorage) Close() error {
	return s.client.Close()
}

// Client returns the underlying Ent client for advanced operations.
func (s *EntStorage) Client() *ent.Client {
	return s.client
}

// buildQuery creates an Ent query with the given filters.
func (s *EntStorage) buildQuery(q *Query) *ent.EventQuery {
	query := s.client.Event.Query()

	// Apply filters
	if q.ClassUID != nil {
		query = query.Where(event.ClassUID(*q.ClassUID))
	}
	if q.CategoryUID != nil {
		query = query.Where(event.CategoryUID(*q.CategoryUID))
	}
	if q.TypeUID != nil {
		query = query.Where(event.TypeUID(*q.TypeUID))
	}
	if q.ActivityID != nil {
		query = query.Where(event.ActivityID(*q.ActivityID))
	}
	if q.SeverityID != nil {
		query = query.Where(event.SeverityID(*q.SeverityID))
	}
	if q.StatusID != nil {
		query = query.Where(event.StatusID(*q.StatusID))
	}
	if q.Source != nil {
		query = query.Where(event.Source(*q.Source))
	}
	if q.TimeFrom != nil {
		query = query.Where(event.TimeGTE(*q.TimeFrom))
	}
	if q.TimeTo != nil {
		query = query.Where(event.TimeLTE(*q.TimeTo))
	}

	return query
}

// entEventToStoredEvent converts an Ent Event to a StoredEvent.
func entEventToStoredEvent(e *ent.Event) *ocsf.StoredEvent {
	return &ocsf.StoredEvent{
		ID:            e.ID,
		ClassUID:      e.ClassUID,
		CategoryUID:   e.CategoryUID,
		ActivityID:    e.ActivityID,
		TypeUID:       e.TypeUID,
		SeverityID:    e.SeverityID,
		StatusID:      e.StatusID,
		Time:          e.Time,
		IngestedAt:    e.IngestedAt,
		Source:        e.Source,
		SchemaVersion: e.SchemaVersion,
		Payload:       e.Payload,
		RawData:       e.RawData,
	}
}

// Helper functions for optional fields
func intPtr(v int) *int {
	if v == 0 {
		return nil
	}
	return &v
}

func strPtr(v string) *string {
	if v == "" {
		return nil
	}
	return &v
}

// Ensure EntStorage implements Storage interface.
var _ Storage = (*EntStorage)(nil)

// StoredEventFromPayload creates a StoredEvent from a raw JSON payload.
func StoredEventFromPayload(id string, payload map[string]any, source, schemaVersion string) *ocsf.StoredEvent {
	ev := &ocsf.StoredEvent{
		ID:            id,
		IngestedAt:    time.Now(),
		Source:        source,
		SchemaVersion: schemaVersion,
		Payload:       payload,
	}

	// Extract classification fields from payload
	if v, ok := payload["class_uid"].(float64); ok {
		ev.ClassUID = int(v)
	}
	if v, ok := payload["category_uid"].(float64); ok {
		ev.CategoryUID = int(v)
	}
	if v, ok := payload["activity_id"].(float64); ok {
		ev.ActivityID = int(v)
	}
	if v, ok := payload["type_uid"].(float64); ok {
		ev.TypeUID = int(v)
	}
	if v, ok := payload["severity_id"].(float64); ok {
		ev.SeverityID = int(v)
	}
	if v, ok := payload["status_id"].(float64); ok {
		ev.StatusID = int(v)
	}
	if v, ok := payload["time"].(float64); ok {
		ev.Time = int64(v)
	}

	return ev
}
