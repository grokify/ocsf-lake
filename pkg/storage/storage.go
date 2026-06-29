// Package storage provides the storage interface and implementations for OCSF events.
package storage

import (
	"context"
	"errors"

	"github.com/grokify/ocsf-lake/pkg/ocsf"
)

// Common storage errors.
var (
	ErrNotFound         = errors.New("event not found")
	ErrDuplicateID      = errors.New("duplicate event ID")
	ErrConnectionFailed = errors.New("storage connection failed")
)

// Storage defines the interface for OCSF event storage.
type Storage interface {
	// Insert stores one or more events.
	// Events must have unique IDs; duplicate IDs return ErrDuplicateID.
	Insert(ctx context.Context, events ...*ocsf.StoredEvent) error

	// Get retrieves a single event by ID.
	// Returns ErrNotFound if the event does not exist.
	Get(ctx context.Context, id string) (*ocsf.StoredEvent, error)

	// Query retrieves events matching the query parameters.
	Query(ctx context.Context, q *Query) ([]*ocsf.StoredEvent, error)

	// Count returns the number of events matching the query parameters.
	Count(ctx context.Context, q *Query) (int, error)

	// Delete removes events matching the query parameters.
	// Returns the number of deleted events.
	Delete(ctx context.Context, q *Query) (int, error)

	// Close closes the storage connection.
	Close() error
}

// Query specifies filters for querying events.
type Query struct {
	// Classification filters
	ClassUID    *int
	CategoryUID *int
	TypeUID     *int
	ActivityID  *int
	SeverityID  *int
	StatusID    *int

	// Source filter
	Source *string

	// Time range filters (epoch milliseconds)
	TimeFrom *int64
	TimeTo   *int64

	// Pagination
	Limit  int
	Offset int

	// Ordering
	OrderBy   string // field name
	OrderDesc bool   // descending order
}

// QueryBuilder provides a fluent interface for building queries.
type QueryBuilder struct {
	query Query
}

// NewQuery creates a new QueryBuilder.
func NewQuery() *QueryBuilder {
	return &QueryBuilder{
		query: Query{
			Limit: 100, // default limit
		},
	}
}

// WithClassUID filters by class_uid.
func (qb *QueryBuilder) WithClassUID(uid int) *QueryBuilder {
	qb.query.ClassUID = &uid
	return qb
}

// WithCategoryUID filters by category_uid.
func (qb *QueryBuilder) WithCategoryUID(uid int) *QueryBuilder {
	qb.query.CategoryUID = &uid
	return qb
}

// WithTypeUID filters by type_uid.
func (qb *QueryBuilder) WithTypeUID(uid int) *QueryBuilder {
	qb.query.TypeUID = &uid
	return qb
}

// WithActivityID filters by activity_id.
func (qb *QueryBuilder) WithActivityID(id int) *QueryBuilder {
	qb.query.ActivityID = &id
	return qb
}

// WithSeverityID filters by severity_id.
func (qb *QueryBuilder) WithSeverityID(id int) *QueryBuilder {
	qb.query.SeverityID = &id
	return qb
}

// WithStatusID filters by status_id.
func (qb *QueryBuilder) WithStatusID(id int) *QueryBuilder {
	qb.query.StatusID = &id
	return qb
}

// WithSource filters by source.
func (qb *QueryBuilder) WithSource(source string) *QueryBuilder {
	qb.query.Source = &source
	return qb
}

// WithTimeRange filters by time range.
func (qb *QueryBuilder) WithTimeRange(from, to int64) *QueryBuilder {
	qb.query.TimeFrom = &from
	qb.query.TimeTo = &to
	return qb
}

// WithTimeFrom filters by minimum time.
func (qb *QueryBuilder) WithTimeFrom(from int64) *QueryBuilder {
	qb.query.TimeFrom = &from
	return qb
}

// WithTimeTo filters by maximum time.
func (qb *QueryBuilder) WithTimeTo(to int64) *QueryBuilder {
	qb.query.TimeTo = &to
	return qb
}

// WithLimit sets the maximum number of results.
func (qb *QueryBuilder) WithLimit(limit int) *QueryBuilder {
	qb.query.Limit = limit
	return qb
}

// WithOffset sets the result offset for pagination.
func (qb *QueryBuilder) WithOffset(offset int) *QueryBuilder {
	qb.query.Offset = offset
	return qb
}

// OrderByTime orders results by event time.
func (qb *QueryBuilder) OrderByTime(desc bool) *QueryBuilder {
	qb.query.OrderBy = "time"
	qb.query.OrderDesc = desc
	return qb
}

// OrderByIngestedAt orders results by ingestion time.
func (qb *QueryBuilder) OrderByIngestedAt(desc bool) *QueryBuilder {
	qb.query.OrderBy = "ingested_at"
	qb.query.OrderDesc = desc
	return qb
}

// Build returns the constructed Query.
func (qb *QueryBuilder) Build() *Query {
	return &qb.query
}
