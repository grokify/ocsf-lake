package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// Event holds the schema definition for the OCSF Event entity.
type Event struct {
	ent.Schema
}

// Fields of the Event.
func (Event) Fields() []ent.Field {
	return []ent.Field{
		// Storage identifier (UUID)
		field.String("id").
			Unique().
			Immutable().
			Comment("Unique storage identifier for the event"),

		// OCSF classification fields (indexed for queries)
		field.Int("class_uid").
			NonNegative().
			Comment("OCSF event class identifier"),
		field.Int("category_uid").
			NonNegative().
			Comment("OCSF event category identifier"),
		field.Int("activity_id").
			NonNegative().
			Comment("OCSF activity identifier"),
		field.Int("type_uid").
			NonNegative().
			Comment("OCSF event type identifier (class_uid * 100 + activity_id)"),
		field.Int("severity_id").
			Optional().
			NonNegative().
			Comment("OCSF severity level"),
		field.Int("status_id").
			Optional().
			NonNegative().
			Comment("OCSF event status"),

		// Time fields
		field.Int64("time").
			Comment("OCSF event time in epoch milliseconds"),
		field.Time("ingested_at").
			Default(time.Now).
			Immutable().
			Comment("Timestamp when the event was ingested into the lake"),

		// Source tracking
		field.String("source").
			Default("unknown").
			Comment("Source system that produced the event (e.g., 'aws-cloudtrail')"),
		field.String("schema_version").
			Default("1.3.0").
			Comment("OCSF schema version used for this event"),

		// Full event payload (stored as JSON)
		field.JSON("payload", map[string]any{}).
			Comment("Full OCSF event payload as JSON"),

		// Raw original event (optional)
		field.Text("raw_data").
			Optional().
			Comment("Original raw event data before OCSF transformation"),
	}
}

// Indexes of the Event.
func (Event) Indexes() []ent.Index {
	return []ent.Index{
		// Primary query patterns
		index.Fields("class_uid", "time"),
		index.Fields("category_uid", "time"),
		index.Fields("type_uid", "time"),

		// Source-based queries
		index.Fields("source", "time"),

		// Severity-based queries (for alerts/prioritization)
		index.Fields("severity_id"),

		// Status-based queries
		index.Fields("status_id"),

		// Time-range queries
		index.Fields("time"),
		index.Fields("ingested_at"),
	}
}

// Edges of the Event.
func (Event) Edges() []ent.Edge {
	return nil // No edges for now; events are standalone
}
