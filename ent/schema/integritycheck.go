package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// IntegrityCheck holds the schema definition for persisted record-integrity
// check reports: an audit trail of the checks themselves plus the incremental
// checkpoint state.
type IntegrityCheck struct {
	ent.Schema
}

// Fields of the IntegrityCheck.
func (IntegrityCheck) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			Unique().
			Immutable().
			Comment("Unique identifier of the check run"),
		field.String("kind").
			Comment("Check mode: event, all, incremental, sample, chain, ingest"),
		field.Time("started_at").
			Comment("When the check run started"),
		field.Time("finished_at").
			Comment("When the check run finished"),
		field.Int("checked").
			NonNegative().
			Comment("Number of events checked"),
		field.Int("verified").
			NonNegative().
			Comment("Number of events that verified"),
		field.Int("unsigned").
			NonNegative().
			Comment("Number of unsigned events (when the policy allows them)"),
		field.Int("failed").
			NonNegative().
			Comment("Number of events that failed"),
		field.Time("checkpoint").
			Optional().
			Nillable().
			Comment("Incremental checkpoint (ingested_after) reached by this run, if applicable"),
		field.JSON("report", map[string]any{}).
			Optional().
			Comment("Full check report (failures, unsigned events, issues)"),
		field.Time("created_at").
			Default(time.Now).
			Immutable().
			Comment("When this record was written"),
	}
}

// Indexes of the IntegrityCheck.
func (IntegrityCheck) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("kind", "finished_at"),
		index.Fields("finished_at"),
	}
}

// Edges of the IntegrityCheck.
func (IntegrityCheck) Edges() []ent.Edge {
	return nil
}
