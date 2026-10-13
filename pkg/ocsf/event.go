// Package ocsf provides the storage-side representation of OCSF events for
// the lake.
//
// The OCSF standard itself — generated event/object structs, classification
// constants, caption maps, and the class-UID registry — lives in
// github.com/grokify/ocsf-schema-go (ocsf/events, ocsf/objects). This package
// only holds what is specific to storing events in a data lake.
package ocsf

import (
	"encoding/json"
	"time"

	"github.com/grokify/ocsf-schema-go/ocsf/events"
)

// StoredEvent represents an OCSF event as stored in the data lake.
// It includes the original payload plus storage metadata.
type StoredEvent struct {
	// Storage identifier
	ID string `json:"id"`

	// OCSF classification fields (indexed)
	ClassUID    int `json:"class_uid"`
	CategoryUID int `json:"category_uid"`
	ActivityID  int `json:"activity_id"`
	TypeUID     int `json:"type_uid"`
	SeverityID  int `json:"severity_id,omitempty"`
	StatusID    int `json:"status_id,omitempty"`

	// Time fields
	Time       int64     `json:"time"`        // OCSF event time (epoch ms)
	IngestedAt time.Time `json:"ingested_at"` // When we received it

	// Source tracking
	Source        string `json:"source"`
	SchemaVersion string `json:"schema_version"`

	// Full event payload
	Payload map[string]any `json:"payload"`

	// Raw original event (optional)
	RawData string `json:"raw_data,omitempty"`

	// Record-integrity check state (optional; maintained by the integrity
	// checker and by verify-on-ingest)
	IntegrityStatus    string     `json:"integrity_status,omitempty"`
	IntegrityCheckedAt *time.Time `json:"integrity_checked_at,omitempty"`
}

// IntegrityCheckRecord is a persisted record-integrity check run: an audit
// trail of the checks themselves plus incremental checkpoint state.
type IntegrityCheckRecord struct {
	ID         string    `json:"id"`
	Kind       string    `json:"kind"` // event, all, incremental, sample, chain, ingest
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`

	Checked  int `json:"checked"`
	Verified int `json:"verified"`
	Unsigned int `json:"unsigned"`
	Failed   int `json:"failed"`

	// Checkpoint is the incremental checkpoint (ingested_after) reached by
	// this run, when the run was incremental.
	Checkpoint *time.Time `json:"checkpoint,omitempty"`

	// Report is the full check report as JSON-compatible data.
	Report map[string]any `json:"report,omitempty"`

	CreatedAt time.Time `json:"created_at"`
}

// Decode unmarshals the stored payload into the concrete generated event
// struct for its class (e.g. *events.Authentication for class_uid 3002),
// dispatching via the ocsf-schema-go class-UID registry.
func (e *StoredEvent) Decode() (any, error) {
	data, err := json.Marshal(e.Payload)
	if err != nil {
		return nil, err
	}
	return events.UnmarshalEvent(data)
}

// TimeAsTime converts the OCSF epoch millisecond timestamp to time.Time.
func (e *StoredEvent) TimeAsTime() time.Time {
	return time.UnixMilli(e.Time)
}

// ParsePayload parses a JSON payload into a generic map for storage.
func ParsePayload(data []byte) (map[string]any, error) {
	var payload map[string]any
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, err
	}
	return payload, nil
}

// CalculateTypeUID computes the type_uid from class_uid and activity_id.
// OCSF formula: type_uid = class_uid * 100 + activity_id
func CalculateTypeUID(classUID, activityID int) int {
	return classUID*100 + activityID
}

// ParseTypeUID extracts class_uid and activity_id from type_uid.
func ParseTypeUID(typeUID int) (classUID, activityID int) {
	classUID = typeUID / 100
	activityID = typeUID % 100
	return
}
