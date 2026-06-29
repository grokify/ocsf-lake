// Package ocsf provides Go types for OCSF (Open Cybersecurity Schema Framework) events.
package ocsf

import (
	"encoding/json"
	"time"
)

// Event represents the base OCSF event structure with common fields
// shared across all event classes.
type Event struct {
	// Classification (required)
	ClassUID    int    `json:"class_uid"`
	ClassName   string `json:"class_name,omitempty"`
	CategoryUID int    `json:"category_uid"`
	ActivityID  int    `json:"activity_id"`
	TypeUID     int    `json:"type_uid"`
	TypeName    string `json:"type_name,omitempty"`

	// Severity
	SeverityID int    `json:"severity_id,omitempty"`
	Severity   string `json:"severity,omitempty"`

	// Time (required - epoch milliseconds)
	Time      int64 `json:"time"`
	StartTime int64 `json:"start_time,omitempty"`
	EndTime   int64 `json:"end_time,omitempty"`
	Duration  int64 `json:"duration,omitempty"`
	Timezone  int   `json:"timezone_offset,omitempty"`

	// Status
	StatusID     int    `json:"status_id,omitempty"`
	Status       string `json:"status,omitempty"`
	StatusCode   string `json:"status_code,omitempty"`
	StatusDetail string `json:"status_detail,omitempty"`

	// Content
	Message  string         `json:"message,omitempty"`
	Metadata *EventMetadata `json:"metadata,omitempty"`

	// Raw data
	RawData     string `json:"raw_data,omitempty"`
	RawDataHash string `json:"raw_data_hash,omitempty"`

	// Counts
	Count int `json:"count,omitempty"`

	// Observables and enrichments
	Observables []any `json:"observables,omitempty"`
	Enrichments []any `json:"enrichments,omitempty"`

	// Extensibility
	Unmapped map[string]any `json:"unmapped,omitempty"`
}

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
}

// ParseEvent parses a JSON payload into a base Event structure.
// It extracts only the common OCSF fields; class-specific fields
// remain in the original JSON.
func ParseEvent(data []byte) (*Event, error) {
	var event Event
	if err := json.Unmarshal(data, &event); err != nil {
		return nil, err
	}
	return &event, nil
}

// ParsePayload parses a JSON payload into a generic map for storage.
func ParsePayload(data []byte) (map[string]any, error) {
	var payload map[string]any
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, err
	}
	return payload, nil
}

// TimeAsTime converts the OCSF epoch millisecond timestamp to time.Time.
func (e *Event) TimeAsTime() time.Time {
	return time.UnixMilli(e.Time)
}

// StartTimeAsTime converts the OCSF start_time epoch millisecond timestamp to time.Time.
func (e *Event) StartTimeAsTime() time.Time {
	return time.UnixMilli(e.StartTime)
}

// EndTimeAsTime converts the OCSF end_time epoch millisecond timestamp to time.Time.
func (e *Event) EndTimeAsTime() time.Time {
	return time.UnixMilli(e.EndTime)
}
