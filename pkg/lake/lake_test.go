package lake_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/grokify/ocsf-lake/pkg/lake"
	"github.com/grokify/ocsf-lake/pkg/ocsf"
	"github.com/grokify/ocsf-lake/pkg/storage"

	_ "github.com/mattn/go-sqlite3" // SQLite driver
)

// Sample OCSF Authentication event
var sampleAuthEvent = `{
	"class_uid": 3002,
	"class_name": "Authentication",
	"category_uid": 3,
	"activity_id": 1,
	"type_uid": 300201,
	"severity_id": 1,
	"status_id": 1,
	"time": 1704067200000,
	"message": "User john.doe logged in successfully",
	"metadata": {
		"version": "1.3.0",
		"product": {
			"name": "test-system",
			"vendor_name": "Test Vendor"
		}
	}
}`

func TestLakeIngestAndQuery(t *testing.T) {
	ctx := context.Background()

	// Create lake with in-memory SQLite
	l, err := lake.New(ctx, lake.WithSQLiteMemory())
	if err != nil {
		t.Fatalf("failed to create lake: %v", err)
	}
	defer l.Close()

	// Ingest an event
	err = l.Ingest(ctx, json.RawMessage(sampleAuthEvent))
	if err != nil {
		t.Fatalf("failed to ingest event: %v", err)
	}

	// Query by class UID
	events, err := l.QueryByClassUID(ctx, ocsf.ClassUIDAuthentication)
	if err != nil {
		t.Fatalf("failed to query events: %v", err)
	}

	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	// Verify event fields
	event := events[0]
	if event.ClassUID != ocsf.ClassUIDAuthentication {
		t.Errorf("expected class_uid %d, got %d", ocsf.ClassUIDAuthentication, event.ClassUID)
	}
	if event.CategoryUID != ocsf.CategoryUIDIAMActivity {
		t.Errorf("expected category_uid %d, got %d", ocsf.CategoryUIDIAMActivity, event.CategoryUID)
	}
	if event.TypeUID != 300201 {
		t.Errorf("expected type_uid 300201, got %d", event.TypeUID)
	}
	if event.Source != "test-system" {
		t.Errorf("expected source 'test-system', got '%s'", event.Source)
	}
}

func TestLakeQueryBuilder(t *testing.T) {
	ctx := context.Background()

	l, err := lake.New(ctx, lake.WithSQLiteMemory())
	if err != nil {
		t.Fatalf("failed to create lake: %v", err)
	}
	defer l.Close()

	// Ingest multiple events
	events := []string{
		`{"class_uid": 3002, "category_uid": 3, "activity_id": 1, "type_uid": 300201, "time": 1704067200000, "severity_id": 1}`,
		`{"class_uid": 3002, "category_uid": 3, "activity_id": 2, "type_uid": 300202, "time": 1704067300000, "severity_id": 2}`,
		`{"class_uid": 4001, "category_uid": 4, "activity_id": 1, "type_uid": 400101, "time": 1704067400000, "severity_id": 4}`,
	}

	for _, e := range events {
		err = l.Ingest(ctx, json.RawMessage(e))
		if err != nil {
			t.Fatalf("failed to ingest event: %v", err)
		}
	}

	// Query by category
	q := l.QueryBuilder().
		WithCategoryUID(ocsf.CategoryUIDIAMActivity).
		Build()

	results, err := l.Query(ctx, q)
	if err != nil {
		t.Fatalf("failed to query: %v", err)
	}
	if len(results) != 2 {
		t.Errorf("expected 2 IAM events, got %d", len(results))
	}

	// Query by severity
	q = l.QueryBuilder().
		WithSeverityID(ocsf.SeverityIDHigh).
		Build()

	results, err = l.Query(ctx, q)
	if err != nil {
		t.Fatalf("failed to query: %v", err)
	}
	if len(results) != 1 {
		t.Errorf("expected 1 high severity event, got %d", len(results))
	}
}

func TestLakeCount(t *testing.T) {
	ctx := context.Background()

	l, err := lake.New(ctx, lake.WithSQLiteMemory())
	if err != nil {
		t.Fatalf("failed to create lake: %v", err)
	}
	defer l.Close()

	// Ingest events
	for i := 0; i < 5; i++ {
		event := `{"class_uid": 3002, "category_uid": 3, "activity_id": 1, "type_uid": 300201, "time": 1704067200000}`
		err = l.Ingest(ctx, json.RawMessage(event))
		if err != nil {
			t.Fatalf("failed to ingest event: %v", err)
		}
	}

	// Count all
	count, err := l.Count(ctx, &storage.Query{})
	if err != nil {
		t.Fatalf("failed to count: %v", err)
	}
	if count != 5 {
		t.Errorf("expected count 5, got %d", count)
	}
}

func TestLakeDelete(t *testing.T) {
	ctx := context.Background()

	l, err := lake.New(ctx, lake.WithSQLiteMemory())
	if err != nil {
		t.Fatalf("failed to create lake: %v", err)
	}
	defer l.Close()

	// Ingest events
	err = l.Ingest(ctx, json.RawMessage(`{"class_uid": 3002, "category_uid": 3, "activity_id": 1, "type_uid": 300201, "time": 1704067200000}`))
	if err != nil {
		t.Fatalf("failed to ingest: %v", err)
	}

	// Delete by class
	deleted, err := l.Delete(ctx, l.QueryBuilder().WithClassUID(ocsf.ClassUIDAuthentication).Build())
	if err != nil {
		t.Fatalf("failed to delete: %v", err)
	}
	if deleted != 1 {
		t.Errorf("expected 1 deleted, got %d", deleted)
	}

	// Verify deletion
	count, _ := l.Count(ctx, &storage.Query{})
	if count != 0 {
		t.Errorf("expected 0 events after deletion, got %d", count)
	}
}

func TestLakeValidation(t *testing.T) {
	ctx := context.Background()

	// Test strict validation
	l, err := lake.New(ctx, lake.WithSQLiteMemory(), lake.WithStrictValidation())
	if err != nil {
		t.Fatalf("failed to create lake: %v", err)
	}
	defer l.Close()

	// Invalid event (missing required fields)
	invalidEvent := `{"message": "invalid event"}`
	err = l.Ingest(ctx, json.RawMessage(invalidEvent))
	if err == nil {
		t.Error("expected validation error for invalid event")
	}

	// Valid event should succeed
	err = l.Ingest(ctx, json.RawMessage(sampleAuthEvent))
	if err != nil {
		t.Errorf("expected valid event to succeed: %v", err)
	}
}

func TestLakePermissiveValidation(t *testing.T) {
	ctx := context.Background()

	// Test permissive validation
	l, err := lake.New(ctx, lake.WithSQLiteMemory(), lake.WithPermissiveValidation())
	if err != nil {
		t.Fatalf("failed to create lake: %v", err)
	}
	defer l.Close()

	// Event with minimal fields should still work with permissive mode
	minimalEvent := `{"class_uid": 3002, "category_uid": 3, "activity_id": 1, "type_uid": 300201, "time": 1704067200000}`
	err = l.Ingest(ctx, json.RawMessage(minimalEvent))
	if err != nil {
		t.Errorf("expected minimal event to succeed in permissive mode: %v", err)
	}
}

func TestLakeIngestWithID(t *testing.T) {
	ctx := context.Background()

	l, err := lake.New(ctx, lake.WithSQLiteMemory())
	if err != nil {
		t.Fatalf("failed to create lake: %v", err)
	}
	defer l.Close()

	// Ingest with specific ID
	customID := "custom-event-id-123"
	err = l.IngestWithID(ctx, customID, json.RawMessage(sampleAuthEvent))
	if err != nil {
		t.Fatalf("failed to ingest with ID: %v", err)
	}

	// Retrieve by ID
	event, err := l.Get(ctx, customID)
	if err != nil {
		t.Fatalf("failed to get event: %v", err)
	}
	if event.ID != customID {
		t.Errorf("expected ID '%s', got '%s'", customID, event.ID)
	}
}
