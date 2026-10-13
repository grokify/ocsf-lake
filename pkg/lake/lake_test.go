package lake_test

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"github.com/grokify/ocsf-lake/pkg/lake"
	"github.com/grokify/ocsf-lake/pkg/storage"
	"github.com/grokify/ocsf-schema-go/ocsf/events"
	"github.com/grokify/ocsf-schema-go/ocsf/objects"
	"github.com/grokify/ocsf-schema-go/validate"

	_ "github.com/mattn/go-sqlite3" // SQLite driver
)

// Sample OCSF Authentication event, valid under strict schema validation.
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
	},
	"user": {"name": "john.doe", "type_id": 1},
	"dst_endpoint": {"hostname": "auth.example.com"}
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
	results, err := l.QueryByClassUID(ctx, events.ClassUIDAuthentication)
	if err != nil {
		t.Fatalf("failed to query events: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 event, got %d", len(results))
	}

	// Verify event fields
	event := results[0]
	if event.ClassUID != events.ClassUIDAuthentication {
		t.Errorf("expected class_uid %d, got %d", events.ClassUIDAuthentication, event.ClassUID)
	}
	if event.CategoryUID != events.CategoryUIDIAM {
		t.Errorf("expected category_uid %d, got %d", events.CategoryUIDIAM, event.CategoryUID)
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

	// Permissive mode: these fixtures are intentionally minimal (querying is
	// under test, not schema completeness).
	l, err := lake.New(ctx, lake.WithSQLiteMemory(), lake.WithPermissiveValidation())
	if err != nil {
		t.Fatalf("failed to create lake: %v", err)
	}
	defer l.Close()

	// Ingest multiple events
	payloads := []string{
		`{"class_uid": 3002, "category_uid": 3, "activity_id": 1, "type_uid": 300201, "time": 1704067200000, "severity_id": 1}`,
		`{"class_uid": 3002, "category_uid": 3, "activity_id": 2, "type_uid": 300202, "time": 1704067300000, "severity_id": 2}`,
		`{"class_uid": 4001, "category_uid": 4, "activity_id": 1, "type_uid": 400101, "time": 1704067400000, "severity_id": 4}`,
	}

	for _, e := range payloads {
		err = l.Ingest(ctx, json.RawMessage(e))
		if err != nil {
			t.Fatalf("failed to ingest event: %v", err)
		}
	}

	// Query by category
	q := l.QueryBuilder().
		WithCategoryUID(events.CategoryUIDIAM).
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
		WithSeverityID(events.SeverityIDHigh).
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

	l, err := lake.New(ctx, lake.WithSQLiteMemory(), lake.WithPermissiveValidation())
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

	l, err := lake.New(ctx, lake.WithSQLiteMemory(), lake.WithPermissiveValidation())
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
	deleted, err := l.Delete(ctx, l.QueryBuilder().WithClassUID(events.ClassUIDAuthentication).Build())
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

// TestLakeIngestTypedAndDecode round-trips a generated ocsf-schema-go event
// struct through the lake: typed ingest -> strict validation -> storage ->
// query -> decode back to the concrete type via the class-UID registry.
func TestLakeIngestTypedAndDecode(t *testing.T) {
	ctx := context.Background()

	l, err := lake.New(ctx, lake.WithSQLiteMemory())
	if err != nil {
		t.Fatalf("failed to create lake: %v", err)
	}
	defer l.Close()

	evt := events.Authentication{
		ActivityID:  events.AuthenticationActivityIDLogon,
		CategoryUID: events.CategoryUIDIAM,
		ClassUID:    events.ClassUIDAuthentication,
		SeverityID:  events.SeverityIDInformational,
		Time:        1704067200000,
		TypeUID:     int64(events.ClassUIDAuthentication)*100 + events.AuthenticationActivityIDLogon,
		Metadata: &objects.Metadata{
			Version: events.SchemaVersion,
			Product: &objects.Product{Name: "typed-producer"},
		},
		User:        &objects.User{Name: "jdoe", TypeID: objects.UserTypeIDUser},
		DstEndpoint: &objects.NetworkEndpoint{Hostname: "auth.example.com"},
	}

	if err := l.IngestTyped(ctx, evt); err != nil {
		t.Fatalf("failed to ingest typed event: %v", err)
	}

	results, err := l.QueryByClassUID(ctx, events.ClassUIDAuthentication)
	if err != nil {
		t.Fatalf("failed to query: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 event, got %d", len(results))
	}
	if results[0].Source != "typed-producer" {
		t.Errorf("source = %q, want typed-producer (from metadata.product.name)", results[0].Source)
	}

	decoded, err := results[0].Decode()
	if err != nil {
		t.Fatalf("failed to decode stored event: %v", err)
	}
	auth, ok := decoded.(*events.Authentication)
	if !ok {
		t.Fatalf("Decode returned %T, want *events.Authentication", decoded)
	}
	if auth.User == nil || auth.User.Name != "jdoe" {
		t.Errorf("decoded user = %+v, want jdoe", auth.User)
	}
	if auth.ActivityID != events.AuthenticationActivityIDLogon {
		t.Errorf("decoded activity = %d, want Logon", auth.ActivityID)
	}
}

// TestUnknownAttributesOption: strict mode tolerates unknown attributes by
// default (warning) but rejects them under validate.UnknownError.
func TestUnknownAttributesOption(t *testing.T) {
	ctx := context.Background()
	withBogus := json.RawMessage(strings.Replace(sampleAuthEvent, `"status_id": 1,`, `"status_id": 1, "bogus_field": 1,`, 1))

	l, err := lake.New(ctx, lake.WithSQLiteMemory())
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if err := l.Ingest(ctx, withBogus); err != nil {
		t.Errorf("default (warn) should accept unknown attributes: %v", err)
	}

	strict, err := lake.New(ctx, lake.WithSQLiteMemory(), lake.WithUnknownAttributes(validate.UnknownError))
	if err != nil {
		t.Fatal(err)
	}
	defer strict.Close()
	if err := strict.Ingest(ctx, withBogus); err == nil {
		t.Error("UnknownError mode should reject unknown attributes")
	} else if !strings.Contains(err.Error(), "event 1 of 1") {
		t.Errorf("batch error should carry event position, got: %v", err)
	}
}

// TestCloseIsIdempotentAndConcurrencySafe covers the closed-flag atomicity.
func TestCloseIsIdempotentAndConcurrencySafe(t *testing.T) {
	ctx := context.Background()
	l, err := lake.New(ctx, lake.WithSQLiteMemory())
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = l.Close()
			_, _ = l.Count(ctx, &storage.Query{})
		}()
	}
	wg.Wait()

	if err := l.Close(); err != nil {
		t.Errorf("second Close = %v, want nil", err)
	}
	if _, err := l.Count(ctx, &storage.Query{}); err == nil {
		t.Error("Count after Close should return ErrClosed")
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
