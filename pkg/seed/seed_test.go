package seed_test

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/grokify/ocsf-lake/pkg/integrity"
	"github.com/grokify/ocsf-lake/pkg/lake"
	"github.com/grokify/ocsf-lake/pkg/seed"
	"github.com/grokify/ocsf-schema-go/ocsf/ocsfdata"
	"github.com/grokify/ocsf-schema-go/validate"

	_ "github.com/mattn/go-sqlite3" // SQLite driver
)

// TestGeneratedEventsValidateStrict is the core guarantee: every event every
// template produces passes strict schema validation.
func TestGeneratedEventsValidateStrict(t *testing.T) {
	res, err := seed.Generate(seed.Config{Events: 400, Seed: 7})
	if err != nil {
		t.Fatal(err)
	}
	v := validate.New(ocsfdata.MustSchema())
	classesSeen := map[string]bool{}
	for _, ev := range res.Events {
		classesSeen[ev.Class] = true
		r := v.ValidateEvent(ev.JSON)
		if !r.Valid() {
			t.Fatalf("%s event %s fails strict validation: %v\npayload: %s", ev.Class, ev.ID, r.Errors(), ev.JSON)
		}
	}
	if len(classesSeen) != 8 {
		t.Errorf("expected all 8 class templates in 400 events, saw %d: %v", len(classesSeen), classesSeen)
	}
}

func TestGenerateDeterministicContent(t *testing.T) {
	cfg := seed.Config{Events: 50, Seed: 42, Start: time.UnixMilli(1704067200000)}
	a, err := seed.Generate(cfg)
	if err != nil {
		t.Fatal(err)
	}
	b, err := seed.Generate(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for i := range a.Events {
		if !bytes.Equal(a.Events[i].JSON, b.Events[i].JSON) {
			t.Fatalf("event %d differs across identical configs", i)
		}
		if a.Events[i].Class != b.Events[i].Class || a.Events[i].UID != b.Events[i].UID {
			t.Fatalf("event %d metadata differs across identical configs", i)
		}
	}
}

// TestSeededLakeMatchesGroundTruth populates a lake with a signed/tampered/
// unsigned mix and asserts the integrity checker reproduces the generator's
// ground-truth counts exactly.
func TestSeededLakeMatchesGroundTruth(t *testing.T) {
	ctx := context.Background()
	res, err := seed.Generate(seed.Config{
		Events:    200,
		Seed:      11,
		SignedPct: 60,
		TamperPct: 10,
		Chains:    2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Tampered == 0 || res.Unsigned == 0 || res.Signed == 0 {
		t.Fatalf("mix degenerate: signed %d tampered %d unsigned %d", res.Signed, res.Tampered, res.Unsigned)
	}

	l, err := lake.New(ctx, lake.WithSQLiteMemory())
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if err := res.Populate(ctx, l); err != nil {
		t.Fatal(err)
	}

	report, err := l.IntegrityChecker(res.Authority.Policy()).CheckAll(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if report.Checked != 200 {
		t.Errorf("checked %d, want 200", report.Checked)
	}
	if report.Verified != res.Signed {
		t.Errorf("verified %d, want %d", report.Verified, res.Signed)
	}
	if report.Failed != res.Tampered {
		t.Errorf("failed %d, want %d (tampered)", report.Failed, res.Tampered)
	}
	if report.Unsigned != res.Unsigned {
		t.Errorf("unsigned %d, want %d", report.Unsigned, res.Unsigned)
	}

	// Both chains verify end to end.
	for _, chainUID := range res.ChainUIDs {
		cr, err := l.IntegrityChecker(res.Authority.Policy()).CheckChain(ctx, chainUID)
		if err != nil {
			t.Fatal(err)
		}
		if cr.Report.Checked != 10 || cr.Report.Failed != 0 || cr.Heads != 1 {
			t.Errorf("chain %s = checked %d failed %d heads %d, want 10/0/1",
				chainUID, cr.Report.Checked, cr.Report.Failed, cr.Heads)
		}
	}
}

func TestBreakChain(t *testing.T) {
	ctx := context.Background()
	res, err := seed.Generate(seed.Config{
		Events:      40,
		Seed:        3,
		Chains:      1,
		ChainLength: 8,
		BreakChain:  true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Tampered != 1 {
		t.Fatalf("BreakChain should tamper exactly one event, got %d", res.Tampered)
	}

	l, err := lake.New(ctx, lake.WithSQLiteMemory())
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if err := res.Populate(ctx, l); err != nil {
		t.Fatal(err)
	}

	cr, err := l.IntegrityChecker(res.Authority.Policy()).CheckChain(ctx, res.ChainUIDs[0])
	if err != nil {
		t.Fatal(err)
	}
	// The corrupted link fails its own signature check, and its successor's
	// prev_event fingerprint no longer matches.
	if cr.Report.Failed < 2 {
		t.Errorf("broken chain failed = %d, want >= 2 (tampered link + broken successor link): %+v",
			cr.Report.Failed, cr.Report.Failures)
	}
}

func TestSampleAndIncrementalOverSeededData(t *testing.T) {
	ctx := context.Background()
	res, err := seed.Generate(seed.Config{Events: 300, Seed: 5, SignedPct: 100})
	if err != nil {
		t.Fatal(err)
	}
	l, err := lake.New(ctx, lake.WithSQLiteMemory())
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if err := res.Populate(ctx, l); err != nil {
		t.Fatal(err)
	}
	checker := l.IntegrityChecker(res.Authority.Policy())

	sample, err := checker.CheckSample(ctx, integrity.SamplePolicy{Percent: 10, Seed: 9})
	if err != nil {
		t.Fatal(err)
	}
	if sample.Checked != 30 || sample.Verified != 30 {
		t.Errorf("10%% sample of 300 = checked %d verified %d, want 30/30", sample.Checked, sample.Verified)
	}

	incr, _, err := checker.CheckIncremental(ctx, integrity.Checkpoint{})
	if err != nil {
		t.Fatal(err)
	}
	if incr.Checked != 300 {
		t.Errorf("incremental from zero = %d, want 300", incr.Checked)
	}
}

func TestNDJSON(t *testing.T) {
	res, err := seed.Generate(seed.Config{Events: 5, Seed: 2})
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := res.NDJSON(&buf); err != nil {
		t.Fatal(err)
	}
	if lines := bytes.Count(buf.Bytes(), []byte("\n")); lines != 5 {
		t.Errorf("NDJSON lines = %d, want 5", lines)
	}
}
