// Package integrity runs record-integrity checks over events stored in the
// lake, using the cryptographic primitives of
// github.com/grokify/ocsf-schema-go/recordintegrity.
//
// Check modes:
//
//   - CheckEvent: one-off, on-demand check of a single stored event.
//   - CheckAll: full sweep of every stored event.
//   - CheckIncremental: everything ingested since a checkpoint; the caller
//     persists the returned checkpoint between runs.
//   - CheckSample: a random sample (percentage and/or fixed cap per run).
//   - CheckChain: end-to-end verification of one tamper-evident chain,
//     following prev_event links.
//
// RunPeriodicIncremental and RunPeriodicSample wrap the incremental and
// sample modes in a ticker loop for automated checking.
package integrity

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"time"

	"github.com/google/uuid"
	"github.com/grokify/ocsf-lake/pkg/ocsf"
	"github.com/grokify/ocsf-lake/pkg/storage"
	ri "github.com/grokify/ocsf-schema-go/recordintegrity"
)

// Outcome classifies one checked event.
type Outcome string

// Event check outcomes.
const (
	OutcomeVerified Outcome = "verified"
	OutcomeUnsigned Outcome = "unsigned"
	OutcomeFailed   Outcome = "failed"
)

// Policy configures how checked events are judged.
type Policy struct {
	// AllowUnsigned controls how events without attestations are treated:
	// true (the default) reports them under Report.Unsigned as warnings;
	// false counts them as failures.
	AllowUnsigned bool
	// Verify supplies the cryptographic verification inputs: candidate
	// signer certificates, trust roots or pinned fingerprints, and the
	// validity-check time. See recordintegrity.VerifyOptions.
	Verify ri.VerifyOptions
	// RecordReports persists a report for every CheckAll, CheckIncremental,
	// CheckSample, and CheckChain run (see Storage.SaveIntegrityReport),
	// building an audit trail of the checks themselves. CheckIncremental
	// checkpoints can then be resumed via ResumeIncremental.
	RecordReports bool
	// RecordEventStatus stamps integrity_status/integrity_checked_at on
	// every checked event.
	RecordEventStatus bool
}

// DefaultPolicy allows unsigned events (reported as warnings).
func DefaultPolicy() Policy {
	return Policy{AllowUnsigned: true}
}

// EventResult is the outcome of checking one stored event.
type EventResult struct {
	EventID  string     `json:"event_id"`
	ClassUID int        `json:"class_uid,omitempty"`
	Outcome  Outcome    `json:"outcome"`
	Status   ri.Status  `json:"status"`
	Issues   []ri.Issue `json:"issues,omitempty"`
}

// Report aggregates the results of one check run.
type Report struct {
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`

	Checked  int `json:"checked"`
	Verified int `json:"verified"`
	Unsigned int `json:"unsigned"` // only populated when Policy.AllowUnsigned
	Failed   int `json:"failed"`

	// Failures lists every event whose outcome was OutcomeFailed.
	Failures []EventResult `json:"failures,omitempty"`
	// UnsignedEvents lists unsigned events when Policy.AllowUnsigned is
	// true (they are warnings, not failures).
	UnsignedEvents []EventResult `json:"unsigned_events,omitempty"`
	// RecordingErrors lists persistence problems encountered while
	// recording per-event statuses or the report itself; they do not abort
	// a check run.
	RecordingErrors []string `json:"recording_errors,omitempty"`
}

func (r *Report) record(res EventResult) {
	r.Checked++
	switch res.Outcome {
	case OutcomeVerified:
		r.Verified++
	case OutcomeUnsigned:
		r.Unsigned++
		r.UnsignedEvents = append(r.UnsignedEvents, res)
	case OutcomeFailed:
		r.Failed++
		r.Failures = append(r.Failures, res)
	}
}

// Checkpoint marks how far incremental checking has progressed. Persist it
// between runs (it serializes to JSON).
type Checkpoint struct {
	// IngestedAfter is the ingestion timestamp of the last checked event;
	// the next incremental run checks events ingested strictly after it.
	IngestedAfter time.Time `json:"ingested_after"`
}

// SamplePolicy configures CheckSample.
type SamplePolicy struct {
	// Percent of matching events to check, 0–100. Zero with MaxEvents set
	// means "up to MaxEvents, chosen uniformly".
	Percent float64
	// MaxEvents caps the number of events checked per run; 0 means no cap.
	// A monthly budget of N events at a run cadence of once per day is
	// expressed as MaxEvents = N/30 (the checker itself is stateless
	// across runs).
	MaxEvents int
	// Seed makes selection deterministic when non-zero (used in tests).
	Seed int64
}

// Checker runs integrity checks against a storage backend.
type Checker struct {
	store  storage.Storage
	policy Policy
	// pageSize bounds storage reads per page during sweeps.
	pageSize int
}

// NewChecker creates a Checker over the given storage.
func NewChecker(store storage.Storage, policy Policy) *Checker {
	return &Checker{store: store, policy: policy, pageSize: 500}
}

// CheckStored checks a single already-loaded event against the policy.
func (c *Checker) CheckStored(ev *ocsf.StoredEvent) EventResult {
	payload, err := json.Marshal(ev.Payload)
	if err != nil {
		return EventResult{
			EventID: ev.ID, ClassUID: ev.ClassUID,
			Outcome: OutcomeFailed, Status: ri.StatusMalformed,
			Issues: []ri.Issue{{Status: ri.StatusMalformed, Message: err.Error()}},
		}
	}
	res := c.CheckJSON(ev.ID, payload)
	res.ClassUID = ev.ClassUID
	return res
}

// CheckJSON checks a raw event payload against the policy (used by
// CheckStored and by verify-on-ingest before an event is stored).
func (c *Checker) CheckJSON(id string, payload []byte) EventResult {
	res := EventResult{EventID: id}
	vr := ri.Verify(payload, c.policy.Verify)
	res.Status = vr.Status
	res.Issues = vr.Issues
	switch {
	case vr.Status == ri.StatusVerified:
		res.Outcome = OutcomeVerified
	case vr.Status == ri.StatusUnsigned && c.policy.AllowUnsigned:
		res.Outcome = OutcomeUnsigned
	default:
		res.Outcome = OutcomeFailed
	}
	return res
}

// checkAndRecord checks one stored event and, when configured, stamps its
// integrity status. Persistence problems are noted on the report without
// aborting the run.
func (c *Checker) checkAndRecord(ctx context.Context, ev *ocsf.StoredEvent, report *Report) EventResult {
	res := c.CheckStored(ev)
	if c.policy.RecordEventStatus {
		if err := c.store.SetEventIntegrity(ctx, ev.ID, string(res.Status), time.Now()); err != nil {
			report.RecordingErrors = append(report.RecordingErrors,
				fmt.Sprintf("event %s: %v", ev.ID, err))
		}
	}
	return res
}

// saveReport persists a check run when Policy.RecordReports is set.
func (c *Checker) saveReport(ctx context.Context, kind string, report *Report, checkpoint *time.Time) {
	if !c.policy.RecordReports {
		return
	}
	var reportMap map[string]any
	if data, err := json.Marshal(report); err == nil {
		if err := json.Unmarshal(data, &reportMap); err != nil {
			reportMap = nil
		}
	}
	rec := &ocsf.IntegrityCheckRecord{
		ID:         uuid.New().String(),
		Kind:       kind,
		StartedAt:  report.StartedAt,
		FinishedAt: report.FinishedAt,
		Checked:    report.Checked,
		Verified:   report.Verified,
		Unsigned:   report.Unsigned,
		Failed:     report.Failed,
		Checkpoint: checkpoint,
		Report:     reportMap,
	}
	if err := c.store.SaveIntegrityReport(ctx, rec); err != nil {
		report.RecordingErrors = append(report.RecordingErrors,
			fmt.Sprintf("saving %s report: %v", kind, err))
	}
}

// ResumeIncremental returns the checkpoint reached by the most recent
// persisted incremental run (zero Checkpoint if none exists), letting
// incremental checking survive restarts when Policy.RecordReports is on.
func (c *Checker) ResumeIncremental(ctx context.Context) (Checkpoint, error) {
	recs, err := c.store.ListIntegrityReports(ctx, "incremental", 1)
	if err != nil {
		return Checkpoint{}, err
	}
	if len(recs) == 0 || recs[0].Checkpoint == nil {
		return Checkpoint{}, nil
	}
	return Checkpoint{IngestedAfter: *recs[0].Checkpoint}, nil
}

// CheckEvent runs a one-off, on-demand check of one event by storage ID.
// The event's integrity status is stamped when Policy.RecordEventStatus is
// set.
func (c *Checker) CheckEvent(ctx context.Context, id string) (EventResult, error) {
	ev, err := c.store.Get(ctx, id)
	if err != nil {
		return EventResult{}, err
	}
	res := c.CheckStored(ev)
	if c.policy.RecordEventStatus {
		if err := c.store.SetEventIntegrity(ctx, ev.ID, string(res.Status), time.Now()); err != nil {
			return res, fmt.Errorf("integrity: recording event status: %w", err)
		}
	}
	return res, nil
}

// CheckAll sweeps every stored event.
func (c *Checker) CheckAll(ctx context.Context) (*Report, error) {
	report := &Report{StartedAt: time.Now()}
	err := c.sweep(ctx, nil, func(ev *ocsf.StoredEvent) {
		report.record(c.checkAndRecord(ctx, ev, report))
	})
	report.FinishedAt = time.Now()
	if err == nil {
		c.saveReport(ctx, "all", report, nil)
	}
	return report, err
}

// CheckIncremental checks every event ingested after the checkpoint and
// returns the advanced checkpoint for the caller to persist.
func (c *Checker) CheckIncremental(ctx context.Context, cp Checkpoint) (*Report, Checkpoint, error) {
	report := &Report{StartedAt: time.Now()}
	next := cp
	base := storage.Query{OrderBy: "ingested_at"}
	if !cp.IngestedAfter.IsZero() {
		t := cp.IngestedAfter
		base.IngestedFrom = &t
	}
	err := c.sweep(ctx, &base, func(ev *ocsf.StoredEvent) {
		report.record(c.checkAndRecord(ctx, ev, report))
		if ev.IngestedAt.After(next.IngestedAfter) {
			next.IngestedAfter = ev.IngestedAt
		}
	})
	report.FinishedAt = time.Now()
	if err == nil {
		var cp *time.Time
		if !next.IngestedAfter.IsZero() {
			t := next.IngestedAfter
			cp = &t
		}
		c.saveReport(ctx, "incremental", report, cp)
	}
	return report, next, err
}

// CheckSample checks a random sample of stored events per the sample policy.
func (c *Checker) CheckSample(ctx context.Context, sp SamplePolicy) (*Report, error) {
	report := &Report{StartedAt: time.Now()}
	seed := sp.Seed
	if seed == 0 {
		seed = time.Now().UnixNano()
	}
	rng := rand.New(rand.NewSource(seed)) //nolint:gosec // sampling, not crypto

	total, err := c.store.Count(ctx, &storage.Query{})
	if err != nil {
		return nil, err
	}
	target := total
	if sp.Percent > 0 {
		target = int(float64(total)*sp.Percent/100.0 + 0.5)
	}
	if sp.MaxEvents > 0 && target > sp.MaxEvents {
		target = sp.MaxEvents
	}
	if target <= 0 {
		report.FinishedAt = time.Now()
		return report, nil
	}

	// Uniform selection without replacement over [0, total).
	indices := rng.Perm(total)[:target]
	for _, idx := range indices {
		if err := ctx.Err(); err != nil {
			return report, err
		}
		page, err := c.store.Query(ctx, &storage.Query{
			OrderBy: "ingested_at", Limit: 1, Offset: idx,
		})
		if err != nil {
			return report, err
		}
		if len(page) == 0 {
			continue // deleted since Count
		}
		report.record(c.checkAndRecord(ctx, page[0], report))
	}
	report.FinishedAt = time.Now()
	c.saveReport(ctx, "sample", report, nil)
	return report, nil
}

// sweep pages through storage applying fn to every event. base narrows the
// sweep; nil means all events ordered by ingestion time.
func (c *Checker) sweep(ctx context.Context, base *storage.Query, fn func(*ocsf.StoredEvent)) error {
	q := storage.Query{OrderBy: "ingested_at"}
	if base != nil {
		q = *base
	}
	q.Limit = c.pageSize
	for offset := 0; ; offset += c.pageSize {
		if err := ctx.Err(); err != nil {
			return err
		}
		q.Offset = offset
		page, err := c.store.Query(ctx, &q)
		if err != nil {
			return fmt.Errorf("integrity: querying events at offset %d: %w", offset, err)
		}
		for _, ev := range page {
			fn(ev)
		}
		if len(page) < c.pageSize {
			return nil
		}
	}
}
