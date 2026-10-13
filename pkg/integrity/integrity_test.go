package integrity_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/grokify/ocsf-lake/pkg/integrity"
	"github.com/grokify/ocsf-lake/pkg/lake"
	ri "github.com/grokify/ocsf-schema-go/recordintegrity"

	_ "github.com/mattn/go-sqlite3" // SQLite driver
)

type fixture struct {
	lake   *lake.Lake
	signer crypto.Signer
	cert   *x509.Certificate
	policy integrity.Policy
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "lake-test-signer"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	// Validation mode is not under test here; keep fixtures minimal.
	l, err := lake.New(context.Background(), lake.WithSQLiteMemory(), lake.WithNoValidation())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := l.Close(); err != nil {
			t.Errorf("closing lake: %v", err)
		}
	})

	policy := integrity.DefaultPolicy()
	policy.Verify = ri.VerifyOptions{
		Certificates:     []*x509.Certificate{cert},
		PinnedCertSHA256: []string{ri.CertSHA256(cert)},
	}
	return &fixture{lake: l, signer: key, cert: cert, policy: policy}
}

func (f *fixture) event(uid string, activityID int) []byte {
	return []byte(fmt.Sprintf(`{
		"class_uid": 3002, "category_uid": 3, "activity_id": %d,
		"type_uid": %d, "time": 1704067200000,
		"metadata": {"uid": %q, "version": "1.10.0", "product": {"name": "integrity-test"}},
		"user": {"name": "jdoe"}
	}`, activityID, 300200+activityID, uid))
}

func (f *fixture) signEvent(t *testing.T, event []byte, chainUID string, prev []byte) []byte {
	t.Helper()
	opts := ri.SignOptions{
		Signer: f.signer, Certificate: f.cert,
		AuthorityUID: "lake-test-signer", ChainUID: chainUID,
	}
	if prev != nil {
		ref, err := ri.NewPrevEventRef(prev)
		if err != nil {
			t.Fatal(err)
		}
		opts.PrevEvent = ref
	}
	signed, _, err := ri.SignAndAttach(event, opts)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func (f *fixture) ingest(t *testing.T, id string, event []byte) {
	t.Helper()
	if err := f.lake.IngestWithID(context.Background(), id, event); err != nil {
		t.Fatal(err)
	}
}

// seedMixed ingests: two signed chained events, one tampered event, one
// unsigned event. Returns the signed first/second event JSON for chain tests.
func (f *fixture) seedMixed(t *testing.T) {
	t.Helper()
	first := f.signEvent(t, f.event("evt-001", 1), "chain-1", nil)
	second := f.signEvent(t, f.event("evt-002", 2), "chain-1", first)
	tampered := []byte(strings.Replace(string(f.signEvent(t, f.event("evt-003", 1), "", nil)), "jdoe", "mallory", 1))
	f.ingest(t, "signed-1", first)
	f.ingest(t, "signed-2", second)
	f.ingest(t, "tampered-1", tampered)
	f.ingest(t, "unsigned-1", f.event("evt-004", 2))
}

func TestCheckEvent(t *testing.T) {
	f := newFixture(t)
	f.seedMixed(t)
	checker := f.lake.IntegrityChecker(f.policy)
	ctx := context.Background()

	res, err := checker.CheckEvent(ctx, "signed-1")
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != integrity.OutcomeVerified || res.Status != ri.StatusVerified {
		t.Errorf("signed-1 = %s/%s, want verified; issues %v", res.Outcome, res.Status, res.Issues)
	}

	res, err = checker.CheckEvent(ctx, "tampered-1")
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != integrity.OutcomeFailed {
		t.Errorf("tampered-1 outcome = %s, want failed; issues %v", res.Outcome, res.Issues)
	}

	res, err = checker.CheckEvent(ctx, "unsigned-1")
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != integrity.OutcomeUnsigned {
		t.Errorf("unsigned-1 outcome = %s, want unsigned (AllowUnsigned)", res.Outcome)
	}
}

func TestCheckAllPolicies(t *testing.T) {
	f := newFixture(t)
	f.seedMixed(t)
	ctx := context.Background()

	report, err := f.lake.IntegrityChecker(f.policy).CheckAll(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if report.Checked != 4 || report.Verified != 2 || report.Unsigned != 1 || report.Failed != 1 {
		t.Errorf("AllowUnsigned report = checked %d verified %d unsigned %d failed %d, want 4/2/1/1: %+v",
			report.Checked, report.Verified, report.Unsigned, report.Failed, report.Failures)
	}
	if len(report.UnsignedEvents) != 1 || report.UnsignedEvents[0].EventID != "unsigned-1" {
		t.Errorf("UnsignedEvents = %+v", report.UnsignedEvents)
	}

	strict := f.policy
	strict.AllowUnsigned = false
	report, err = f.lake.IntegrityChecker(strict).CheckAll(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if report.Failed != 2 || report.Unsigned != 0 {
		t.Errorf("disallow-unsigned report = failed %d unsigned %d, want 2/0", report.Failed, report.Unsigned)
	}
}

func TestCheckIncremental(t *testing.T) {
	f := newFixture(t)
	checker := f.lake.IntegrityChecker(f.policy)
	ctx := context.Background()

	f.ingest(t, "a", f.signEvent(t, f.event("evt-a", 1), "", nil))
	time.Sleep(5 * time.Millisecond)

	report, cp, err := checker.CheckIncremental(ctx, integrity.Checkpoint{})
	if err != nil {
		t.Fatal(err)
	}
	if report.Checked != 1 || cp.IngestedAfter.IsZero() {
		t.Fatalf("first run checked %d, checkpoint %v", report.Checked, cp)
	}

	time.Sleep(5 * time.Millisecond)
	f.ingest(t, "b", f.event("evt-b", 2)) // unsigned
	report, cp2, err := checker.CheckIncremental(ctx, cp)
	if err != nil {
		t.Fatal(err)
	}
	if report.Checked != 1 || report.Unsigned != 1 {
		t.Errorf("second run = checked %d unsigned %d, want 1/1", report.Checked, report.Unsigned)
	}
	if !cp2.IngestedAfter.After(cp.IngestedAfter) {
		t.Errorf("checkpoint did not advance: %v -> %v", cp.IngestedAfter, cp2.IngestedAfter)
	}

	// Nothing new: empty run.
	report, _, err = checker.CheckIncremental(ctx, cp2)
	if err != nil {
		t.Fatal(err)
	}
	if report.Checked != 0 {
		t.Errorf("third run checked %d, want 0", report.Checked)
	}
}

func TestCheckSample(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	for i := 0; i < 10; i++ {
		f.ingest(t, fmt.Sprintf("s-%02d", i), f.signEvent(t, f.event(fmt.Sprintf("evt-%02d", i), 1), "", nil))
	}
	checker := f.lake.IntegrityChecker(f.policy)

	report, err := checker.CheckSample(ctx, integrity.SamplePolicy{Percent: 100, Seed: 1})
	if err != nil {
		t.Fatal(err)
	}
	if report.Checked != 10 || report.Verified != 10 {
		t.Errorf("100%% sample = checked %d verified %d, want 10/10", report.Checked, report.Verified)
	}

	report, err = checker.CheckSample(ctx, integrity.SamplePolicy{Percent: 100, MaxEvents: 3, Seed: 1})
	if err != nil {
		t.Fatal(err)
	}
	if report.Checked != 3 {
		t.Errorf("capped sample checked %d, want 3", report.Checked)
	}

	report, err = checker.CheckSample(ctx, integrity.SamplePolicy{Percent: 50, Seed: 1})
	if err != nil {
		t.Fatal(err)
	}
	if report.Checked != 5 {
		t.Errorf("50%% sample checked %d, want 5", report.Checked)
	}
}

func TestCheckChain(t *testing.T) {
	f := newFixture(t)
	f.seedMixed(t)
	checker := f.lake.IntegrityChecker(f.policy)

	cr, err := checker.CheckChain(context.Background(), "chain-1")
	if err != nil {
		t.Fatal(err)
	}
	if cr.Report.Checked != 2 || cr.Report.Verified != 2 || cr.Report.Failed != 0 {
		t.Errorf("chain report = checked %d verified %d failed %d, want 2/2/0: %+v",
			cr.Report.Checked, cr.Report.Verified, cr.Report.Failed, cr.Report.Failures)
	}
	if cr.Heads != 1 {
		t.Errorf("chain heads = %d, want 1", cr.Heads)
	}
}

func TestCheckChainDetectsBrokenLink(t *testing.T) {
	f := newFixture(t)
	first := f.signEvent(t, f.event("evt-001", 1), "chain-2", nil)
	second := f.signEvent(t, f.event("evt-002", 2), "chain-2", first)

	// Replace the stored first event with a re-signed variant: its own
	// signature verifies, but the successor's prev_event fingerprint no
	// longer matches.
	replaced := f.signEvent(t, f.event("evt-001", 99), "chain-2", nil)
	f.ingest(t, "c-1", replaced)
	f.ingest(t, "c-2", second)

	cr, err := f.lake.IntegrityChecker(f.policy).CheckChain(context.Background(), "chain-2")
	if err != nil {
		t.Fatal(err)
	}
	if cr.Report.Failed != 1 {
		t.Fatalf("chain report failed = %d, want 1 (broken link): %+v", cr.Report.Failed, cr.Report)
	}
	found := false
	for _, issue := range cr.Report.Failures[0].Issues {
		if issue.Status == ri.StatusChainBroken {
			found = true
		}
	}
	if !found {
		t.Errorf("expected chain_broken issue, got %+v", cr.Report.Failures[0].Issues)
	}
}

func TestReportSerializes(t *testing.T) {
	f := newFixture(t)
	f.seedMixed(t)
	report, err := f.lake.IntegrityChecker(f.policy).CheckAll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"failures"`) {
		t.Errorf("report JSON missing failures: %s", data)
	}
}
