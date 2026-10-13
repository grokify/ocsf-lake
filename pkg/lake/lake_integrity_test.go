package lake_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/grokify/ocsf-lake/pkg/integrity"
	"github.com/grokify/ocsf-lake/pkg/lake"
	ri "github.com/grokify/ocsf-schema-go/recordintegrity"
)

func newTestSigner(t *testing.T) (crypto.Signer, *x509.Certificate) {
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
		Subject:               pkix.Name{CommonName: "pipeline-test"},
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
	return key, cert
}

func pipelineEvent(uid string) []byte {
	return []byte(fmt.Sprintf(`{
		"class_uid": 3002, "category_uid": 3, "activity_id": 1,
		"type_uid": 300201, "time": 1704067200000,
		"metadata": {"uid": %q, "version": "1.10.0", "product": {"name": "pipeline-test"}},
		"user": {"name": "jdoe"}
	}`, uid))
}

func trustPolicy(cert *x509.Certificate) integrity.Policy {
	p := integrity.DefaultPolicy()
	p.Verify = ri.VerifyOptions{
		Certificates:     []*x509.Certificate{cert},
		PinnedCertSHA256: []string{ri.CertSHA256(cert)},
	}
	return p
}

func TestIngestIntegrityMonitor(t *testing.T) {
	ctx := context.Background()
	signer, cert := newTestSigner(t)

	l, err := lake.New(ctx, lake.WithSQLiteMemory(), lake.WithNoValidation(),
		lake.WithIngestIntegrity(lake.IngestIntegrityMonitor, trustPolicy(cert)))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	signed, _, err := ri.SignAndAttach(pipelineEvent("m-1"), ri.SignOptions{Signer: signer, Certificate: cert})
	if err != nil {
		t.Fatal(err)
	}
	tampered := []byte(strings.Replace(string(signed), "jdoe", "mallory", 1))

	if err := l.IngestWithID(ctx, "ok", signed); err != nil {
		t.Fatal(err)
	}
	if err := l.IngestWithID(ctx, "bad", tampered); err != nil {
		t.Fatalf("monitor mode must not reject: %v", err)
	}
	if err := l.IngestWithID(ctx, "plain", pipelineEvent("m-2")); err != nil {
		t.Fatal(err)
	}

	for id, want := range map[string]string{
		"ok":    string(ri.StatusVerified),
		"plain": string(ri.StatusUnsigned),
	} {
		ev, err := l.Get(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if ev.IntegrityStatus != want {
			t.Errorf("%s integrity_status = %q, want %q", id, ev.IntegrityStatus, want)
		}
		if ev.IntegrityCheckedAt == nil {
			t.Errorf("%s integrity_checked_at not stamped", id)
		}
	}
	ev, err := l.Get(ctx, "bad")
	if err != nil {
		t.Fatal(err)
	}
	if ev.IntegrityStatus == string(ri.StatusVerified) || ev.IntegrityStatus == "" {
		t.Errorf("bad integrity_status = %q, want a failure status", ev.IntegrityStatus)
	}
}

func TestIngestIntegrityEnforce(t *testing.T) {
	ctx := context.Background()
	signer, cert := newTestSigner(t)

	l, err := lake.New(ctx, lake.WithSQLiteMemory(), lake.WithNoValidation(),
		lake.WithIngestIntegrity(lake.IngestIntegrityEnforce, trustPolicy(cert)))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	signed, _, err := ri.SignAndAttach(pipelineEvent("e-1"), ri.SignOptions{Signer: signer, Certificate: cert})
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Ingest(ctx, signed); err != nil {
		t.Fatalf("valid signed event rejected: %v", err)
	}
	// AllowUnsigned=true (default): unsigned passes enforce mode.
	if err := l.Ingest(ctx, pipelineEvent("e-2")); err != nil {
		t.Fatalf("unsigned event rejected despite AllowUnsigned: %v", err)
	}

	tampered := []byte(strings.Replace(string(signed), "jdoe", "mallory", 1))
	err = l.Ingest(ctx, tampered)
	var rejection *lake.IntegrityRejectionError
	if !errors.As(err, &rejection) {
		t.Fatalf("tampered event error = %v, want IntegrityRejectionError", err)
	}

	// Disallow unsigned: plain events now rejected too.
	strict := trustPolicy(cert)
	strict.AllowUnsigned = false
	l2, err := lake.New(ctx, lake.WithSQLiteMemory(), lake.WithNoValidation(),
		lake.WithIngestIntegrity(lake.IngestIntegrityEnforce, strict))
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Close()
	if err := l2.Ingest(ctx, pipelineEvent("e-3")); !errors.As(err, &rejection) {
		t.Fatalf("unsigned event error = %v, want IntegrityRejectionError with AllowUnsigned=false", err)
	}
}

func TestIngestAttestation(t *testing.T) {
	ctx := context.Background()
	signer, cert := newTestSigner(t)

	l, err := lake.New(ctx, lake.WithSQLiteMemory(), lake.WithNoValidation(),
		lake.WithIngestAttestation(lake.AttestationOptions{
			Signer: signer, Certificate: cert,
			AuthorityUID: "lake.example.com", ChainUID: "lake-chain",
		}))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	if err := l.IngestWithID(ctx, "a-1", pipelineEvent("evt-a1")); err != nil {
		t.Fatal(err)
	}
	if err := l.IngestWithID(ctx, "a-2", pipelineEvent("evt-a2")); err != nil {
		t.Fatal(err)
	}

	first, err := l.Get(ctx, "a-1")
	if err != nil {
		t.Fatal(err)
	}
	atts, ok := first.Payload["attestation_list"].([]any)
	if !ok || len(atts) != 1 {
		t.Fatalf("first event attestation_list = %v, want 1 lake attestation", first.Payload["attestation_list"])
	}
	att := atts[0].(map[string]any)
	if att["authority_uid"] != "lake.example.com" || att["chain_uid"] != "lake-chain" {
		t.Errorf("attestation = %v", att)
	}
	if att["prev_event"] != nil {
		t.Errorf("first chain event should have no prev_event, got %v", att["prev_event"])
	}

	second, err := l.Get(ctx, "a-2")
	if err != nil {
		t.Fatal(err)
	}
	att2 := second.Payload["attestation_list"].([]any)[0].(map[string]any)
	prev, ok := att2["prev_event"].(map[string]any)
	if !ok || prev["uid"] != "evt-a1" {
		t.Fatalf("second event prev_event = %v, want link to evt-a1", att2["prev_event"])
	}

	if l.ChainTail() == nil {
		t.Error("ChainTail should be set after attested ingests")
	}

	// The lake-attested chain verifies end to end.
	cr, err := l.IntegrityChecker(trustPolicy(cert)).CheckChain(ctx, "lake-chain")
	if err != nil {
		t.Fatal(err)
	}
	if cr.Report.Checked != 2 || cr.Report.Verified != 2 || cr.Report.Failed != 0 {
		t.Errorf("lake chain = checked %d verified %d failed %d, want 2/2/0: %+v",
			cr.Report.Checked, cr.Report.Verified, cr.Report.Failed, cr.Report.Failures)
	}

	// Marshal round-trip: stored payload still parses as a typed event.
	data, err := json.Marshal(second.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"signature_value"`) {
		t.Error("stored attested payload missing signature_value")
	}
}

// TestQueryByIntegrityStatus exercises the integrity_status query filter
// against monitor-mode stamps.
func TestQueryByIntegrityStatus(t *testing.T) {
	ctx := context.Background()
	signer, cert := newTestSigner(t)

	l, err := lake.New(ctx, lake.WithSQLiteMemory(), lake.WithNoValidation(),
		lake.WithIngestIntegrity(lake.IngestIntegrityMonitor, trustPolicy(cert)))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	signed, _, err := ri.SignAndAttach(pipelineEvent("q-1"), ri.SignOptions{Signer: signer, Certificate: cert})
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Ingest(ctx, signed, pipelineEvent("q-2"), pipelineEvent("q-3")); err != nil {
		t.Fatal(err)
	}

	verified, err := l.Query(ctx, l.QueryBuilder().WithIntegrityStatus(string(ri.StatusVerified)).Build())
	if err != nil {
		t.Fatal(err)
	}
	if len(verified) != 1 {
		t.Errorf("verified events = %d, want 1", len(verified))
	}
	unsigned, err := l.Count(ctx, l.QueryBuilder().WithIntegrityStatus(string(ri.StatusUnsigned)).Build())
	if err != nil {
		t.Fatal(err)
	}
	if unsigned != 2 {
		t.Errorf("unsigned count = %d, want 2", unsigned)
	}
}

// TestRawDataRetention verifies WithRawDataRetention stores the original
// bytes as received, even when the lake attests (and thus mutates) the event.
func TestRawDataRetention(t *testing.T) {
	ctx := context.Background()
	signer, cert := newTestSigner(t)

	l, err := lake.New(ctx, lake.WithSQLiteMemory(), lake.WithNoValidation(),
		lake.WithRawDataRetention(),
		lake.WithIngestAttestation(lake.AttestationOptions{Signer: signer, Certificate: cert, AuthorityUID: "lake"}))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	original := pipelineEvent("raw-1")
	if err := l.IngestWithID(ctx, "raw-1", original); err != nil {
		t.Fatal(err)
	}
	ev, err := l.Get(ctx, "raw-1")
	if err != nil {
		t.Fatal(err)
	}
	if ev.RawData != string(original) {
		t.Errorf("RawData = %q, want the original pre-attestation bytes", ev.RawData)
	}
	if _, ok := ev.Payload["attestation_list"]; !ok {
		t.Error("stored payload should carry the lake attestation")
	}
	if strings.Contains(ev.RawData, "attestation_list") {
		t.Error("RawData must not include the lake attestation")
	}

	// Without the option, RawData stays empty.
	l2, err := lake.New(ctx, lake.WithSQLiteMemory(), lake.WithNoValidation())
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Close()
	if err := l2.IngestWithID(ctx, "raw-2", original); err != nil {
		t.Fatal(err)
	}
	ev, err = l2.Get(ctx, "raw-2")
	if err != nil {
		t.Fatal(err)
	}
	if ev.RawData != "" {
		t.Errorf("RawData = %q, want empty without retention option", ev.RawData)
	}
}

func TestIntegrityReportPersistenceAndResume(t *testing.T) {
	ctx := context.Background()
	signer, cert := newTestSigner(t)

	l, err := lake.New(ctx, lake.WithSQLiteMemory(), lake.WithNoValidation())
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	signed, _, err := ri.SignAndAttach(pipelineEvent("r-1"), ri.SignOptions{Signer: signer, Certificate: cert})
	if err != nil {
		t.Fatal(err)
	}
	if err := l.IngestWithID(ctx, "r-1", signed); err != nil {
		t.Fatal(err)
	}

	policy := trustPolicy(cert)
	policy.RecordReports = true
	policy.RecordEventStatus = true
	checker := l.IntegrityChecker(policy)

	report, cp, err := checker.CheckIncremental(ctx, integrity.Checkpoint{})
	if err != nil {
		t.Fatal(err)
	}
	if report.Checked != 1 || len(report.RecordingErrors) != 0 {
		t.Fatalf("incremental report = %+v", report)
	}

	// Report persisted and checkpoint resumable.
	recs, err := l.IntegrityReports(ctx, "incremental", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || recs[0].Checked != 1 || recs[0].Checkpoint == nil {
		t.Fatalf("persisted reports = %+v", recs)
	}
	resumed, err := checker.ResumeIncremental(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !resumed.IngestedAfter.Equal(cp.IngestedAfter) {
		t.Errorf("resumed checkpoint %v != returned %v", resumed.IngestedAfter, cp.IngestedAfter)
	}

	// Event status stamped by the checker.
	ev, err := l.Get(ctx, "r-1")
	if err != nil {
		t.Fatal(err)
	}
	if ev.IntegrityStatus != string(ri.StatusVerified) || ev.IntegrityCheckedAt == nil {
		t.Errorf("event integrity stamp = %q/%v", ev.IntegrityStatus, ev.IntegrityCheckedAt)
	}

	// CheckAll also persists.
	if _, err := checker.CheckAll(ctx); err != nil {
		t.Fatal(err)
	}
	recs, err = l.IntegrityReports(ctx, "", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 {
		t.Errorf("total persisted reports = %d, want 2", len(recs))
	}
}
