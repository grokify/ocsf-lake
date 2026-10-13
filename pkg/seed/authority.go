package seed

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/grokify/ocsf-lake/pkg/integrity"
	ri "github.com/grokify/ocsf-schema-go/recordintegrity"
)

// Authority is an ephemeral signing identity (ECDSA P-256 key plus
// self-signed certificate) for seeding signed events. Authorities are always
// generated at runtime — never commit key material, even test-only keys, to
// a repository.
type Authority struct {
	Name        string
	Signer      crypto.Signer
	Certificate *x509.Certificate
}

// NewAuthority generates a fresh signing authority. Key generation is fast
// (microseconds for P-256), so per-test generation is fine.
func NewAuthority(name string) (*Authority, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("seed: generating key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, fmt.Errorf("seed: creating certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &Authority{Name: name, Signer: key, Certificate: cert}, nil
}

// Pin returns the certificate's lowercase hex SHA-256 fingerprint.
func (a *Authority) Pin() string {
	return ri.CertSHA256(a.Certificate)
}

// VerifyOptions returns verification inputs trusting this authority.
func (a *Authority) VerifyOptions() ri.VerifyOptions {
	return ri.VerifyOptions{
		Certificates:     []*x509.Certificate{a.Certificate},
		PinnedCertSHA256: []string{a.Pin()},
	}
}

// Policy returns an integrity policy trusting this authority, with default
// unsigned handling (warn).
func (a *Authority) Policy() integrity.Policy {
	p := integrity.DefaultPolicy()
	p.Verify = a.VerifyOptions()
	return p
}

// WritePEM writes the authority's private key (key.pem, PKCS#8) and
// certificate (cert.pem) into dir, for use across CLI invocations. The key
// file is created with 0600 permissions.
func (a *Authority) WritePEM(dir string) (keyPath, certPath string, err error) {
	keyDER, err := x509.MarshalPKCS8PrivateKey(a.Signer)
	if err != nil {
		return "", "", fmt.Errorf("seed: marshaling key: %w", err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", "", err
	}
	keyPath = filepath.Join(dir, "key.pem")
	certPath = filepath.Join(dir, "cert.pem")
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: a.Certificate.Raw})
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return "", "", err
	}
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		return "", "", err
	}
	return keyPath, certPath, nil
}
