package main

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/grokify/ocsf-lake/pkg/integrity"
	ri "github.com/grokify/ocsf-schema-go/recordintegrity"
)

// trustFlags supply verification inputs shared by ingest --integrity and the
// check/verify commands.
type trustFlags struct {
	certPaths []string
	rootPaths []string
	pins      []string
}

func (f *trustFlags) register(cmd *cobra.Command) {
	cmd.Flags().StringSliceVar(&f.certPaths, "cert", nil, "PEM file with a candidate signer certificate (repeatable)")
	cmd.Flags().StringSliceVar(&f.rootPaths, "root", nil, "PEM file with a trusted root certificate (repeatable)")
	cmd.Flags().StringSliceVar(&f.pins, "pin", nil, "lowercase hex SHA-256 fingerprint of a directly trusted signer certificate (repeatable)")
}

func (f *trustFlags) verifyOptions() (ri.VerifyOptions, error) {
	opts := ri.VerifyOptions{PinnedCertSHA256: f.pins}
	for _, path := range f.certPaths {
		certs, err := loadCertificates(path)
		if err != nil {
			return opts, err
		}
		opts.Certificates = append(opts.Certificates, certs...)
	}
	if len(f.rootPaths) > 0 {
		pool := x509.NewCertPool()
		for _, path := range f.rootPaths {
			certs, err := loadCertificates(path)
			if err != nil {
				return opts, err
			}
			for _, c := range certs {
				pool.AddCert(c)
			}
		}
		opts.Roots = pool
	}
	return opts, nil
}

// policy builds an integrity policy from the trust flags (verification
// inputs only; callers adjust AllowUnsigned/recording).
func (f *trustFlags) policy() (integrity.Policy, error) {
	verify, err := f.verifyOptions()
	if err != nil {
		return integrity.Policy{}, err
	}
	p := integrity.DefaultPolicy()
	p.Verify = verify
	return p, nil
}

// loadCertificates reads every CERTIFICATE block from a PEM file.
func loadCertificates(path string) ([]*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var certs []*x509.Certificate
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("%s: no CERTIFICATE blocks found", path)
	}
	return certs, nil
}

// loadSigner reads a private key from a PEM file (PKCS#8, EC, or PKCS#1).
func loadSigner(path string) (crypto.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("%s: no private key block found", path)
		}
		switch block.Type {
		case "PRIVATE KEY":
			key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", path, err)
			}
			signer, ok := key.(crypto.Signer)
			if !ok {
				return nil, fmt.Errorf("%s: key type %T cannot sign", path, key)
			}
			return signer, nil
		case "EC PRIVATE KEY":
			key, err := x509.ParseECPrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", path, err)
			}
			return key, nil
		case "RSA PRIVATE KEY":
			key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", path, err)
			}
			return key, nil
		}
	}
}

func signCmd() *cobra.Command {
	var keyPath, certPath, authorityUID, chainUID, prevPath string
	cmd := &cobra.Command{
		Use:   "sign <event.json>",
		Short: "Sign an OCSF event under the record_integrity profile (writes the signed event to stdout)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			eventJSON, err := os.ReadFile(args[0])
			if err != nil {
				return err
			}
			signer, err := loadSigner(keyPath)
			if err != nil {
				return err
			}
			opts := ri.SignOptions{Signer: signer, AuthorityUID: authorityUID, ChainUID: chainUID}
			if certPath != "" {
				certs, err := loadCertificates(certPath)
				if err != nil {
					return err
				}
				opts.Certificate = certs[0]
			}
			if prevPath != "" {
				prevJSON, err := os.ReadFile(prevPath)
				if err != nil {
					return err
				}
				if opts.PrevEvent, err = ri.NewPrevEventRef(prevJSON); err != nil {
					return err
				}
			}
			signed, _, err := ri.SignAndAttach(eventJSON, opts)
			if err != nil {
				return err
			}
			// cobra's cmd.Println writes to stderr; event data must go to
			// stdout so it can be piped and redirected.
			_, err = fmt.Fprintln(cmd.OutOrStdout(), string(signed))
			return err
		},
	}
	cmd.Flags().StringVar(&keyPath, "key", "", "PEM file with the signing private key (required)")
	cmd.Flags().StringVar(&certPath, "signer-cert", "", "PEM file with the signer certificate")
	cmd.Flags().StringVar(&authorityUID, "authority", "", "authority_uid identifying the attesting party")
	cmd.Flags().StringVar(&chainUID, "chain-uid", "", "chain identifier for tamper-evident chaining")
	cmd.Flags().StringVar(&prevPath, "prev", "", "JSON file of the previous chained event")
	if err := cmd.MarkFlagRequired("key"); err != nil {
		panic(err) // programming error: flag name must exist
	}
	return cmd
}

func verifyCmd() *cobra.Command {
	trust := &trustFlags{}
	var prevPath string
	var at string
	cmd := &cobra.Command{
		Use:   "verify <event.json>",
		Short: "Verify a signed OCSF event (and optionally its chain link) without a lake",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			eventJSON, err := os.ReadFile(args[0])
			if err != nil {
				return err
			}
			opts, err := trust.verifyOptions()
			if err != nil {
				return err
			}
			if at != "" {
				ms, err := parseTimeMillis(at)
				if err != nil {
					return fmt.Errorf("--at: %w", err)
				}
				opts.At = msToTime(ms)
			}
			result := ri.Verify(eventJSON, opts)
			if err := printJSON(cmd, result); err != nil {
				return err
			}
			if prevPath != "" {
				prevJSON, err := os.ReadFile(prevPath)
				if err != nil {
					return err
				}
				link := ri.VerifyLink(eventJSON, prevJSON)
				if err := printJSON(cmd, link); err != nil {
					return err
				}
				if link.Status != ri.StatusVerified {
					return fmt.Errorf("chain link: %s", link.Status)
				}
			}
			if result.Status != ri.StatusVerified && result.Status != ri.StatusUnsigned {
				return fmt.Errorf("event: %s", result.Status)
			}
			return nil
		},
	}
	trust.register(cmd)
	cmd.Flags().StringVar(&prevPath, "prev", "", "JSON file of the previous chained event to verify the link against")
	cmd.Flags().StringVar(&at, "at", "", "certificate validity check time (RFC3339 or epoch millis)")
	return cmd
}

func msToTime(ms int64) time.Time {
	return time.UnixMilli(ms)
}
