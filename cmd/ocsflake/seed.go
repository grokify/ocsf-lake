package main

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/grokify/ocsf-lake/pkg/seed"
)

func seedCmd(g *globalFlags) *cobra.Command {
	var (
		count       int
		spanDays    int
		rngSeed     int64
		signedPct   float64
		tamperPct   float64
		chains      int
		chainLength int
		breakChain  bool
		keysDir     string
		ndjsonOnly  bool
	)

	cmd := &cobra.Command{
		Use:   "seed",
		Short: "Populate the lake with realistic, schema-valid test data",
		Long: `Generates a weighted mix of OCSF events (authentication, network, DNS,
HTTP, file, process, findings, and Windows registry activity) spread over a
time window, with configurable proportions of signed, unsigned, and
tampered-after-signing events plus tamper-evident chains.

When signing is enabled, an ephemeral authority is generated and its key and
certificate PEMs are written to --keys-dir so later invocations can verify:

  ocsflake seed --events 5000 --signed-pct 60 --tamper-pct 2 --chains 2
  ocsflake check all --cert seed-keys/cert.pem --record`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := seed.Config{
				Events:      count,
				Span:        time.Duration(spanDays) * 24 * time.Hour,
				Seed:        rngSeed,
				SignedPct:   signedPct,
				TamperPct:   tamperPct,
				Chains:      chains,
				ChainLength: chainLength,
				BreakChain:  breakChain,
			}
			res, err := seed.Generate(cfg)
			if err != nil {
				return err
			}

			if ndjsonOnly {
				if err := res.NDJSON(cmd.OutOrStdout()); err != nil {
					return err
				}
			} else {
				l, err := openLake(cmd.Context(), g)
				if err != nil {
					return err
				}
				defer closeLake(l)
				if err := res.Populate(cmd.Context(), l); err != nil {
					return err
				}
			}

			cmd.PrintErrf("generated %d events: %d signed, %d unsigned, %d tampered",
				len(res.Events), res.Signed, res.Unsigned, res.Tampered)
			if len(res.ChainUIDs) > 0 {
				cmd.PrintErrf("; chains: %v", res.ChainUIDs)
			}
			cmd.PrintErrln()

			if res.Authority != nil {
				keyPath, certPath, err := res.Authority.WritePEM(keysDir)
				if err != nil {
					return fmt.Errorf("writing authority PEMs: %w", err)
				}
				cmd.PrintErrf("signing authority: key %s, cert %s, pin %s\n", keyPath, certPath, res.Authority.Pin())
			}
			return nil
		},
	}

	cmd.Flags().IntVar(&count, "events", 1000, "number of events to generate")
	cmd.Flags().IntVar(&spanDays, "span-days", 30, "spread events over this many days ending now")
	cmd.Flags().Int64Var(&rngSeed, "seed", 1, "random seed for deterministic event content")
	cmd.Flags().Float64Var(&signedPct, "signed-pct", 0, "percentage of events signed (0-100)")
	cmd.Flags().Float64Var(&tamperPct, "tamper-pct", 0, "percentage of signed events tampered after signing (0-100)")
	cmd.Flags().IntVar(&chains, "chains", 0, "number of tamper-evident chains to weave through the data")
	cmd.Flags().IntVar(&chainLength, "chain-length", 10, "events per chain")
	cmd.Flags().BoolVar(&breakChain, "break-chain", false, "corrupt one link of the last chain (for testing chain_broken detection)")
	cmd.Flags().StringVar(&keysDir, "keys-dir", "seed-keys", "directory to write the ephemeral signing key/cert PEMs")
	cmd.Flags().BoolVar(&ndjsonOnly, "ndjson", false, "write events as NDJSON to stdout instead of ingesting")
	return cmd
}
