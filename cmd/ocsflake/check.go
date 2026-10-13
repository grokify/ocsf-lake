package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/grokify/ocsf-lake/pkg/integrity"
)

// checkRunFlags are shared by the check subcommands.
type checkRunFlags struct {
	trust         trustFlags
	allowUnsigned bool
	record        bool
}

func (f *checkRunFlags) register(cmd *cobra.Command) {
	f.trust.register(cmd)
	cmd.Flags().BoolVar(&f.allowUnsigned, "allow-unsigned", true, "treat unsigned events as warnings rather than failures")
	cmd.Flags().BoolVar(&f.record, "record", false, "persist the check report and stamp integrity_status on checked events")
}

func (f *checkRunFlags) policy() (integrity.Policy, error) {
	verify, err := f.trust.policy()
	if err != nil {
		return integrity.Policy{}, err
	}
	verify.AllowUnsigned = f.allowUnsigned
	verify.RecordReports = f.record
	verify.RecordEventStatus = f.record
	return verify, nil
}

// reportResult prints the report and returns an error when events failed,
// so CI pipelines get a non-zero exit code.
func reportResult(cmd *cobra.Command, report *integrity.Report) error {
	if err := printJSON(cmd, report); err != nil {
		return err
	}
	if report.Failed > 0 {
		return fmt.Errorf("%d of %d events failed integrity checks", report.Failed, report.Checked)
	}
	return nil
}

func checkCmd(g *globalFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "check",
		Short: "Record-integrity checks over stored events",
	}
	cmd.AddCommand(
		checkEventCmd(g),
		checkAllCmd(g),
		checkIncrementalCmd(g),
		checkSampleCmd(g),
		checkChainCmd(g),
		checkReportsCmd(g),
	)
	return cmd
}

func checkEventCmd(g *globalFlags) *cobra.Command {
	flags := &checkRunFlags{}
	cmd := &cobra.Command{
		Use:   "event <id>",
		Short: "Check one stored event on demand",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			policy, err := flags.policy()
			if err != nil {
				return err
			}
			l, err := openLake(cmd.Context(), g)
			if err != nil {
				return err
			}
			defer closeLake(l)

			res, err := l.IntegrityChecker(policy).CheckEvent(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			if err := printJSON(cmd, res); err != nil {
				return err
			}
			if res.Outcome == integrity.OutcomeFailed {
				return fmt.Errorf("event %s failed integrity check (%s)", args[0], res.Status)
			}
			return nil
		},
	}
	flags.register(cmd)
	return cmd
}

func checkAllCmd(g *globalFlags) *cobra.Command {
	flags := &checkRunFlags{}
	cmd := &cobra.Command{
		Use:   "all",
		Short: "Check every stored event",
		RunE: func(cmd *cobra.Command, args []string) error {
			policy, err := flags.policy()
			if err != nil {
				return err
			}
			l, err := openLake(cmd.Context(), g)
			if err != nil {
				return err
			}
			defer closeLake(l)

			report, err := l.IntegrityChecker(policy).CheckAll(cmd.Context())
			if err != nil {
				return err
			}
			return reportResult(cmd, report)
		},
	}
	flags.register(cmd)
	return cmd
}

func checkIncrementalCmd(g *globalFlags) *cobra.Command {
	flags := &checkRunFlags{}
	var after string
	cmd := &cobra.Command{
		Use:   "incremental",
		Short: "Check events ingested since the last recorded incremental run (or --after)",
		RunE: func(cmd *cobra.Command, args []string) error {
			policy, err := flags.policy()
			if err != nil {
				return err
			}
			l, err := openLake(cmd.Context(), g)
			if err != nil {
				return err
			}
			defer closeLake(l)
			checker := l.IntegrityChecker(policy)

			var cp integrity.Checkpoint
			if after != "" {
				ms, err := parseTimeMillis(after)
				if err != nil {
					return fmt.Errorf("--after: %w", err)
				}
				cp.IngestedAfter = msToTime(ms)
			} else {
				if cp, err = checker.ResumeIncremental(cmd.Context()); err != nil {
					return err
				}
			}

			report, next, err := checker.CheckIncremental(cmd.Context(), cp)
			if err != nil {
				return err
			}
			cmd.PrintErrf("checkpoint: %s\n", next.IngestedAfter.Format("2006-01-02T15:04:05.000Z07:00"))
			return reportResult(cmd, report)
		},
	}
	flags.register(cmd)
	cmd.Flags().StringVar(&after, "after", "", "override checkpoint: check events ingested after this time (RFC3339 or epoch millis)")
	return cmd
}

func checkSampleCmd(g *globalFlags) *cobra.Command {
	flags := &checkRunFlags{}
	var percent float64
	var maxEvents int
	cmd := &cobra.Command{
		Use:   "sample",
		Short: "Check a random sample of stored events",
		RunE: func(cmd *cobra.Command, args []string) error {
			policy, err := flags.policy()
			if err != nil {
				return err
			}
			l, err := openLake(cmd.Context(), g)
			if err != nil {
				return err
			}
			defer closeLake(l)

			report, err := l.IntegrityChecker(policy).CheckSample(cmd.Context(), integrity.SamplePolicy{
				Percent:   percent,
				MaxEvents: maxEvents,
			})
			if err != nil {
				return err
			}
			return reportResult(cmd, report)
		},
	}
	flags.register(cmd)
	cmd.Flags().Float64Var(&percent, "percent", 5, "percentage of events to sample (0-100)")
	cmd.Flags().IntVar(&maxEvents, "max", 0, "maximum events to check this run (0 = no cap)")
	return cmd
}

func checkChainCmd(g *globalFlags) *cobra.Command {
	flags := &checkRunFlags{}
	cmd := &cobra.Command{
		Use:   "chain <chain-uid>",
		Short: "Verify a tamper-evident chain end to end",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			policy, err := flags.policy()
			if err != nil {
				return err
			}
			l, err := openLake(cmd.Context(), g)
			if err != nil {
				return err
			}
			defer closeLake(l)

			cr, err := l.IntegrityChecker(policy).CheckChain(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			if err := printJSON(cmd, cr); err != nil {
				return err
			}
			if cr.Report.Failed > 0 {
				return fmt.Errorf("chain %s: %d of %d events failed", args[0], cr.Report.Failed, cr.Report.Checked)
			}
			return nil
		},
	}
	flags.register(cmd)
	return cmd
}

func checkReportsCmd(g *globalFlags) *cobra.Command {
	var kind string
	var limit int
	cmd := &cobra.Command{
		Use:   "reports",
		Short: "List persisted integrity check reports, newest first",
		RunE: func(cmd *cobra.Command, args []string) error {
			l, err := openLake(cmd.Context(), g)
			if err != nil {
				return err
			}
			defer closeLake(l)

			recs, err := l.IntegrityReports(cmd.Context(), kind, limit)
			if err != nil {
				return err
			}
			return printJSON(cmd, recs)
		},
	}
	cmd.Flags().StringVar(&kind, "kind", "", "filter by check kind (event, all, incremental, sample, chain)")
	cmd.Flags().IntVar(&limit, "limit", 20, "maximum reports to list")
	return cmd
}
