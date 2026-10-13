package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/spf13/cobra"

	"github.com/grokify/ocsf-lake/pkg/lake"
	"github.com/grokify/ocsf-lake/pkg/storage"
)

func ingestCmd(g *globalFlags) *cobra.Command {
	var integrityMode string
	trust := &trustFlags{}

	cmd := &cobra.Command{
		Use:   "ingest [file ...]",
		Short: "Ingest OCSF event JSON files (or NDJSON from stdin with no arguments)",
		RunE: func(cmd *cobra.Command, args []string) error {
			var extra []lake.Option
			if integrityMode != "off" {
				policy, err := trust.policy()
				if err != nil {
					return err
				}
				switch integrityMode {
				case "monitor":
					extra = append(extra, lake.WithIngestIntegrity(lake.IngestIntegrityMonitor, policy))
				case "enforce":
					extra = append(extra, lake.WithIngestIntegrity(lake.IngestIntegrityEnforce, policy))
				default:
					return fmt.Errorf("unknown --integrity mode %q (off, monitor, enforce)", integrityMode)
				}
			}
			l, err := openLake(cmd.Context(), g, extra...)
			if err != nil {
				return err
			}
			defer closeLake(l)

			events, err := readEvents(args)
			if err != nil {
				return err
			}
			// Single batched call: one bulk insert, with the lake reporting
			// the failing event's position on error.
			if err := l.Ingest(cmd.Context(), events...); err != nil {
				return err
			}
			cmd.Printf("ingested %d events\n", len(events))
			return nil
		},
	}
	cmd.Flags().StringVar(&integrityMode, "integrity", "off", "ingest-time integrity checking: off, monitor, enforce")
	trust.register(cmd)
	return cmd
}

// readEvents loads one JSON event per file, or NDJSON lines from stdin when
// no files are given.
func readEvents(paths []string) ([]json.RawMessage, error) {
	var events []json.RawMessage
	if len(paths) == 0 {
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Buffer(make([]byte, 1024*1024), 16*1024*1024)
		for scanner.Scan() {
			line := scanner.Bytes()
			if len(line) == 0 {
				continue
			}
			events = append(events, json.RawMessage(append([]byte(nil), line...)))
		}
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("reading stdin: %w", err)
		}
		return events, nil
	}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		events = append(events, json.RawMessage(data))
	}
	return events, nil
}

func getCmd(g *globalFlags) *cobra.Command {
	var payloadOnly bool
	cmd := &cobra.Command{
		Use:   "get <id>",
		Short: "Get one stored event by ID",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			l, err := openLake(cmd.Context(), g)
			if err != nil {
				return err
			}
			defer closeLake(l)

			ev, err := l.Get(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			var out any = ev
			if payloadOnly {
				out = ev.Payload
			}
			return printJSON(cmd, out)
		},
	}
	cmd.Flags().BoolVar(&payloadOnly, "payload-only", false, "print only the OCSF payload")
	return cmd
}

// queryFilterFlags are shared by query and count.
type queryFilterFlags struct {
	classUID, categoryUID, severityID, statusID int
	source, since, until, integrityStatus       string
	limit, offset                               int
}

func (f *queryFilterFlags) register(cmd *cobra.Command, withPaging bool) {
	cmd.Flags().IntVar(&f.classUID, "class-uid", 0, "filter by class_uid")
	cmd.Flags().IntVar(&f.categoryUID, "category-uid", 0, "filter by category_uid")
	cmd.Flags().IntVar(&f.severityID, "severity-id", 0, "filter by severity_id")
	cmd.Flags().IntVar(&f.statusID, "status-id", 0, "filter by status_id")
	cmd.Flags().StringVar(&f.source, "filter-source", "", "filter by source")
	cmd.Flags().StringVar(&f.integrityStatus, "integrity-status", "",
		`filter by recorded integrity status (e.g. "verified", "unsigned", "signature_invalid")`)
	cmd.Flags().StringVar(&f.since, "since", "", "events at/after this time (RFC3339 or epoch millis)")
	cmd.Flags().StringVar(&f.until, "until", "", "events at/before this time (RFC3339 or epoch millis)")
	if withPaging {
		cmd.Flags().IntVar(&f.limit, "limit", 100, "maximum events to return")
		cmd.Flags().IntVar(&f.offset, "offset", 0, "events to skip")
	}
}

func (f *queryFilterFlags) build() (*storage.Query, error) {
	q := &storage.Query{Limit: f.limit, Offset: f.offset}
	if f.classUID != 0 {
		q.ClassUID = &f.classUID
	}
	if f.categoryUID != 0 {
		q.CategoryUID = &f.categoryUID
	}
	if f.severityID != 0 {
		q.SeverityID = &f.severityID
	}
	if f.statusID != 0 {
		q.StatusID = &f.statusID
	}
	if f.source != "" {
		q.Source = &f.source
	}
	if f.integrityStatus != "" {
		q.IntegrityStatus = &f.integrityStatus
	}
	if f.since != "" {
		ms, err := parseTimeMillis(f.since)
		if err != nil {
			return nil, fmt.Errorf("--since: %w", err)
		}
		q.TimeFrom = &ms
	}
	if f.until != "" {
		ms, err := parseTimeMillis(f.until)
		if err != nil {
			return nil, fmt.Errorf("--until: %w", err)
		}
		q.TimeTo = &ms
	}
	return q, nil
}

func parseTimeMillis(s string) (int64, error) {
	if ms, err := strconv.ParseInt(s, 10, 64); err == nil {
		return ms, nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return 0, fmt.Errorf("not epoch millis or RFC3339: %q", s)
	}
	return t.UnixMilli(), nil
}

func queryCmd(g *globalFlags) *cobra.Command {
	filters := &queryFilterFlags{}
	var payloadOnly bool
	cmd := &cobra.Command{
		Use:   "query",
		Short: "Query stored events (NDJSON output)",
		RunE: func(cmd *cobra.Command, args []string) error {
			l, err := openLake(cmd.Context(), g)
			if err != nil {
				return err
			}
			defer closeLake(l)

			q, err := filters.build()
			if err != nil {
				return err
			}
			events, err := l.Query(cmd.Context(), q)
			if err != nil {
				return err
			}
			enc := json.NewEncoder(cmd.OutOrStdout())
			for _, ev := range events {
				var out any = ev
				if payloadOnly {
					out = ev.Payload
				}
				if err := enc.Encode(out); err != nil {
					return err
				}
			}
			return nil
		},
	}
	filters.register(cmd, true)
	cmd.Flags().BoolVar(&payloadOnly, "payload-only", false, "print only the OCSF payloads")
	return cmd
}

func countCmd(g *globalFlags) *cobra.Command {
	filters := &queryFilterFlags{}
	cmd := &cobra.Command{
		Use:   "count",
		Short: "Count stored events matching the filters",
		RunE: func(cmd *cobra.Command, args []string) error {
			l, err := openLake(cmd.Context(), g)
			if err != nil {
				return err
			}
			defer closeLake(l)

			q, err := filters.build()
			if err != nil {
				return err
			}
			n, err := l.Count(cmd.Context(), q)
			if err != nil {
				return err
			}
			// Data goes to stdout (cobra's cmd.Println writes to stderr).
			_, err = fmt.Fprintln(cmd.OutOrStdout(), n)
			return err
		},
	}
	filters.register(cmd, false)
	return cmd
}

func printJSON(cmd *cobra.Command, v any) error {
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
