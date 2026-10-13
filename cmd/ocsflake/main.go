// Command ocsflake is the CLI for ocsf-lake: ingest, query, and
// integrity-check OCSF events, and sign/verify events under the
// record_integrity profile.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/grokify/ocsf-lake/pkg/lake"
	"github.com/grokify/ocsf-schema-go/validate"

	_ "github.com/mattn/go-sqlite3" // SQLite driver
)

// globalFlags are persistent across subcommands.
type globalFlags struct {
	dbPath       string
	memory       bool
	dsn          string
	validation   string
	unknownAttrs string
	source       string
}

func main() {
	if err := rootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "ocsflake:", err)
		os.Exit(1)
	}
}

func rootCmd() *cobra.Command {
	g := &globalFlags{}
	root := &cobra.Command{
		Use:           "ocsflake",
		Short:         "OCSF data lake: ingest, query, and integrity-check OCSF events",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().StringVar(&g.dbPath, "db", "ocsf-lake.db", "SQLite database file path")
	root.PersistentFlags().BoolVar(&g.memory, "memory", false, "use in-memory SQLite (single-process only)")
	root.PersistentFlags().StringVar(&g.dsn, "dsn", "", "PostgreSQL connection string (overrides --db)")
	root.PersistentFlags().StringVar(&g.validation, "validation", "strict", "schema validation mode: strict, permissive, off")
	root.PersistentFlags().StringVar(&g.unknownAttrs, "unknown-attributes", "warn", "handling of attributes not in the OCSF schema: warn, ignore, error")
	root.PersistentFlags().StringVar(&g.source, "source", "", "default source for ingested events")

	root.AddCommand(
		ingestCmd(g),
		getCmd(g),
		queryCmd(g),
		countCmd(g),
		checkCmd(g),
		seedCmd(g),
		signCmd(),
		verifyCmd(),
	)
	return root
}

// openLake constructs a Lake from the global flags plus extra options.
func openLake(ctx context.Context, g *globalFlags, extra ...lake.Option) (*lake.Lake, error) {
	opts := make([]lake.Option, 0, 4+len(extra))
	switch {
	case g.dsn != "":
		opts = append(opts, lake.WithPostgres(g.dsn))
	case g.memory:
		opts = append(opts, lake.WithSQLiteMemory())
	default:
		opts = append(opts, lake.WithSQLiteFile(g.dbPath))
	}
	switch g.validation {
	case "strict":
		opts = append(opts, lake.WithStrictValidation())
	case "permissive":
		opts = append(opts, lake.WithPermissiveValidation())
	case "off":
		opts = append(opts, lake.WithNoValidation())
	default:
		return nil, fmt.Errorf("unknown --validation mode %q (strict, permissive, off)", g.validation)
	}
	switch g.unknownAttrs {
	case "warn", "":
		// validator default
	case "ignore":
		opts = append(opts, lake.WithUnknownAttributes(validate.UnknownIgnore))
	case "error":
		opts = append(opts, lake.WithUnknownAttributes(validate.UnknownError))
	default:
		return nil, fmt.Errorf("unknown --unknown-attributes mode %q (warn, ignore, error)", g.unknownAttrs)
	}
	if g.source != "" {
		opts = append(opts, lake.WithDefaultSource(g.source))
	}
	opts = append(opts, extra...)
	return lake.New(ctx, opts...)
}

// closeLake closes l, surfacing the error on stderr since command results
// have already been produced by the time it runs.
func closeLake(l *lake.Lake) {
	if err := l.Close(); err != nil {
		fmt.Fprintln(os.Stderr, "ocsflake: closing lake:", err)
	}
}
