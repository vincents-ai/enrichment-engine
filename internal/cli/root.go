package cli

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"os"

	"github.com/shift/enrichment-engine/pkg/enricher"
	grcbuiltin "github.com/shift/enrichment-engine/pkg/grc/builtin"
	"github.com/shift/enrichment-engine/pkg/storage"
	"github.com/spf13/cobra"

	_ "github.com/glebarez/go-sqlite/compat"
)

type cliOption struct {
	version string
}

type CLIOption func(*cliOption)

func WithVersion(v string) CLIOption {
	return func(o *cliOption) {
		o.version = v
	}
}

var (
	workspace string
	logLevel  string
)

func New(opts ...CLIOption) *cobra.Command {
	o := &cliOption{version: "dev"}
	for _, opt := range opts {
		opt(o)
	}

	root := &cobra.Command{
		Use:   "enrich",
		Short: "GRC enrichment engine - maps vulnerabilities to compliance controls",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			var level slog.Level
			switch logLevel {
			case "debug":
				level = slog.LevelDebug
			case "warn":
				level = slog.LevelWarn
			case "error":
				level = slog.LevelError
			default:
				level = slog.LevelInfo
			}
			slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
				Level: level,
			})))
		},
	}

	root.PersistentFlags().StringVarP(&workspace, "workspace", "w", "./data", "Workspace directory")
	root.PersistentFlags().StringVarP(&logLevel, "log-level", "l", "info", "Log level (debug, info, warn, error)")

	root.AddCommand(runCmd())
	root.AddCommand(providersCmd())
	root.AddCommand(statusCmd())
	root.AddCommand(versionCmd(o.version))

	return root
}

func runCmd() *cobra.Command {
	var all bool
	var providers []string
	var skipMapping bool
	var maxParallel int
	var enableTagMapping bool

	cmd := &cobra.Command{
		Use:   "run [provider...]",
		Short: "Run GRC providers and enrichment pipeline",
		Long: `Run GRC control providers and the enrichment pipeline.

By default, runs all registered providers followed by CWE/CPE mapping.
Use --provider to run specific providers, or --skip-mapping to only populate controls.`,
		Example: `  enrich run --all
  enrich run --all --skip-mapping
  enrich run --provider hipaa --provider gdpr`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			logger := slog.Default()

			store, err := storage.NewSQLiteBackend(workspace + "/enrichment.db")
			if err != nil {
				return fmt.Errorf("initialize storage: %w", err)
			}
			defer store.Close(ctx)

			providerNames := providers
			if len(providerNames) == 0 && len(args) > 0 {
				providerNames = args
			}

			cfg := enricher.Config{
				Store:            store,
				MaxParallel:      maxParallel,
				Logger:           logger,
				ProviderNames:    providerNames,
				RunAll:           all,
				SkipMapping:      skipMapping,
				EnableTagMapping: enableTagMapping,
			}

			engine := enricher.New(cfg)
			result, err := engine.Run(ctx)
			if err != nil {
				return fmt.Errorf("enrichment pipeline: %w", err)
			}

			if skipMapping {
				logger.Info("providers complete",
					"providers", result.ProviderCount,
					"controls", result.ControlCount,
					"duration", result.Duration)
				fmt.Printf("Providers complete: %d providers, %d controls in %s\n",
					result.ProviderCount, result.ControlCount, result.Duration)
				return nil
			}

			logger.Info("enrichment complete",
				"controls", result.ControlCount,
				"mappings", result.MappingCount,
				"duration", result.Duration)

			fmt.Printf("Enrichment complete: %d controls, %d mappings in %s\n",
				result.ControlCount, result.MappingCount, result.Duration)
			return nil
		},
	}

	cmd.Flags().BoolVarP(&all, "all", "a", false, "Run all providers")
	cmd.Flags().StringSliceVarP(&providers, "provider", "p", nil, "Run specific providers")
	cmd.Flags().BoolVar(&skipMapping, "skip-mapping", false, "Skip CWE/CPE mapping phase (controls only)")
	cmd.Flags().BoolVar(&enableTagMapping, "enable-tag-mapping", false, "Enable tag-based mapping phase (confidence 0.4)")
	cmd.Flags().IntVar(&maxParallel, "max-parallel", 4, "Maximum parallel provider execution")

	return cmd
}

func providersCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "providers",
		Short: "List registered GRC providers",
		Run: func(cmd *cobra.Command, args []string) {
			reg := grcbuiltin.DefaultRegistry()
			names := reg.SortedList()
			fmt.Printf("Registered providers (%d):\n", len(names))
			for _, name := range names {
				fmt.Printf("  %s\n", name)
			}
		},
	}
}

func statusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show enrichment status",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("Workspace:", workspace)

			if _, err := os.Stat(workspace); os.IsNotExist(err) {
				fmt.Println("Workspace directory: MISSING")
				return nil
			}
			fmt.Println("Workspace directory: OK")

			dbPath := workspace + "/enrichment.db"
			if _, err := os.Stat(dbPath); os.IsNotExist(err) {
				fmt.Println("Database:", "MISSING")
				return nil
			}
			fmt.Println("Database:", "OK")

			db, err := sql.Open("sqlite", dbPath+"?mode=ro")
			if err != nil {
				fmt.Printf("Database: ERROR (%v)\n", err)
				return nil
			}
			defer db.Close()

			var controlCount int
			if err := db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM grc_controls").Scan(&controlCount); err != nil {
				fmt.Printf("Controls: ERROR (%v)\n", err)
			} else {
				fmt.Printf("Controls: %d in database\n", controlCount)
			}

			var vulnCount int
			if err := db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM vulnerabilities").Scan(&vulnCount); err != nil {
				fmt.Printf("Vulnerabilities: ERROR (%v)\n", err)
			} else {
				fmt.Printf("Vulnerabilities: %d in database\n", vulnCount)
			}

			var mappingCount int
			if err := db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM vulnerability_grc_mappings").Scan(&mappingCount); err != nil {
				fmt.Printf("Mappings: ERROR (%v)\n", err)
			} else {
				fmt.Printf("Mappings: %d in database\n", mappingCount)
			}

			reg := grcbuiltin.DefaultRegistry()
			fmt.Printf("Providers: %d registered\n", len(reg.List()))

			fmt.Println("Status: OK")
			return nil
		},
	}
}

func versionCmd(version string) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Show version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("enrichment-engine v%s\n", version)
		},
	}
}
