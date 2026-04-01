package cli

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/shift/enrichment-engine/pkg/enricher"
	"github.com/shift/enrichment-engine/pkg/schema"
	"github.com/shift/enrichment-engine/pkg/storage"
	"github.com/spf13/cobra"
)

var (
	workspace string
	logLevel  string
)

func New() *cobra.Command {
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
	root.AddCommand(statusCmd())
	root.AddCommand(versionCmd())

	return root
}

func runCmd() *cobra.Command {
	var all bool
	var providers []string

	cmd := &cobra.Command{
		Use:   "run [provider...]",
		Short: "Run GRC providers and enrichment pipeline",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			logger := slog.Default()

			// Initialize storage
			store, err := storage.NewSQLiteBackend(workspace + "/enrichment.db")
			if err != nil {
				return fmt.Errorf("initialize storage: %w", err)
			}
			defer store.Close(ctx)

			// Initialize schema validator
			validator, err := schema.NewValidator()
			if err != nil {
				return fmt.Errorf("initialize validator: %w", err)
			}
			_ = validator

			// Run enrichment pipeline
			engine := enricher.New(enricher.Config{
				Store:       store,
				MaxParallel: 4,
				Logger:      logger,
			})

			result, err := engine.Run(ctx)
			if err != nil {
				return fmt.Errorf("enrichment pipeline: %w", err)
			}

			logger.Info("enrichment complete",
				"mappings", result.MappingCount,
				"duration", result.Duration)

			fmt.Printf("Enrichment complete: %d mappings in %s\n", result.MappingCount, result.Duration)
			return nil
		},
	}

	cmd.Flags().BoolVarP(&all, "all", "a", false, "Run all providers")
	cmd.Flags().StringSliceVarP(&providers, "provider", "p", nil, "Run specific providers")

	return cmd
}

func statusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show enrichment status",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("Workspace:", workspace)
			fmt.Println("Status: OK")
			return nil
		},
	}
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Show version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("enrichment-engine v0.1.0")
		},
	}
}
