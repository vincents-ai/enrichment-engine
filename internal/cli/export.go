package cli

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/shift/enrichment-engine/pkg/export/cyclonedx"
	"github.com/shift/enrichment-engine/pkg/storage"
	"github.com/spf13/cobra"
)

func exportCmd() *cobra.Command {
	var outputPath string

	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export enrichment data as CycloneDX BOM",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			logger := slog.Default()

			store, err := storage.NewSQLiteBackend(workspace + "/enrichment.db")
			if err != nil {
				return fmt.Errorf("initialize storage: %w", err)
			}
			defer store.Close(ctx)

			ser := cyclonedx.NewSerializer(store)
			data, err := ser.SerializeJSON(ctx)
			if err != nil {
				return fmt.Errorf("serialize BOM: %w", err)
			}

			if outputPath != "" {
				if err := os.WriteFile(outputPath, data, 0644); err != nil {
					return fmt.Errorf("write output: %w", err)
				}
				logger.Info("export complete", "output", outputPath, "size", len(data))
				fmt.Printf("Exported CycloneDX BOM to %s (%d bytes)\n", outputPath, len(data))
				return nil
			}

			os.Stdout.Write(data)
			fmt.Println()
			return nil
		},
	}

	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "Output file path (default: stdout)")

	return cmd
}
