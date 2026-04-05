package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/shift/enrichment-engine/pkg/storage"
	"github.com/spf13/cobra"
)

func ingestCmd() *cobra.Command {
	var filePath string

	cmd := &cobra.Command{
		Use:   "ingest",
		Short: "Load NVD 2.0 JSON vulnerability files into the enrichment DB",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			logger := slog.Default()

			var reader io.Reader
			if filePath != "" {
				f, err := os.Open(filePath)
				if err != nil {
					return fmt.Errorf("open file: %w", err)
				}
				defer f.Close()
				reader = f
			} else {
				reader = os.Stdin
			}

			data, err := io.ReadAll(reader)
			if err != nil {
				return fmt.Errorf("read input: %w", err)
			}

			if len(data) == 0 {
				return fmt.Errorf("empty input: no JSON data provided")
			}

			var records []json.RawMessage
			data = bytes.TrimSpace(data)

			if data[0] == '[' {
				if err := json.Unmarshal(data, &records); err != nil {
					return fmt.Errorf("parse JSON array: %w", err)
				}
			} else {
				if err := json.Unmarshal(data, &map[string]interface{}{}); err != nil {
					return fmt.Errorf("parse JSON object: %w", err)
				}
				records = []json.RawMessage{data}
			}

			store, err := storage.NewSQLiteBackend(workspace + "/enrichment.db")
			if err != nil {
				return fmt.Errorf("initialize storage: %w", err)
			}
			defer store.Close(ctx)

			count := 0
			for _, raw := range records {
				var parsed struct {
					ID string `json:"id"`
				}
				if err := json.Unmarshal(raw, &parsed); err != nil {
					return fmt.Errorf("parse record: %w", err)
				}
				if parsed.ID == "" {
					return fmt.Errorf("record missing required \"id\" field")
				}

				if err := store.WriteVulnerability(ctx, parsed.ID, json.RawMessage(raw)); err != nil {
					return fmt.Errorf("write vulnerability %s: %w", parsed.ID, err)
				}
				count++
			}

			logger.Info("ingest complete", "count", count, "source", filePath)
			fmt.Printf("Ingested %d vulnerabilities\n", count)
			return nil
		},
	}

	cmd.Flags().StringVarP(&filePath, "file", "f", "", "Path to NVD 2.0 JSON file (default: stdin)")

	return cmd
}
