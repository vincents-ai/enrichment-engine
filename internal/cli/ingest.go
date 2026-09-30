package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/spf13/cobra"
	"github.com/vincents-ai/enrichment-engine/pkg/storage"
	"github.com/vincents-ai/enrichment-engine/pkg/vulnnormal"
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

			// Records are normalized before storage rather than stored raw.
			//
			// The raw path required a top-level "id" and stored whatever
			// arrived, while the engine read weaknesses and configurations from
			// under a "cve" key. Those assumptions are mutually exclusive, so
			// neither supported input shape worked: an unwrapped CVE ingested
			// successfully and then produced zero mappings, and a real NVD 2.0
			// response file failed outright. Normalizing here means the engine
			// reads one shape, and an unreadable record is named rather than
			// stored to be discovered later as a silent empty result.
			count := 0
			for i, raw := range records {
				c, err := vulnnormal.Normalize(json.RawMessage(raw), "nvd")
				if err != nil {
					return fmt.Errorf("record %d of %d: %w", i+1, len(records), err)
				}
				stored, err := json.Marshal(c)
				if err != nil {
					return fmt.Errorf("re-serialize %s: %w", c.ID, err)
				}
				if err := store.WriteVulnerability(ctx, c.ID, json.RawMessage(stored)); err != nil {
					return fmt.Errorf("write vulnerability %s: %w", c.ID, err)
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
