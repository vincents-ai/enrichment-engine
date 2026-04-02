//go:build integration

package scenario

import (
	"context"
	"log/slog"
	"os"
	"testing"

	_ "github.com/glebarez/go-sqlite/compat"
	"github.com/shift/enrichment-engine/pkg/enricher"
	"github.com/shift/enrichment-engine/pkg/grc"
	grcbuiltin "github.com/shift/enrichment-engine/pkg/grc/builtin"
	"github.com/shift/enrichment-engine/pkg/storage"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func setupScenarioDB(t *testing.T) *storage.SQLiteBackend {
	t.Helper()
	path := t.TempDir() + "/scenario.db"
	backend, err := storage.NewSQLiteBackend(path)
	if err != nil {
		t.Fatalf("NewSQLiteBackend: %v", err)
	}
	t.Cleanup(func() { backend.Close(context.Background()) })
	return backend
}

func TestE2E_FullPipelineWithRealDB(t *testing.T) {
	backend := setupScenarioDB(t)
	ctx := context.Background()
	logger := testLogger()

	for _, vuln := range sampleNVDCVEs {
		err := backend.WriteVulnerability(ctx, vuln["id"].(string), vuln)
		if err != nil {
			t.Fatalf("write vulnerability %s: %v", vuln["id"], err)
		}
	}

	registry := grcbuiltin.DefaultRegistry()
	total, err := registry.RunAll(ctx, backend, logger)
	if err != nil {
		t.Fatalf("RunAll: %v", err)
	}
	t.Logf("providers wrote %d controls", total)

	engine := enricher.New(enricher.Config{
		Store:  backend,
		Logger: logger,
	})
	result, err := engine.Run(ctx)
	if err != nil {
		t.Fatalf("engine run: %v", err)
	}

	t.Logf("full pipeline: controls=%d, mappings=%d, duration=%v",
		result.ControlCount, result.MappingCount, result.Duration)

	if result.ControlCount <= 0 {
		t.Error("expected controls to be written")
	}
	if result.MappingCount <= 0 {
		t.Errorf("expected mappings from sample NVD data, got %d", result.MappingCount)
	}

	vulns, err := backend.ListAllVulnerabilities(ctx)
	if err != nil {
		t.Fatalf("list vulns: %v", err)
	}
	if len(vulns) != len(sampleNVDCVEs) {
		t.Errorf("expected %d vulnerabilities, got %d", len(sampleNVDCVEs), len(vulns))
	}

	for _, vuln := range vulns {
		mappings, err := backend.ListMappings(ctx, vuln.ID)
		if err != nil {
			t.Fatalf("list mappings for %s: %v", vuln.ID, err)
		}
		t.Logf("  %s: %d mappings", vuln.ID, len(mappings))
	}
}

func TestE2E_RegistryAllProvidersComplete(t *testing.T) {
	backend := setupScenarioDB(t)
	ctx := context.Background()
	logger := testLogger()
	registry := grcbuiltin.DefaultRegistry()

	names := registry.List()
	t.Logf("registry has %d providers", len(names))

	failed := []string{}
	for _, name := range names {
		p, err := registry.Get(name, backend, logger)
		if err != nil {
			t.Errorf("get provider %s: %v", name, err)
			continue
		}
		count, err := p.Run(ctx)
		if err != nil {
			t.Logf("provider %s error (non-fatal): %v", name, err)
			failed = append(failed, name)
			continue
		}
		if count <= 0 {
			t.Logf("provider %s wrote 0 controls", name)
		}
	}

	if len(failed) > 0 {
		t.Logf("providers with errors: %v", failed)
	}

	controls, err := backend.ListAllControls(ctx)
	if err != nil {
		t.Fatalf("list controls: %v", err)
	}
	t.Logf("total controls in DB: %d", len(controls))
	if len(controls) <= 500 {
		t.Errorf("expected > 500 controls, got %d", len(controls))
	}
}

func TestE2E_EnrichmentWithRealNVDData(t *testing.T) {
	backend := setupScenarioDB(t)
	ctx := context.Background()
	logger := testLogger()

	registry := grcbuiltin.DefaultRegistry()
	total, err := registry.RunAll(ctx, backend, logger)
	if err != nil {
		t.Fatalf("RunAll: %v", err)
	}
	t.Logf("loaded %d controls", total)

	for _, vuln := range sampleNVDCVEs {
		err := backend.WriteVulnerability(ctx, vuln["id"].(string), vuln)
		if err != nil {
			t.Fatalf("write vuln %s: %v", vuln["id"], err)
		}
	}

	engine := enricher.New(enricher.Config{
		Store:  backend,
		Logger: logger,
	})

	result, err := engine.Run(ctx)
	if err != nil {
		t.Fatalf("engine run: %v", err)
	}

	t.Logf("mappings created: %d", result.MappingCount)

	for _, vuln := range sampleNVDCVEs {
		vulnID := vuln["id"].(string)
		mappings, err := backend.ListMappings(ctx, vulnID)
		if err != nil {
			t.Fatalf("list mappings for %s: %v", vulnID, err)
		}

		cweMappings := 0
		cpeMappings := 0
		for _, m := range mappings {
			if m.MappingType == "cwe" {
				cweMappings++
			} else if m.MappingType == "cpe" {
				cpeMappings++
			}
		}
		t.Logf("  %s: %d CWE mappings, %d CPE mappings", vulnID, cweMappings, cpeMappings)
	}

	totalMappings := 0
	for _, vuln := range sampleNVDCVEs {
		vulnID := vuln["id"].(string)
		mappings, _ := backend.ListMappings(ctx, vulnID)
		totalMappings += len(mappings)
	}

	if totalMappings == 0 {
		t.Errorf("expected at least some mappings across all sample CVEs, got 0")
	}

	components := []grc.SBOMComponent{
		{
			Name:    "log4j-core",
			Version: "2.14.0",
			Type:    "library",
			CPEs:    []string{"cpe:2.3:a:apache:log4j:2.14.0:*:*:*:*:*:*:*"},
		},
	}

	enriched, err := engine.EnrichSBOM(ctx, components)
	if err != nil {
		t.Fatalf("EnrichSBOM: %v", err)
	}
	if len(enriched) != 1 {
		t.Fatalf("expected 1 enriched component, got %d", len(enriched))
	}
	t.Logf("enriched log4j: controls=%d, risk=%q", len(enriched[0].Controls), enriched[0].ComplianceRisk)
}
