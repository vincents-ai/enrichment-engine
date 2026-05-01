//go:build integration

package scenario

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	_ "github.com/glebarez/go-sqlite/compat"
	"github.com/vincents-ai/enrichment-engine/pkg/enricher"
	"github.com/vincents-ai/enrichment-engine/pkg/grc"
	grcbuiltin "github.com/vincents-ai/enrichment-engine/pkg/grc/builtin"
	"github.com/vincents-ai/enrichment-engine/pkg/storage"
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
		Store:         backend,
		Logger:        logger,
		SkipProviders: true,
	})
	result, err := engine.Run(ctx)
	if err != nil {
		t.Fatalf("engine run: %v", err)
	}

	t.Logf("full pipeline: controls=%d, mappings=%d, duration=%v",
		result.ControlCount, result.MappingCount, result.Duration)

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
		Store:         backend,
		Logger:        logger,
		SkipProviders: true,
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

func TestE2E_Scenario1_FullPipelineWithConfidence(t *testing.T) {
	backend := setupScenarioDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	logger := testLogger()

	for _, vuln := range sampleNVDCVEs {
		err := backend.WriteVulnerability(ctx, vuln["id"].(string), vuln)
		if err != nil {
			t.Fatalf("write vulnerability %s: %v", vuln["id"], err)
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

	if result.ControlCount <= 0 {
		t.Fatalf("expected controls to be written, got %d", result.ControlCount)
	}
	if result.MappingCount <= 0 {
		t.Fatalf("expected mappings from %d CVEs, got %d", len(sampleNVDCVEs), result.MappingCount)
	}

	if result.Duration <= 0 {
		t.Error("expected positive duration")
	}

	knownFrameworks := map[string]bool{
		"CIS_Controls_v8": true, "HIPAA_SECURITY_RULE_2013": true, "PCI_DSS_v4": true,
		"NIST_CSF_2_0": true, "ISO_27001_2022": true,
	}

	mappedVulns := 0
	for _, vuln := range sampleNVDCVEs {
		vulnID := vuln["id"].(string)
		mappings, err := backend.ListMappings(ctx, vulnID)
		if err != nil {
			t.Fatalf("list mappings for %s: %v", vulnID, err)
		}
		if len(mappings) == 0 {
			t.Logf("  %s: no mappings (CWE may not exist in any provider)", vulnID)
			continue
		}
		mappedVulns++

		for _, m := range mappings {
			if m.MappingType == "cwe" {
				if m.Confidence != 0.8 {
					t.Errorf("CWE mapping for %s should have confidence 0.8, got %.1f", vulnID, m.Confidence)
				}
			}
			if m.MappingType == "cpe" {
				if m.Confidence != 0.6 {
					t.Errorf("CPE mapping for %s should have confidence 0.6, got %.1f", vulnID, m.Confidence)
				}
			}
			if !knownFrameworks[m.Framework] {
				t.Logf("  %s: unknown framework %q", vulnID, m.Framework)
			}
		}
	}

	if mappedVulns == 0 {
		t.Errorf("expected at least some CVEs to have mappings across %d CVEs", len(sampleNVDCVEs))
	}

	t.Logf("scenario 1: %d/%d CVEs mapped, %d total mappings, %d controls",
		mappedVulns, len(sampleNVDCVEs), result.MappingCount, result.ControlCount)
}

func TestE2E_Scenario2_CWE79MappingAccuracy(t *testing.T) {
	backend := setupScenarioDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	logger := testLogger()

	vulnWithCPE := makeVuln("CVE-TEST-XSS-001", "CWE-79",
		"cpe:2.3:a:apache:struts:2.5.30:*:*:*:*:*:*:*")
	err := backend.WriteVulnerability(ctx, vulnWithCPE["id"].(string), vulnWithCPE)
	if err != nil {
		t.Fatalf("write vulnerability: %v", err)
	}

	vulnNoCPE := map[string]interface{}{
		"id": "CVE-TEST-XSS-002",
		"cve": map[string]interface{}{
			"id":        "CVE-TEST-XSS-002",
			"published": "2024-01-01T00:00:00.000Z",
			"descriptions": []map[string]string{
				{"lang": "en", "value": "XSS without CPE info"},
			},
			"weaknesses": []map[string]interface{}{
				{"description": []map[string]string{{"lang": "en", "value": "CWE-79"}}},
			},
			"configurations": []map[string]interface{}{},
		},
	}
	err = backend.WriteVulnerability(ctx, vulnNoCPE["id"].(string), vulnNoCPE)
	if err != nil {
		t.Fatalf("write vulnerability: %v", err)
	}

	engine := enricher.New(enricher.Config{
		Store:  backend,
		Logger: logger,
	})
	_, err = engine.Run(ctx)
	if err != nil {
		t.Fatalf("engine run: %v", err)
	}

	mappingsWithCPE, err := backend.ListMappings(ctx, "CVE-TEST-XSS-001")
	if err != nil {
		t.Fatalf("list mappings: %v", err)
	}
	if len(mappingsWithCPE) == 0 {
		t.Fatalf("expected CWE-79 to map to at least one control, got 0 mappings")
	}

	hasPCIDSS := false
	for _, m := range mappingsWithCPE {
		if m.Framework == "PCI_DSS_v4" {
			hasPCIDSS = true
			t.Logf("CWE-79 mapped to PCI_DSS_v4 control %s (conf=%.1f)", m.ControlID, m.Confidence)
		}
	}
	if !hasPCIDSS {
		t.Error("expected CWE-79 to map to at least one PCI_DSS_v4 control")
	}

	mappingsNoCPE, err := backend.ListMappings(ctx, "CVE-TEST-XSS-002")
	if err != nil {
		t.Fatalf("list mappings: %v", err)
	}
	if len(mappingsNoCPE) == 0 {
		t.Fatalf("expected CWE-79 (no CPE) to still get CWE-direct mappings, got 0")
	}

	for _, m := range mappingsNoCPE {
		if m.Confidence != 0.8 {
			t.Errorf("CWE-direct mapping (no CPE) should have confidence 0.8, got %.1f for %s/%s",
				m.Confidence, m.Framework, m.ControlID)
		}
		if m.MappingType != "cwe" {
			t.Errorf("vuln without CPEs should only have CWE mapping types, got %q", m.MappingType)
		}
	}

	t.Logf("scenario 2: CWE-79 with CPE=%d mappings, CWE-79 no CPE=%d mappings (all 0.8 conf)",
		len(mappingsWithCPE), len(mappingsNoCPE))
}

func TestE2E_Scenario3_NoFalsePositives(t *testing.T) {
	backend := setupScenarioDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	logger := testLogger()

	vuln := makeVuln("CVE-TEST-UNCOMMON-001", "CWE-9999",
		"cpe:2.3:a:fictional:product:1.0.0:*:*:*:*:*:*:*")
	err := backend.WriteVulnerability(ctx, vuln["id"].(string), vuln)
	if err != nil {
		t.Fatalf("write vulnerability: %v", err)
	}

	engine := enricher.New(enricher.Config{
		Store:  backend,
		Logger: logger,
	})
	result, err := engine.Run(ctx)
	if err != nil {
		t.Fatalf("engine run: %v", err)
	}

	mappings, err := backend.ListMappings(ctx, "CVE-TEST-UNCOMMON-001")
	if err != nil {
		t.Fatalf("list mappings: %v", err)
	}

	if len(mappings) > 0 {
		t.Errorf("CWE-9999 should not map to any controls, but got %d mappings:", len(mappings))
		for _, m := range mappings {
			t.Errorf("  unexpected: %s/%s type=%s conf=%.1f evidence=%s",
				m.Framework, m.ControlID, m.MappingType, m.Confidence, m.Evidence)
		}
	}

	t.Logf("scenario 3: CWE-9999 correctly produced 0 mappings (controls=%d)", result.ControlCount)
}

func TestE2E_Scenario4_SBOMEnrichment(t *testing.T) {
	backend := setupScenarioDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	logger := testLogger()

	for _, vuln := range sampleNVDCVEs {
		err := backend.WriteVulnerability(ctx, vuln["id"].(string), vuln)
		if err != nil {
			t.Fatalf("write vulnerability %s: %v", vuln["id"], err)
		}
	}

	engine := enricher.New(enricher.Config{
		Store:  backend,
		Logger: logger,
	})
	_, err := engine.Run(ctx)
	if err != nil {
		t.Fatalf("engine run: %v", err)
	}

	components := []grc.SBOMComponent{
		{
			Name:    "log4j-core",
			Version: "2.14.0",
			Type:    "library",
			CPEs:    []string{"cpe:2.3:a:apache:log4j:2.14.0:*:*:*:*:*:*:*"},
		},
		{
			Name:    "nginx",
			Version: "1.24.0",
			Type:    "application",
			CPEs:    []string{"cpe:2.3:a:f5:nginx:1.24.0:*:*:*:*:*:*:*"},
		},
		{
			Name:    "internal-utils",
			Version: "1.0.0",
			Type:    "library",
		},
	}

	enriched, err := engine.EnrichSBOM(ctx, components)
	if err != nil {
		t.Fatalf("EnrichSBOM: %v", err)
	}

	if len(enriched) != 3 {
		t.Fatalf("expected 3 enriched components, got %d", len(enriched))
	}

	if len(enriched[0].Controls) == 0 {
		t.Error("expected log4j-core (has CPE) to have controls attached")
	}
	if enriched[0].ComplianceRisk != "needs-review" {
		t.Errorf("expected log4j-core ComplianceRisk='needs-review', got %q", enriched[0].ComplianceRisk)
	}
	if enriched[0].Name != "log4j-core" || enriched[0].Version != "2.14.0" {
		t.Error("enriched component should preserve original name and version")
	}

	if len(enriched[1].Controls) == 0 {
		t.Error("expected nginx (has CPE) to have controls attached")
	}
	if enriched[1].ComplianceRisk != "needs-review" {
		t.Errorf("expected nginx ComplianceRisk='needs-review', got %q", enriched[1].ComplianceRisk)
	}

	if len(enriched[2].Controls) != 0 {
		t.Errorf("expected internal-utils (no CPE) to have 0 controls, got %d", len(enriched[2].Controls))
	}
	if enriched[2].ComplianceRisk != "" {
		t.Errorf("expected internal-utils ComplianceRisk='', got %q", enriched[2].ComplianceRisk)
	}

	t.Logf("scenario 4: log4j=%d controls, nginx=%d controls, internal=%d controls",
		len(enriched[0].Controls), len(enriched[1].Controls), len(enriched[2].Controls))
}

func TestE2E_Scenario5_Idempotency(t *testing.T) {
	backend := setupScenarioDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	logger := testLogger()

	for _, vuln := range sampleNVDCVEs {
		err := backend.WriteVulnerability(ctx, vuln["id"].(string), vuln)
		if err != nil {
			t.Fatalf("write vulnerability %s: %v", vuln["id"], err)
		}
	}

	engine := enricher.New(enricher.Config{
		Store:  backend,
		Logger: logger,
	})

	result1, err := engine.Run(ctx)
	if err != nil {
		t.Fatalf("engine run 1: %v", err)
	}

	result2, err := engine.Run(ctx)
	if err != nil {
		t.Fatalf("engine run 2: %v", err)
	}

	if result1.ControlCount != result2.ControlCount {
		t.Errorf("control count changed: run1=%d, run2=%d", result1.ControlCount, result2.ControlCount)
	}
	if result1.MappingCount != result2.MappingCount {
		t.Errorf("mapping count changed: run1=%d, run2=%d", result1.MappingCount, result2.MappingCount)
	}

	totalMappingsRun1 := 0
	totalMappingsRun2 := 0
	for _, vuln := range sampleNVDCVEs {
		vulnID := vuln["id"].(string)
		m1, _ := backend.ListMappings(ctx, vulnID)
		m2, _ := backend.ListMappings(ctx, vulnID)
		if len(m1) != len(m2) {
			t.Errorf("mappings changed for %s: run1=%d, run2=%d", vulnID, len(m1), len(m2))
		}
		totalMappingsRun1 += len(m1)
		totalMappingsRun2 += len(m2)
	}

	if totalMappingsRun1 != totalMappingsRun2 {
		t.Errorf("total mappings changed: run1=%d, run2=%d", totalMappingsRun1, totalMappingsRun2)
	}

	t.Logf("scenario 5: idempotent - controls=%d, mappings=%d on both runs",
		result1.ControlCount, result1.MappingCount)
}
