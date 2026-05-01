package verification

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/vincents-ai/enrichment-engine/pkg/enricher"
	"github.com/vincents-ai/enrichment-engine/pkg/storage"
)

func setupVerificationDB(t *testing.T) *storage.SQLiteBackend {
	t.Helper()
	path := t.TempDir() + "/verification.db"
	backend, err := storage.NewSQLiteBackend(path)
	if err != nil {
		t.Fatalf("setup verification db: %v", err)
	}
	t.Cleanup(func() { backend.Close(context.Background()) })
	return backend
}

func runFullPipeline(t *testing.T, backend *storage.SQLiteBackend) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	engine := enricher.New(enricher.Config{
		Store:       backend,
		Logger:      testLogger(),
		MaxParallel: 4,
	})

	result, err := engine.Run(ctx)
	if err != nil {
		t.Fatalf("full pipeline run: %v", err)
	}

	t.Logf("pipeline: %d providers, %d controls, %d vulns, %d mappings, %s",
		result.ProviderCount, result.ControlCount, result.VulnCount,
		result.MappingCount, result.Duration)

	if result.ControlCount == 0 {
		t.Fatal("no controls loaded from providers")
	}
}

func loadCVEs(t *testing.T, backend storage.Backend, cves []cveRecord) {
	t.Helper()
	ctx := context.Background()
	for _, cve := range cves {
		if err := backend.WriteVulnerability(ctx, cve.ID, cve.ToMap()); err != nil {
			t.Fatalf("write CVE %s: %v", cve.ID, err)
		}
	}
}

func runMappingPhase(t *testing.T, backend storage.Backend) *enricher.Result {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	engine := enricher.New(enricher.Config{
		Store:         backend,
		Logger:        testLogger(),
		SkipProviders: true,
	})

	result, err := engine.Run(ctx)
	if err != nil {
		t.Fatalf("mapping phase: %v", err)
	}
	return result
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(&discardWriter{}, &slog.HandlerOptions{Level: slog.LevelWarn}))
}

type discardWriter struct{}

func (d *discardWriter) Write(p []byte) (n int, err error) {
	return len(p), nil
}

func TestCVEDataIntegrity(t *testing.T) {
	cves := AllRealCVEs()

	if len(cves) == 0 {
		t.Fatal("no CVE records defined")
	}

	for _, cve := range cves {
		t.Run(cve.ID, func(t *testing.T) {
			if cve.ID == "" {
				t.Fatal("empty CVE ID")
			}
			if cve.CVE.ID != cve.ID {
				t.Fatalf("ID mismatch: top-level=%s, inner=%s", cve.ID, cve.CVE.ID)
			}
			if len(cve.CVE.Weaknesses) == 0 {
				t.Fatal("no weaknesses defined")
			}
			if len(cve.CVE.Descriptions) == 0 {
				t.Fatal("no descriptions defined")
			}

			cweCount := 0
			for _, w := range cve.CVE.Weaknesses {
				for _, d := range w.Description {
					if d.Lang == "en" && len(d.Value) > 0 {
						cweCount++
					}
				}
			}
			if cweCount == 0 {
				t.Fatal("no English weakness descriptions")
			}

			cpeCount := 0
			for _, cfg := range cve.CVE.Configurations {
				for _, node := range cfg.Nodes {
					for _, match := range node.CPEMatch {
						if match.Criteria != "" {
							cpeCount++
						}
					}
				}
			}
			if cpeCount == 0 {
				t.Fatal("no CPE match criteria defined")
			}
		})
	}
}

func TestCVEToMapRoundTrip(t *testing.T) {
	for _, cve := range AllRealCVEs() {
		t.Run(cve.ID, func(t *testing.T) {
			m := cve.ToMap()

			if m["id"] != cve.ID {
				t.Fatalf("map id=%q, want=%q", m["id"], cve.ID)
			}

			cveMap, ok := m["cve"].(map[string]interface{})
			if !ok {
				t.Fatal("cve field is not a map")
			}
			if cveMap["id"] != cve.ID {
				t.Fatalf("cve.id=%q, want=%q", cveMap["id"], cve.ID)
			}

			weaknesses, ok := cveMap["weaknesses"].([]interface{})
			if !ok || len(weaknesses) == 0 {
				t.Fatal("weaknesses missing or empty")
			}
		})
	}
}

func TestExpectationsCoverage(t *testing.T) {
	cves := AllRealCVEs()
	cveIDs := make(map[string]bool)
	for _, cve := range cves {
		cveIDs[cve.ID] = true
	}

	for _, exp := range expectations {
		t.Run(exp.ID, func(t *testing.T) {
			if !cveIDs[exp.ID] {
				t.Fatalf("expectation references %s but no CVE data exists", exp.ID)
			}

			cve, ok := CVEByID(exp.ID)
			if !ok {
				t.Fatalf("CVEByID(%s) returned false", exp.ID)
			}

			var foundCWE bool
			for _, w := range cve.CVE.Weaknesses {
				for _, d := range w.Description {
					if d.Lang == "en" && d.Value == exp.CWE {
						foundCWE = true
					}
				}
			}
			if !foundCWE {
				t.Fatalf("CWE %s not found in %s data", exp.CWE, exp.ID)
			}
		})
	}
}

func TestPositiveCVEMappings(t *testing.T) {
	backend := setupVerificationDB(t)
	runFullPipeline(t, backend)

	positive := PositiveExpectations()
	if len(positive) == 0 {
		t.Fatal("no positive expectations defined")
	}

	t.Logf("testing %d CVEs expected to produce mappings", len(positive))

	var positiveCVEs []cveRecord
	for _, exp := range positive {
		cve, ok := CVEByID(exp.ID)
		if !ok {
			t.Fatalf("missing CVE data for %s", exp.ID)
		}
		positiveCVEs = append(positiveCVEs, cve)
	}

	loadCVEs(t, backend, positiveCVEs)
	result := runMappingPhase(t, backend)

	t.Logf("mapping result: %d mappings for %d CVEs", result.MappingCount, len(positiveCVEs))

	if result.VulnCount != len(positiveCVEs) {
		t.Errorf("vuln count=%d, want=%d", result.VulnCount, len(positiveCVEs))
	}

	for _, exp := range positive {
		t.Run(exp.ID+"_"+exp.Name, func(t *testing.T) {
			ctx := context.Background()
			mappings, err := backend.ListMappings(ctx, exp.ID)
			if err != nil {
				t.Fatalf("list mappings for %s: %v", exp.ID, err)
			}

			if len(mappings) < exp.MinMappings {
				t.Errorf("got %d mappings, expected at least %d for %s (%s)",
					len(mappings), exp.MinMappings, exp.ID, exp.Name)
			}
			if len(mappings) > exp.MaxMappings {
				t.Errorf("got %d mappings, expected at most %d for %s (%s)",
					len(mappings), exp.MaxMappings, exp.ID, exp.Name)
			}

			if len(exp.ExpectedCWEHits) > 0 {
				t.Run("specific_control_hits", func(t *testing.T) {
					hitSet := make(map[string]bool)
					for _, m := range mappings {
						key := m.Framework + ":" + m.ControlID
						hitSet[key] = true
					}

					for _, expected := range exp.ExpectedCWEHits {
						key := expected.Framework + ":" + expected.ControlID
						if !hitSet[key] {
							t.Errorf("expected mapping to %s/%s not found for %s (CWE %s)",
								expected.Framework, expected.ControlID, exp.ID, expected.CWE)
						}
					}
				})
			}

			if len(mappings) > 0 {
				t.Run("mapping_quality", func(t *testing.T) {
					frameworks := make(map[string]int)
					types := make(map[string]int)
					for _, m := range mappings {
						frameworks[m.Framework]++
						types[m.MappingType]++
					}

					if len(frameworks) < 2 {
						t.Logf("WARNING: only %d frameworks mapped for %s", len(frameworks), exp.ID)
					}
					if types["cwe"] == 0 && types["cpe"] == 0 {
						t.Error("no CWE-based or CPE-based mappings found")
					}
				})
			}
		})
	}
}

func TestNegativeCVEMappings(t *testing.T) {
	backend := setupVerificationDB(t)
	runFullPipeline(t, backend)

	negative := NegativeExpectations()
	if len(negative) == 0 {
		t.Skip("no negative expectations defined")
	}

	t.Logf("testing %d CVEs expected to produce zero mappings", len(negative))

	var negativeCVEs []cveRecord
	for _, exp := range negative {
		cve, ok := CVEByID(exp.ID)
		if !ok {
			t.Fatalf("missing CVE data for %s", exp.ID)
		}
		negativeCVEs = append(negativeCVEs, cve)
	}

	loadCVEs(t, backend, negativeCVEs)
	result := runMappingPhase(t, backend)

	t.Logf("mapping result: %d mappings for %d negative-test CVEs", result.MappingCount, len(negativeCVEs))

	for _, exp := range negative {
		t.Run(exp.ID+"_"+exp.Name, func(t *testing.T) {
			ctx := context.Background()
			mappings, err := backend.ListMappings(ctx, exp.ID)
			if err != nil {
				t.Fatalf("list mappings for %s: %v", exp.ID, err)
			}

			if len(mappings) != exp.MaxMappings {
				t.Errorf("expected %d mappings for %s (%s, CWE %s), got %d",
					exp.MaxMappings, exp.ID, exp.Name, exp.CWE, len(mappings))
			}
		})
	}
}

func TestSpring4ShellDeepVerification(t *testing.T) {
	backend := setupVerificationDB(t)
	runFullPipeline(t, backend)

	cve := CVE_2022_22965
	loadCVEs(t, backend, []cveRecord{cve})
	result := runMappingPhase(t, backend)

	t.Logf("Spring4Shell: %d total mappings", result.MappingCount)

	ctx := context.Background()
	mappings, _ := backend.ListMappings(ctx, cve.ID)

	cweMappings := 0
	cpeMappings := 0
	frameworks := make(map[string][]string)
	for _, m := range mappings {
		switch m.MappingType {
		case "cwe":
			cweMappings++
		case "cpe":
			cpeMappings++
		}
		frameworks[m.Framework] = append(frameworks[m.Framework], m.ControlID)
	}

	t.Logf("  CWE mappings: %d, CPE mappings: %d", cweMappings, cpeMappings)
	t.Logf("  Frameworks hit: %d", len(frameworks))

	for fw, controls := range frameworks {
		t.Logf("  %s: %v", fw, controls)
	}

	requiredFrameworks := []string{"PCI_DSS_v4", "ISO_27001_2022"}
	for _, fw := range requiredFrameworks {
		if _, ok := frameworks[fw]; !ok {
			t.Errorf("Spring4Shell (CWE-94) should map to %s framework", fw)
		}
	}

	if cweMappings == 0 {
		t.Error("expected CWE mappings for Spring4Shell (CWE-94) but got 0 — CWE mappings may have been overwritten by CPE mappings")
	}
	if cpeMappings == 0 {
		t.Error("expected CPE mappings for Spring4Shell but got 0")
	}

	for _, m := range mappings {
		if m.Confidence <= 0 {
			t.Errorf("mapping %s/%s has zero confidence", m.Framework, m.ControlID)
		}
		if m.Evidence == "" {
			t.Errorf("mapping %s/%s has no evidence", m.Framework, m.ControlID)
		}
	}
}

func TestXZUtilsBackdoorDeepVerification(t *testing.T) {
	backend := setupVerificationDB(t)
	runFullPipeline(t, backend)

	cve := CVE_2024_3094
	loadCVEs(t, backend, []cveRecord{cve})
	runMappingPhase(t, backend)

	ctx := context.Background()
	mappings, _ := backend.ListMappings(ctx, cve.ID)

	t.Logf("xz-utils backdoor: %d total mappings", len(mappings))

	frameworks := make(map[string][]string)
	for _, m := range mappings {
		frameworks[m.Framework] = append(frameworks[m.Framework], m.ControlID)
	}

	for fw, controls := range frameworks {
		t.Logf("  %s: %v", fw, controls)
	}

	supplyChainFrameworks := []string{"PCI_DSS_v4", "SOC2_TSC_2017", "ISO_27001_2022"}
	for _, fw := range supplyChainFrameworks {
		if _, ok := frameworks[fw]; !ok {
			t.Errorf("supply chain attack (CWE-506) should map to %s", fw)
		}
	}
}

func TestLog4ShellMappings(t *testing.T) {
	backend := setupVerificationDB(t)
	runFullPipeline(t, backend)

	cve := CVE_2021_44228
	loadCVEs(t, backend, []cveRecord{cve})
	runMappingPhase(t, backend)

	ctx := context.Background()
	mappings, _ := backend.ListMappings(ctx, cve.ID)

	if len(mappings) == 0 {
		t.Fatal("Log4Shell (CWE-502) should produce mappings after adding CWE-502 to providers")
	}

	t.Logf("Log4Shell: %d total mappings", len(mappings))

	frameworks := make(map[string][]string)
	for _, m := range mappings {
		frameworks[m.Framework] = append(frameworks[m.Framework], m.ControlID)
	}

	for fw, controls := range frameworks {
		t.Logf("  %s: %v", fw, controls)
	}

	requiredFrameworks := []string{"PCI_DSS_v4", "ISO_27001_2022", "SOC2_TSC_2017", "FEDRAMP_REV5", "CMMC_v2"}
	for _, fw := range requiredFrameworks {
		if _, ok := frameworks[fw]; !ok {
			t.Errorf("Log4Shell (CWE-502) should map to %s framework", fw)
		}
	}
}

func TestHeartbleedMappings(t *testing.T) {
	backend := setupVerificationDB(t)
	runFullPipeline(t, backend)

	cve := CVE_2014_0160
	loadCVEs(t, backend, []cveRecord{cve})
	runMappingPhase(t, backend)

	ctx := context.Background()
	mappings, _ := backend.ListMappings(ctx, cve.ID)

	if len(mappings) == 0 {
		t.Fatal("Heartbleed (CWE-119) should produce mappings after adding CWE-119 to providers")
	}

	t.Logf("Heartbleed: %d total mappings", len(mappings))

	frameworks := make(map[string][]string)
	for _, m := range mappings {
		frameworks[m.Framework] = append(frameworks[m.Framework], m.ControlID)
	}

	for fw, controls := range frameworks {
		t.Logf("  %s: %v", fw, controls)
	}

	requiredFrameworks := []string{"PCI_DSS_v4", "ISO_27001_2022", "SOC2_TSC_2017", "FEDRAMP_REV5", "CMMC_v2"}
	for _, fw := range requiredFrameworks {
		if _, ok := frameworks[fw]; !ok {
			t.Errorf("Heartbleed (CWE-119) should map to %s framework", fw)
		}
	}
}

func TestBatchAllCVEs(t *testing.T) {
	backend := setupVerificationDB(t)
	runFullPipeline(t, backend)

	allCVEs := AllRealCVEs()
	loadCVEs(t, backend, allCVEs)
	result := runMappingPhase(t, backend)

	t.Logf("batch test: %d CVEs -> %d total mappings", len(allCVEs), result.MappingCount)

	ctx := context.Background()
	totalFromDB := 0
	for _, cve := range allCVEs {
		mappings, _ := backend.ListMappings(ctx, cve.ID)
		totalFromDB += len(mappings)
	}

	if totalFromDB > result.MappingCount {
		t.Errorf("DB total=%d exceeds pipeline total=%d", totalFromDB, result.MappingCount)
	}

	if totalFromDB == 0 && result.MappingCount > 0 {
		t.Errorf("DB has 0 mappings but pipeline reports %d", result.MappingCount)
	}

	positiveCount := 0
	negativeCount := 0
	for _, cve := range allCVEs {
		mappings, _ := backend.ListMappings(ctx, cve.ID)
		if len(mappings) > 0 {
			positiveCount++
		} else {
			negativeCount++
		}
	}

	t.Logf("  CVEs with mappings: %d, without: %d", positiveCount, negativeCount)

	if positiveCount == 0 {
		t.Error("no CVEs produced any mappings")
	}
	if negativeCount == 0 {
		t.Logf("no CVEs produced zero mappings (no negative expectations defined)")
	}
}

func TestMappingEvidenceQuality(t *testing.T) {
	backend := setupVerificationDB(t)
	runFullPipeline(t, backend)

	for _, exp := range PositiveExpectations() {
		cve, ok := CVEByID(exp.ID)
		if !ok {
			continue
		}
		loadCVEs(t, backend, []cveRecord{cve})
	}

	runMappingPhase(t, backend)

	ctx := context.Background()
	totalChecked := 0
	for _, exp := range PositiveExpectations() {
		mappings, err := backend.ListMappings(ctx, exp.ID)
		if err != nil || len(mappings) == 0 {
			continue
		}

		t.Run(exp.ID+"_evidence", func(t *testing.T) {
			for _, m := range mappings {
				totalChecked++

				if m.Evidence == "" {
					t.Errorf("%s/%s: empty evidence field", m.Framework, m.ControlID)
				}
				if m.VulnerabilityID != exp.ID {
					t.Errorf("%s/%s: wrong vuln ID %s", m.Framework, m.ControlID, m.VulnerabilityID)
				}
				if m.ControlID == "" {
					t.Errorf("%s: empty control ID", m.Framework)
				}
				if m.Framework == "" {
					t.Errorf("%s: empty framework", m.ControlID)
				}
				if m.Confidence < 0.5 || m.Confidence > 1.0 {
					t.Errorf("%s/%s: confidence %.2f out of expected range [0.5, 1.0]",
						m.Framework, m.ControlID, m.Confidence)
				}
				if m.MappingType != "cwe" && m.MappingType != "cpe" {
					t.Errorf("%s/%s: unknown mapping type %q", m.Framework, m.ControlID, m.MappingType)
				}
			}
		})
	}

	t.Logf("checked evidence quality for %d total mappings", totalChecked)
}

func TestMOVEitSQLiNarrowMapping(t *testing.T) {
	backend := setupVerificationDB(t)
	runFullPipeline(t, backend)

	cve := CVE_2023_34362
	loadCVEs(t, backend, []cveRecord{cve})
	runMappingPhase(t, backend)

	ctx := context.Background()
	mappings, _ := backend.ListMappings(ctx, cve.ID)

	t.Logf("MOVEit SQLi: %d mappings", len(mappings))

	if len(mappings) > 20 {
		t.Errorf("SQL injection (CWE-89) has narrow coverage; expected <= 20 mappings, got %d", len(mappings))
	}

	pciHit := false
	for _, m := range mappings {
		if m.Framework == "PCI_DSS_v4" && m.ControlID == "PCI_DSS_v4/6.4" {
			pciHit = true
		}
	}
	if !pciHit {
		t.Error("MOVEit SQLi (CWE-89) should map to PCI_DSS_v4/6.4")
	}
}

func TestConcurrentCVELoading(t *testing.T) {
	backend := setupVerificationDB(t)
	runFullPipeline(t, backend)

	allCVEs := AllRealCVEs()

	done := make(chan error, len(allCVEs))
	for _, cve := range allCVEs {
		go func(c cveRecord) {
			ctx := context.Background()
			done <- backend.WriteVulnerability(ctx, c.ID, c.ToMap())
		}(cve)
	}

	for range allCVEs {
		if err := <-done; err != nil {
			t.Errorf("concurrent write failed: %v", err)
		}
	}

	ctx := context.Background()
	vulns, err := backend.ListAllVulnerabilities(ctx)
	if err != nil {
		t.Fatalf("list vulns: %v", err)
	}

	if len(vulns) != len(allCVEs) {
		t.Errorf("got %d vulns, want %d", len(vulns), len(allCVEs))
	}

	result := runMappingPhase(t, backend)
	t.Logf("concurrent load: %d CVEs -> %d mappings", len(allCVEs), result.MappingCount)
}

func TestConfluenceDeepVerification(t *testing.T) {
	backend := setupVerificationDB(t)
	runFullPipeline(t, backend)

	cve := CVE_2022_26134
	loadCVEs(t, backend, []cveRecord{cve})
	result := runMappingPhase(t, backend)

	t.Logf("Confluence RCE (CWE-287): %d total mappings", result.MappingCount)

	ctx := context.Background()
	mappings, _ := backend.ListMappings(ctx, cve.ID)

	frameworks := make(map[string][]string)
	cweMappings := 0
	cpeMappings := 0
	for _, m := range mappings {
		switch m.MappingType {
		case "cwe":
			cweMappings++
		case "cpe":
			cpeMappings++
		}
		frameworks[m.Framework] = append(frameworks[m.Framework], m.ControlID)
	}

	t.Logf("  CWE mappings: %d, CPE mappings: %d", cweMappings, cpeMappings)
	t.Logf("  Frameworks hit: %d", len(frameworks))

	for fw, controls := range frameworks {
		t.Logf("  %s: %v", fw, controls)
	}

	requiredFrameworks := []string{"PCI_DSS_v4", "ISO_27001_2022", "SOC2_TSC_2017", "FEDRAMP_REV5", "CIS_Controls_v8"}
	for _, fw := range requiredFrameworks {
		if _, ok := frameworks[fw]; !ok {
			t.Errorf("Confluence RCE (CWE-287) should map to %s framework", fw)
		}
	}

	if cweMappings == 0 {
		t.Error("expected CWE mappings for Confluence (CWE-287) but got 0")
	}

	for _, m := range mappings {
		if m.Confidence <= 0 {
			t.Errorf("mapping %s/%s has zero confidence", m.Framework, m.ControlID)
		}
		if m.Evidence == "" {
			t.Errorf("mapping %s/%s has no evidence", m.Framework, m.ControlID)
		}
	}
}

func TestPwnKitDeepVerification(t *testing.T) {
	backend := setupVerificationDB(t)
	runFullPipeline(t, backend)

	cve := CVE_2021_4034
	loadCVEs(t, backend, []cveRecord{cve})
	result := runMappingPhase(t, backend)

	t.Logf("PwnKit (CWE-269): %d total mappings", result.MappingCount)

	ctx := context.Background()
	mappings, _ := backend.ListMappings(ctx, cve.ID)

	frameworks := make(map[string][]string)
	cweMappings := 0
	cpeMappings := 0
	for _, m := range mappings {
		switch m.MappingType {
		case "cwe":
			cweMappings++
		case "cpe":
			cpeMappings++
		}
		frameworks[m.Framework] = append(frameworks[m.Framework], m.ControlID)
	}

	t.Logf("  CWE mappings: %d, CPE mappings: %d", cweMappings, cpeMappings)
	t.Logf("  Frameworks hit: %d", len(frameworks))

	for fw, controls := range frameworks {
		t.Logf("  %s: %v", fw, controls)
	}

	requiredFrameworks := []string{"ISO_27001_2022", "CIS_Controls_v8", "FEDRAMP_REV5"}
	for _, fw := range requiredFrameworks {
		if _, ok := frameworks[fw]; !ok {
			t.Errorf("PwnKit (CWE-269) should map to %s framework", fw)
		}
	}

	if cweMappings == 0 {
		t.Error("expected CWE mappings for PwnKit (CWE-269) but got 0")
	}

	for _, m := range mappings {
		if m.Confidence <= 0 {
			t.Errorf("mapping %s/%s has zero confidence", m.Framework, m.ControlID)
		}
		if m.Evidence == "" {
			t.Errorf("mapping %s/%s has no evidence", m.Framework, m.ControlID)
		}
	}
}
