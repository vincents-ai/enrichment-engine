package integration

import (
	"context"
	"database/sql"
	"encoding/json"
	"log/slog"
	"os"
	"testing"
	"time"

	_ "github.com/glebarez/go-sqlite/compat"
	"github.com/shift/enrichment-engine/pkg/enricher"
	"github.com/shift/enrichment-engine/pkg/grc"
	grcbuiltin "github.com/shift/enrichment-engine/pkg/grc/builtin"
	"github.com/shift/enrichment-engine/pkg/storage"
)

var sampleVulns = []map[string]interface{}{
	{
		"id": "CVE-2024-12345",
		"cve": map[string]interface{}{
			"id": "CVE-2024-12345",
			"weaknesses": []map[string]interface{}{
				{"description": []map[string]string{{"lang": "en", "value": "CWE-79"}}},
			},
			"configurations": []map[string]interface{}{
				{"nodes": []map[string]interface{}{
					{"cpeMatch": []map[string]string{
						{"criteria": "cpe:2.3:a:apache:log4j:2.14.0:*:*:*:*:*:*:*"},
					}},
				}},
			},
		},
	},
	{
		"id": "CVE-2024-67890",
		"cve": map[string]interface{}{
			"id": "CVE-2024-67890",
			"weaknesses": []map[string]interface{}{
				{"description": []map[string]string{{"lang": "en", "value": "CWE-89"}}},
			},
			"configurations": []map[string]interface{}{},
		},
	},
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func setupTestDB(t *testing.T) *storage.SQLiteBackend {
	t.Helper()
	path := t.TempDir() + "/integration.db"
	backend, err := storage.NewSQLiteBackend(path)
	if err != nil {
		t.Fatalf("NewSQLiteBackend: %v", err)
	}
	t.Cleanup(func() { backend.Close(context.Background()) })
	return backend
}

func TestIntegration_ProviderWritesToStorage(t *testing.T) {
	backend := setupTestDB(t)
	logger := testLogger()
	registry := grcbuiltin.DefaultRegistry()

	for _, name := range []string{"hipaa", "gdpr", "iso27001"} {
		p, err := registry.Get(name, backend, logger)
		if err != nil {
			t.Fatalf("get provider %s: %v", name, err)
		}
		count, err := p.Run(context.Background())
		if err != nil {
			t.Fatalf("run provider %s: %v", name, err)
		}
		if count <= 0 {
			t.Errorf("provider %s wrote 0 controls", name)
		}
	}

	controls, err := backend.ListAllControls(context.Background())
	if err != nil {
		t.Fatalf("list controls: %v", err)
	}
	if len(controls) < 10 {
		t.Fatalf("expected at least 10 controls, got %d", len(controls))
	}

	frameworks := make(map[string]bool)
	for _, c := range controls {
		frameworks[c.Framework] = true
	}
	for _, fw := range []string{"HIPAA_SECURITY_RULE_2013", "GDPR_2016_679", "ISO_27001_2022"} {
		if !frameworks[fw] {
			t.Errorf("missing framework %s", fw)
		}
	}

	for _, c := range controls {
		data, err := backend.ReadControl(context.Background(), c.ID)
		if err != nil {
			t.Errorf("read control %s: %v", c.ID, err)
		}
		if len(data) == 0 {
			t.Errorf("empty record for control %s", c.ID)
		}
		if !json.Valid(data) {
			t.Errorf("invalid JSON for control %s", c.ID)
		}
	}
}

func TestIntegration_AllProvidersRun(t *testing.T) {
	backend := setupTestDB(t)
	logger := testLogger()
	registry := grcbuiltin.DefaultRegistry()

	total, err := registry.RunAll(context.Background(), backend, logger)
	if err != nil {
		t.Fatalf("RunAll: %v", err)
	}

	t.Logf("all providers wrote %d total controls", total)
	if total <= 500 {
		t.Errorf("expected > 500 controls, got %d", total)
	}

	controls, err := backend.ListAllControls(context.Background())
	if err != nil {
		t.Fatalf("list controls: %v", err)
	}
	if len(controls) != total {
		t.Errorf("DB has %d controls but providers reported %d", len(controls), total)
	}
}

func TestIntegration_CWEMapping(t *testing.T) {
	backend := setupTestDB(t)
	ctx := context.Background()

	vulnRecord := map[string]interface{}{
		"id": "CVE-2024-TEST-CWE",
		"cve": map[string]interface{}{
			"id": "CVE-2024-TEST-CWE",
			"weaknesses": []map[string]interface{}{
				{"description": []map[string]string{{"lang": "en", "value": "CWE-79"}}},
			},
			"configurations": []interface{}{},
		},
	}
	err := backend.WriteVulnerability(ctx, "CVE-2024-TEST-CWE", vulnRecord)
	if err != nil {
		t.Fatalf("write vulnerability: %v", err)
	}

	control := grc.Control{
		Framework:   "TEST_FRAMEWORK",
		ControlID:   "TEST-CTRL-1",
		Title:       "Input Validation",
		Description: "Validate all input",
		RelatedCWEs: []string{"CWE-79"},
	}
	err = backend.WriteControl(ctx, "TEST_FRAMEWORK/TEST-CTRL-1", control)
	if err != nil {
		t.Fatalf("write control: %v", err)
	}

	engine := enricher.New(enricher.Config{
		Store:         backend,
		Logger:        testLogger(),
		SkipProviders: true,
	})
	count, err := engine.Run(ctx)
	if err != nil {
		t.Fatalf("engine run: %v", err)
	}

	allCtrls, _ := backend.ListAllControls(ctx)
	t.Logf("total controls: %d", len(allCtrls))
	for _, c := range allCtrls {
		if c.ID == "TEST_FRAMEWORK/TEST-CTRL-1" {
			t.Logf("  test ctrl: cwes=%v, record=%s", c.RelatedCWEs, string(c.Record))
		}
	}

	ctrls, _ := backend.ListControlsByCWE(ctx, "CWE-79")
	t.Logf("controls with CWE-79: %d", len(ctrls))

	if count.MappingCount < 1 {
		t.Fatalf("expected at least 1 mapping, got %d", count.MappingCount)
	}

	mappings, err := backend.ListMappings(ctx, "CVE-2024-TEST-CWE")
	if err != nil {
		t.Fatalf("list mappings: %v", err)
	}
	if len(mappings) == 0 {
		t.Fatal("no mappings found for CVE-2024-TEST-CWE")
	}

	found := false
	for _, m := range mappings {
		if m.ControlID == "TEST_FRAMEWORK/TEST-CTRL-1" && m.MappingType == "cwe" {
			found = true
			if m.Confidence != 0.8 {
				t.Errorf("expected confidence 0.8, got %f", m.Confidence)
			}
		}
	}
	if !found {
		t.Errorf("mapping to TEST_FRAMEWORK/TEST-CTRL-1 not found in %v", mappings)
	}
}

func TestIntegration_EnrichSBOM(t *testing.T) {
	backend := setupTestDB(t)
	ctx := context.Background()

	control := grc.Control{
		Framework:   "TEST_FW",
		ControlID:   "TC-1",
		Title:       "Test Control",
		Description: "A test control",
	}
	backend.WriteControl(ctx, "TEST_FW/TC-1", control)

	engine := enricher.New(enricher.Config{
		Store:  backend,
		Logger: testLogger(),
	})

	components := []grc.SBOMComponent{
		{
			Name:    "log4j-core",
			Version: "2.14.0",
			Type:    "library",
			CPEs:    []string{"cpe:2.3:a:apache:log4j:2.14.0:*:*:*:*:*:*:*"},
		},
		{
			Name:    "safe-lib",
			Version: "1.0.0",
			Type:    "library",
			CPEs:    []string{},
		},
	}

	enriched, err := engine.EnrichSBOM(ctx, components)
	if err != nil {
		t.Fatalf("EnrichSBOM: %v", err)
	}
	if len(enriched) != 2 {
		t.Fatalf("expected 2 enriched components, got %d", len(enriched))
	}

	if enriched[0].ComplianceRisk != "needs-review" {
		t.Errorf("expected compliance risk 'needs-review' for log4j, got %q", enriched[0].ComplianceRisk)
	}
	if len(enriched[0].Controls) == 0 {
		t.Error("expected controls for log4j component")
	}

	if enriched[1].ComplianceRisk != "" {
		t.Errorf("expected empty compliance risk for safe-lib, got %q", enriched[1].ComplianceRisk)
	}
}

func TestIntegration_FullPipeline(t *testing.T) {
	backend := setupTestDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	logger := testLogger()

	for _, vuln := range sampleVulns {
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

	t.Logf("full pipeline: %d controls, %d mappings, duration %v",
		result.ControlCount, result.MappingCount, result.Duration)

	if result.ControlCount <= 0 {
		t.Error("expected controls to be written")
	}
	if result.MappingCount <= 0 {
		t.Errorf("expected mappings from sample vulns with CWE-79/CWE-89, got %d", result.MappingCount)
	}

	vulns, err := backend.ListAllVulnerabilities(ctx)
	if err != nil {
		t.Fatalf("list vulnerabilities: %v", err)
	}
	if len(vulns) != 2 {
		t.Errorf("expected 2 vulnerabilities, got %d", len(vulns))
	}
}

func TestIntegration_DatabasePersistence(t *testing.T) {
	dir := t.TempDir()
	dbPath := dir + "/persist.db"

	backend, err := storage.NewSQLiteBackend(dbPath)
	if err != nil {
		t.Fatalf("create db: %v", err)
	}

	control := grc.Control{
		Framework:   "TEST_FW",
		ControlID:   "PERSIST-1",
		Title:       "Persistent Control",
		Description: "Survives close and reopen",
		RelatedCWEs: []string{"CWE-79", "CWE-89"},
	}
	err = backend.WriteControl(context.Background(), "TEST_FW/PERSIST-1", control)
	if err != nil {
		t.Fatalf("write control: %v", err)
	}

	data, err := backend.ReadControl(context.Background(), "TEST_FW/PERSIST-1")
	if err != nil {
		t.Fatalf("read before close: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("control empty before close")
	}

	err = backend.Close(context.Background())
	if err != nil {
		t.Fatalf("close db: %v", err)
	}

	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		t.Fatal("committed database file does not exist after close")
	}

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("reopen raw db: %v", err)
	}
	defer db.Close()

	var count int
	err = db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM grc_controls").Scan(&count)
	if err != nil {
		t.Fatalf("count controls: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 control in committed db, got %d", count)
	}

	var recordData []byte
	err = db.QueryRowContext(context.Background(), "SELECT record FROM grc_controls WHERE id = ?", "TEST_FW/PERSIST-1").Scan(&recordData)
	if err != nil {
		t.Fatalf("read committed record: %v", err)
	}

	var readCtrl grc.Control
	if err := json.Unmarshal(recordData, &readCtrl); err != nil {
		t.Fatalf("unmarshal committed control: %v", err)
	}
	if readCtrl.ControlID != "PERSIST-1" {
		t.Errorf("expected ControlID PERSIST-1, got %s", readCtrl.ControlID)
	}
	if readCtrl.Title != "Persistent Control" {
		t.Errorf("expected title 'Persistent Control', got %s", readCtrl.Title)
	}
	if len(readCtrl.RelatedCWEs) != 2 {
		t.Errorf("expected 2 RelatedCWEs, got %d", len(readCtrl.RelatedCWEs))
	}
}
