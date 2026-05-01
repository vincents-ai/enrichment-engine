package scenario

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/vincents-ai/enrichment-engine/pkg/enricher"
	"github.com/vincents-ai/enrichment-engine/pkg/storage"
)

func leakLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func leakSetupDB(t *testing.T) *storage.SQLiteBackend {
	t.Helper()
	path := t.TempDir() + "/leakage.db"
	backend, err := storage.NewSQLiteBackend(path)
	if err != nil {
		t.Fatalf("NewSQLiteBackend: %v", err)
	}
	t.Cleanup(func() { backend.Close(context.Background()) })
	return backend
}

func seedControl(t *testing.T, db storage.Backend, id, framework, controlID, title string, cwes []string) {
	t.Helper()
	ctrl := map[string]interface{}{
		"Framework":   framework,
		"ControlID":   controlID,
		"Title":       title,
		"RelatedCWEs": cwes,
	}
	if err := db.WriteControl(context.Background(), id, ctrl); err != nil {
		t.Fatalf("WriteControl %s: %v", id, err)
	}
}

func TestLeakage_SeparateDatabasesIsolated(t *testing.T) {
	ctx := context.Background()
	logger := leakLogger()

	db1 := leakSetupDB(t)
	db2 := leakSetupDB(t)

	vulnA := makeVuln("CVE-TEST-A", "CWE-79", "cpe:2.3:a:apache:struts:2.5.30:*:*:*:*:*:*:*")
	if err := db1.WriteVulnerability(ctx, vulnA["id"].(string), vulnA); err != nil {
		t.Fatalf("write vulnA to db1: %v", err)
	}

	vulnB := makeVuln("CVE-TEST-B", "CWE-89", "cpe:2.3:a:mysql:mysql:8.0.0:*:*:*:*:*:*:*")
	if err := db2.WriteVulnerability(ctx, vulnB["id"].(string), vulnB); err != nil {
		t.Fatalf("write vulnB to db2: %v", err)
	}

	seedControl(t, db1, "ctrl-1", "PCI_DSS_v4", "6.5.1", "XSS Prevention", []string{"CWE-79"})

	engine := enricher.New(enricher.Config{
		Store:         db1,
		Logger:        logger,
		SkipProviders: true,
	})
	_, err := engine.Run(ctx)
	if err != nil {
		t.Fatalf("engine run on db1: %v", err)
	}

	controls2, err := db2.ListAllControls(ctx)
	if err != nil {
		t.Fatalf("list controls db2: %v", err)
	}
	if len(controls2) != 0 {
		t.Errorf("db2 should have 0 controls, got %d", len(controls2))
	}

	vulns2, err := db2.ListAllVulnerabilities(ctx)
	if err != nil {
		t.Fatalf("list vulns db2: %v", err)
	}
	for _, v := range vulns2 {
		mappings, err := db2.ListMappings(ctx, v.ID)
		if err != nil {
			t.Fatalf("list mappings db2 for %s: %v", v.ID, err)
		}
		if len(mappings) != 0 {
			t.Errorf("db2 should have 0 mappings for %s, got %d", v.ID, len(mappings))
		}
	}

	controls1, err := db1.ListAllControls(ctx)
	if err != nil {
		t.Fatalf("list controls db1: %v", err)
	}
	if len(controls1) == 0 {
		t.Error("db1 should have controls")
	}

	mappings1, err := db1.ListMappings(ctx, "CVE-TEST-A")
	if err != nil {
		t.Fatalf("list mappings db1: %v", err)
	}
	if len(mappings1) == 0 {
		t.Error("db1 should have mappings for CVE-TEST-A")
	}
}

func TestLeakage_SequentialRunsIdempotent(t *testing.T) {
	ctx := context.Background()
	logger := leakLogger()

	db := leakSetupDB(t)

	seedControl(t, db, "ctrl-idem-1", "CIS_Controls_v8", "4.1", "Secure Config", []string{"CWE-79", "CWE-89"})
	seedControl(t, db, "ctrl-idem-2", "PCI_DSS_v4", "6.5.1", "XSS Prevention", []string{"CWE-79"})

	for _, vuln := range sampleNVDCVEs {
		if err := db.WriteVulnerability(ctx, vuln["id"].(string), vuln); err != nil {
			t.Fatalf("write vuln %s: %v", vuln["id"], err)
		}
	}

	engine := enricher.New(enricher.Config{
		Store:         db,
		Logger:        logger,
		SkipProviders: true,
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

	totalMappings1 := 0
	totalMappings2 := 0
	for _, vuln := range sampleNVDCVEs {
		vulnID := vuln["id"].(string)
		m1, err := db.ListMappings(ctx, vulnID)
		if err != nil {
			t.Fatalf("list mappings run1 for %s: %v", vulnID, err)
		}
		m2, err := db.ListMappings(ctx, vulnID)
		if err != nil {
			t.Fatalf("list mappings run2 for %s: %v", vulnID, err)
		}
		if len(m1) != len(m2) {
			t.Errorf("mappings changed for %s: run1=%d, run2=%d", vulnID, len(m1), len(m2))
		}
		totalMappings1 += len(m1)
		totalMappings2 += len(m2)
	}

	if totalMappings1 != totalMappings2 {
		t.Errorf("total mappings changed: run1=%d, run2=%d", totalMappings1, totalMappings2)
	}
}

func TestLeakage_TempDirIsolation(t *testing.T) {
	ctx := context.Background()

	dir1 := t.TempDir()
	dir2 := t.TempDir()

	db1, err := storage.NewSQLiteBackend(dir1 + "/iso1.db")
	if err != nil {
		t.Fatalf("new db1: %v", err)
	}
	t.Cleanup(func() { db1.Close(context.Background()) })

	db2, err := storage.NewSQLiteBackend(dir2 + "/iso2.db")
	if err != nil {
		t.Fatalf("new db2: %v", err)
	}
	t.Cleanup(func() { db2.Close(context.Background()) })

	vuln := makeVuln("CVE-TEST-ISO", "CWE-79", "cpe:2.3:a:apache:struts:2.5.30:*:*:*:*:*:*:*")
	if err := db1.WriteVulnerability(ctx, vuln["id"].(string), vuln); err != nil {
		t.Fatalf("write vuln to db1: %v", err)
	}

	seedControl(t, db1, "ctrl-iso-1", "CIS_Controls_v8", "4.1", "Secure Config", []string{"CWE-79"})

	engine := enricher.New(enricher.Config{
		Store:         db1,
		Logger:        leakLogger(),
		SkipProviders: true,
	})
	_, err = engine.Run(ctx)
	if err != nil {
		t.Fatalf("engine run: %v", err)
	}

	controls2, err := db2.ListAllControls(ctx)
	if err != nil {
		t.Fatalf("list controls db2: %v", err)
	}
	if len(controls2) != 0 {
		t.Errorf("db2 should have 0 controls, got %d", len(controls2))
	}

	vulns2, err := db2.ListAllVulnerabilities(ctx)
	if err != nil {
		t.Fatalf("list vulns db2: %v", err)
	}
	if len(vulns2) != 0 {
		t.Errorf("db2 should have 0 vulns, got %d", len(vulns2))
	}

	mappings2, err := db2.ListAllVulnerabilities(ctx)
	if err != nil {
		t.Fatalf("list vulns db2 for mappings check: %v", err)
	}
	totalMappings := 0
	for _, v := range mappings2 {
		m, err := db2.ListMappings(ctx, v.ID)
		if err != nil {
			t.Fatalf("list mappings db2 for %s: %v", v.ID, err)
		}
		totalMappings += len(m)
	}
	if totalMappings != 0 {
		t.Errorf("db2 should have 0 total mappings, got %d", totalMappings)
	}
}
