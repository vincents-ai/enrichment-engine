package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"
)

func setupTestDB(t *testing.T) *SQLiteBackend {
	t.Helper()
	path := t.TempDir() + "/test.db"
	backend, err := NewSQLiteBackend(path)
	if err != nil {
		t.Fatalf("NewSQLiteBackend: %v", err)
	}
	t.Cleanup(func() {
		backend.Close(context.Background())
	})
	return backend
}

var sampleControl = map[string]interface{}{
	"Framework":   "TEST_FRAMEWORK",
	"ControlID":   "TC-1",
	"Title":       "Test Control",
	"Family":      "Test Family",
	"Description": "A test control",
	"RelatedCWEs": []string{"CWE-79", "CWE-89"},
	"Level":       "standard",
}

func TestNewSQLiteBackend(t *testing.T) {
	path := t.TempDir() + "/test.db"
	backend, err := NewSQLiteBackend(path)
	if err != nil {
		t.Fatalf("NewSQLiteBackend: %v", err)
	}
	defer backend.Close(context.Background())

	tables := []string{"vulnerabilities", "grc_controls", "vulnerability_grc_mappings"}
	for _, table := range tables {
		var name string
		err := backend.db.QueryRowContext(context.Background(),
			"SELECT name FROM sqlite_master WHERE type='table' AND name=?", table).Scan(&name)
		if err != nil {
			t.Errorf("table %q not found: %v", table, err)
		}
	}
}

func TestWriteControl_ExtractsFields(t *testing.T) {
	b := setupTestDB(t)
	ctx := context.Background()

	id := "ctrl-001"
	if err := b.WriteControl(ctx, id, sampleControl); err != nil {
		t.Fatalf("WriteControl: %v", err)
	}

	rows, err := b.ListAllControls(ctx)
	if err != nil {
		t.Fatalf("ListAllControls: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 control, got %d", len(rows))
	}

	got := rows[0]
	if got.Framework != "TEST_FRAMEWORK" {
		t.Errorf("Framework = %q, want %q", got.Framework, "TEST_FRAMEWORK")
	}
	if got.ControlID != "TC-1" {
		t.Errorf("ControlID = %q, want %q", got.ControlID, "TC-1")
	}
	if got.Title != "Test Control" {
		t.Errorf("Title = %q, want %q", got.Title, "Test Control")
	}
}

func TestWriteControl_WithRelatedCWEs(t *testing.T) {
	b := setupTestDB(t)
	ctx := context.Background()

	if err := b.WriteControl(ctx, "ctrl-cwe", sampleControl); err != nil {
		t.Fatalf("WriteControl: %v", err)
	}

	rows, err := b.ListAllControls(ctx)
	if err != nil {
		t.Fatalf("ListAllControls: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 control, got %d", len(rows))
	}

	cwes := rows[0].RelatedCWEs
	if len(cwes) != 2 {
		t.Fatalf("expected 2 CWEs, got %d", len(cwes))
	}

	found79, found89 := false, false
	for _, c := range cwes {
		if c == "CWE-79" {
			found79 = true
		}
		if c == "CWE-89" {
			found89 = true
		}
	}
	if !found79 {
		t.Error("CWE-79 not found in RelatedCWEs")
	}
	if !found89 {
		t.Error("CWE-89 not found in RelatedCWEs")
	}
}

func TestWriteVulnerability_ReadBack(t *testing.T) {
	b := setupTestDB(t)
	ctx := context.Background()

	vuln := map[string]interface{}{
		"cve_id":      "CVE-2024-0001",
		"description": "A test vulnerability",
		"severity":    "HIGH",
		"published":   "2024-01-01T00:00:00Z",
		"cvss_score":  8.5,
	}

	id := "vuln-001"
	if err := b.WriteVulnerability(ctx, id, vuln); err != nil {
		t.Fatalf("WriteVulnerability: %v", err)
	}

	data, err := b.ReadVulnerability(ctx, id)
	if err != nil {
		t.Fatalf("ReadVulnerability: %v", err)
	}

	var got map[string]interface{}
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal read back: %v", err)
	}

	if got["cve_id"] != "CVE-2024-0001" {
		t.Errorf("cve_id = %v, want CVE-2024-0001", got["cve_id"])
	}
	if got["severity"] != "HIGH" {
		t.Errorf("severity = %v, want HIGH", got["severity"])
	}
}

func TestWriteMapping_ListMappings(t *testing.T) {
	b := setupTestDB(t)
	ctx := context.Background()

	mappings := []struct {
		controlID   string
		framework   string
		mappingType string
		confidence  float64
		evidence    string
	}{
		{"TC-1", "TEST_FRAMEWORK", "direct", 0.95, "Evidence 1"},
		{"TC-2", "TEST_FRAMEWORK", "indirect", 0.7, "Evidence 2"},
		{"TC-3", "OTHER_FRAMEWORK", "direct", 0.85, "Evidence 3"},
	}

	vulnID := "vuln-map-001"
	for _, m := range mappings {
		if err := b.WriteMapping(ctx, vulnID, m.controlID, m.framework, m.mappingType, m.confidence, m.evidence); err != nil {
			t.Fatalf("WriteMapping: %v", err)
		}
	}

	rows, err := b.ListMappings(ctx, vulnID)
	if err != nil {
		t.Fatalf("ListMappings: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("expected 3 mappings, got %d", len(rows))
	}

	controlIDs := map[string]bool{}
	for _, r := range rows {
		controlIDs[r.ControlID] = true
	}
	for _, m := range mappings {
		if !controlIDs[m.controlID] {
			t.Errorf("mapping for control %q not found", m.controlID)
		}
	}
}

func TestListAllVulnerabilities_Empty(t *testing.T) {
	b := setupTestDB(t)
	ctx := context.Background()

	rows, err := b.ListAllVulnerabilities(ctx)
	if err != nil {
		t.Fatalf("ListAllVulnerabilities: %v", err)
	}
	if rows != nil {
		t.Errorf("expected nil slice, got %d rows", len(rows))
	}
}

func TestListAllControls(t *testing.T) {
	b := setupTestDB(t)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		ctrl := map[string]interface{}{
			"Framework": "FW-A",
			"ControlID": "C-" + string(rune('1'+i)),
			"Title":     "Control " + string(rune('1'+i)),
		}
		if err := b.WriteControl(ctx, "ctrl-all-"+string(rune('1'+i)), ctrl); err != nil {
			t.Fatalf("WriteControl %d: %v", i, err)
		}
	}

	rows, err := b.ListAllControls(ctx)
	if err != nil {
		t.Fatalf("ListAllControls: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("expected 3 controls, got %d", len(rows))
	}
}

func TestListControlsByCWE(t *testing.T) {
	b := setupTestDB(t)
	ctx := context.Background()

	ctrl1 := map[string]interface{}{
		"Framework":   "FW-X",
		"ControlID":   "XC-1",
		"Title":       "Has CWE-79",
		"RelatedCWEs": []string{"CWE-79"},
	}
	ctrl2 := map[string]interface{}{
		"Framework":   "FW-X",
		"ControlID":   "XC-2",
		"Title":       "Has CWE-22",
		"RelatedCWEs": []string{"CWE-22"},
	}
	ctrl3 := map[string]interface{}{
		"Framework":   "FW-X",
		"ControlID":   "XC-3",
		"Title":       "Has both",
		"RelatedCWEs": []string{"CWE-79", "CWE-22"},
	}

	for i, c := range []map[string]interface{}{ctrl1, ctrl2, ctrl3} {
		if err := b.WriteControl(ctx, "cwe-ctrl-"+string(rune('1'+i)), c); err != nil {
			t.Fatalf("WriteControl: %v", err)
		}
	}

	rows, err := b.ListControlsByCWE(ctx, "CWE-79")
	if err != nil {
		t.Fatalf("ListControlsByCWE: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("expected 2 controls for CWE-79, got %d", len(rows))
	}

	rows22, err := b.ListControlsByCWE(ctx, "CWE-22")
	if err != nil {
		t.Fatalf("ListControlsByCWE: %v", err)
	}
	if len(rows22) != 2 {
		t.Fatalf("expected 2 controls for CWE-22, got %d", len(rows22))
	}
}

func TestListControlsByFramework(t *testing.T) {
	b := setupTestDB(t)
	ctx := context.Background()

	fw1 := map[string]interface{}{
		"Framework": "NIST",
		"ControlID": "AC-2",
		"Title":     "NIST Control",
	}
	fw2 := map[string]interface{}{
		"Framework": "ISO",
		"ControlID": "A.5.1",
		"Title":     "ISO Control",
	}

	if err := b.WriteControl(ctx, "fw-1", fw1); err != nil {
		t.Fatalf("WriteControl fw1: %v", err)
	}
	if err := b.WriteControl(ctx, "fw-2", fw2); err != nil {
		t.Fatalf("WriteControl fw2: %v", err)
	}

	rows, err := b.ListControlsByFramework(ctx, "NIST")
	if err != nil {
		t.Fatalf("ListControlsByFramework: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 NIST control, got %d", len(rows))
	}
	if rows[0].ControlID != "AC-2" {
		t.Errorf("ControlID = %q, want AC-2", rows[0].ControlID)
	}
}

func makeNVDVuln(id, cpe string, cwes []string) map[string]interface{} {
	weaknesses := []interface{}{}
	for _, cwe := range cwes {
		weaknesses = append(weaknesses, map[string]interface{}{
			"description": []interface{}{
				map[string]interface{}{
					"lang":  "en",
					"value": cwe,
				},
			},
		})
	}

	cpeMatches := []interface{}{}
	if cpe != "" {
		cpeMatches = append(cpeMatches, map[string]interface{}{
			"criteria": cpe,
		})
	}

	configs := []interface{}{}
	if len(cpeMatches) > 0 {
		configs = append(configs, map[string]interface{}{
			"nodes": []interface{}{
				map[string]interface{}{
					"cpeMatch": cpeMatches,
				},
			},
		})
	}

	return map[string]interface{}{
		"id": id,
		"cve": map[string]interface{}{
			"id":             id,
			"weaknesses":     weaknesses,
			"configurations": configs,
		},
	}
}

func TestListControlsByCPE_NoVulns(t *testing.T) {
	b := setupTestDB(t)
	ctx := context.Background()

	ctrl := map[string]interface{}{
		"Framework":   "CPE-FW",
		"ControlID":   "CP-1",
		"Title":       "CPE Control",
		"RelatedCWEs": []string{"CWE-79"},
	}
	if err := b.WriteControl(ctx, "cpe-no-vuln", ctrl); err != nil {
		t.Fatalf("WriteControl: %v", err)
	}

	rows, err := b.ListControlsByCPE(ctx, "cpe:2.3:a:fake:app:*:*:*:*:*:*:*:*")
	if err != nil {
		t.Fatalf("ListControlsByCPE: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("expected 0 controls with no vulnerabilities, got %d", len(rows))
	}
}

func TestListControlsByCPE_NoMatchingCPE(t *testing.T) {
	b := setupTestDB(t)
	ctx := context.Background()

	vuln := makeNVDVuln("CVE-2024-NOPE", "cpe:2.3:a:other:product:1.0:*:*:*:*:*:*:*", []string{"CWE-79"})
	if err := b.WriteVulnerability(ctx, "vuln-no-match", vuln); err != nil {
		t.Fatalf("WriteVulnerability: %v", err)
	}

	ctrl := map[string]interface{}{
		"Framework":   "CPE-FW2",
		"ControlID":   "CP-2",
		"Title":       "CPE Control 2",
		"RelatedCWEs": []string{"CWE-79"},
	}
	if err := b.WriteControl(ctx, "cpe-no-match-ctrl", ctrl); err != nil {
		t.Fatalf("WriteControl: %v", err)
	}

	rows, err := b.ListControlsByCPE(ctx, "cpe:2.3:a:fake:app:*:*:*:*:*:*:*:*")
	if err != nil {
		t.Fatalf("ListControlsByCPE: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("expected 0 controls when no CPE match, got %d", len(rows))
	}
}

func TestListControlsByCPE_MatchingCWEs(t *testing.T) {
	b := setupTestDB(t)
	ctx := context.Background()

	vuln := makeNVDVuln("CVE-2024-CPE1", "cpe:2.3:a:test:app:1.0:*:*:*:*:*:*:*", []string{"CWE-79", "CWE-89"})
	if err := b.WriteVulnerability(ctx, "vuln-cpe-match", vuln); err != nil {
		t.Fatalf("WriteVulnerability: %v", err)
	}

	ctrl79 := map[string]interface{}{
		"Framework":   "CPE-FW3",
		"ControlID":   "CP-79",
		"Title":       "XSS Control",
		"RelatedCWEs": []string{"CWE-79"},
	}
	ctrl89 := map[string]interface{}{
		"Framework":   "CPE-FW3",
		"ControlID":   "CP-89",
		"Title":       "Injection Control",
		"RelatedCWEs": []string{"CWE-89"},
	}
	ctrlUnrelated := map[string]interface{}{
		"Framework":   "CPE-FW3",
		"ControlID":   "CP-22",
		"Title":       "Path Traversal Control",
		"RelatedCWEs": []string{"CWE-22"},
	}

	if err := b.WriteControl(ctx, "cpe-ctrl-79", ctrl79); err != nil {
		t.Fatalf("WriteControl ctrl79: %v", err)
	}
	if err := b.WriteControl(ctx, "cpe-ctrl-89", ctrl89); err != nil {
		t.Fatalf("WriteControl ctrl89: %v", err)
	}
	if err := b.WriteControl(ctx, "cpe-ctrl-22", ctrlUnrelated); err != nil {
		t.Fatalf("WriteControl ctrl22: %v", err)
	}

	rows, err := b.ListControlsByCPE(ctx, "cpe:2.3:a:test:app:1.0:*:*:*:*:*:*:*")
	if err != nil {
		t.Fatalf("ListControlsByCPE: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("expected 2 controls matching CWE-79/CWE-89, got %d", len(rows))
	}

	ids := map[string]bool{}
	for _, r := range rows {
		ids[r.ControlID] = true
	}
	if !ids["CP-79"] {
		t.Error("expected control CP-79 (CWE-79) in results")
	}
	if !ids["CP-89"] {
		t.Error("expected control CP-89 (CWE-89) in results")
	}
	if ids["CP-22"] {
		t.Error("unexpected control CP-22 (CWE-22) in results")
	}
}

func TestListControlsByCPE_VulnNoCWEs(t *testing.T) {
	b := setupTestDB(t)
	ctx := context.Background()

	vuln := makeNVDVuln("CVE-2024-NOCWE", "cpe:2.3:a:nocwe:app:1.0:*:*:*:*:*:*:*", nil)
	if err := b.WriteVulnerability(ctx, "vuln-no-cwe", vuln); err != nil {
		t.Fatalf("WriteVulnerability: %v", err)
	}

	ctrl := map[string]interface{}{
		"Framework":   "CPE-FW4",
		"ControlID":   "CP-NOCWE",
		"Title":       "No CWE Control",
		"RelatedCWEs": []string{"CWE-79"},
	}
	if err := b.WriteControl(ctx, "cpe-no-cwe-ctrl", ctrl); err != nil {
		t.Fatalf("WriteControl: %v", err)
	}

	rows, err := b.ListControlsByCPE(ctx, "cpe:2.3:a:nocwe:app:1.0:*:*:*:*:*:*:*")
	if err != nil {
		t.Fatalf("ListControlsByCPE: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("expected 0 controls when vuln has no CWEs, got %d", len(rows))
	}
}

func TestListControlsByCPE_Deduplicates(t *testing.T) {
	b := setupTestDB(t)
	ctx := context.Background()

	vuln1 := makeNVDVuln("CVE-2024-DUP1", "cpe:2.3:a:dup:app:1.0:*:*:*:*:*:*:*", []string{"CWE-79"})
	vuln2 := makeNVDVuln("CVE-2024-DUP2", "cpe:2.3:a:dup:app:2.0:*:*:*:*:*:*:*", []string{"CWE-79"})
	if err := b.WriteVulnerability(ctx, "vuln-dup-1", vuln1); err != nil {
		t.Fatalf("WriteVulnerability vuln1: %v", err)
	}
	if err := b.WriteVulnerability(ctx, "vuln-dup-2", vuln2); err != nil {
		t.Fatalf("WriteVulnerability vuln2: %v", err)
	}

	ctrl := map[string]interface{}{
		"Framework":   "CPE-FW5",
		"ControlID":   "CP-DUP",
		"Title":       "Dedup Control",
		"RelatedCWEs": []string{"CWE-79"},
	}
	if err := b.WriteControl(ctx, "cpe-dup-ctrl", ctrl); err != nil {
		t.Fatalf("WriteControl: %v", err)
	}

	cpe := "cpe:2.3:a:dup:app"
	rows, err := b.ListControlsByCPE(ctx, cpe)
	if err != nil {
		t.Fatalf("ListControlsByCPE: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 deduplicated control, got %d", len(rows))
	}
	if rows[0].ControlID != "CP-DUP" {
		t.Errorf("ControlID = %q, want CP-DUP", rows[0].ControlID)
	}
}

func TestListControlsByCPE_ControlNoCWEs(t *testing.T) {
	b := setupTestDB(t)
	ctx := context.Background()

	vuln := makeNVDVuln("CVE-2024-NOCTRL", "cpe:2.3:a:noctrl:app:1.0:*:*:*:*:*:*:*", []string{"CWE-79"})
	if err := b.WriteVulnerability(ctx, "vuln-no-ctrl", vuln); err != nil {
		t.Fatalf("WriteVulnerability: %v", err)
	}

	ctrl := map[string]interface{}{
		"Framework": "CPE-FW6",
		"ControlID": "CP-NOCWES",
		"Title":     "No Related CWEs Control",
	}
	if err := b.WriteControl(ctx, "cpe-no-cwes-ctrl", ctrl); err != nil {
		t.Fatalf("WriteControl: %v", err)
	}

	rows, err := b.ListControlsByCPE(ctx, "cpe:2.3:a:noctrl:app:1.0:*:*:*:*:*:*:*")
	if err != nil {
		t.Fatalf("ListControlsByCPE: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("expected 0 controls when control has no RelatedCWEs, got %d", len(rows))
	}
}

func TestWriteControl_Update(t *testing.T) {
	b := setupTestDB(t)
	ctx := context.Background()

	id := "ctrl-update"
	v1 := map[string]interface{}{
		"Framework": "FW-UP",
		"ControlID": "UP-1",
		"Title":     "Original Title",
	}
	if err := b.WriteControl(ctx, id, v1); err != nil {
		t.Fatalf("WriteControl v1: %v", err)
	}

	v2 := map[string]interface{}{
		"Framework": "FW-UP",
		"ControlID": "UP-1",
		"Title":     "Updated Title",
	}
	if err := b.WriteControl(ctx, id, v2); err != nil {
		t.Fatalf("WriteControl v2: %v", err)
	}

	rows, err := b.ListAllControls(ctx)
	if err != nil {
		t.Fatalf("ListAllControls: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 control after update, got %d", len(rows))
	}
	if rows[0].Title != "Updated Title" {
		t.Errorf("Title = %q, want %q", rows[0].Title, "Updated Title")
	}
}

func TestConcurrentWrites(t *testing.T) {
	b := setupTestDB(t)
	ctx := context.Background()

	var wg sync.WaitGroup
	errs := make(chan error, 10)

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ctrl := map[string]interface{}{
				"Framework": "CONC-FW",
				"ControlID": "CONC-" + string(rune('A'+i)),
				"Title":     "Concurrent Control " + string(rune('A'+i)),
			}
			if err := b.WriteControl(ctx, "conc-ctrl-"+string(rune('A'+i)), ctrl); err != nil {
				errs <- err
			}
		}(i)
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("concurrent write error: %v", err)
	}

	rows, err := b.ListAllControls(ctx)
	if err != nil {
		t.Fatalf("ListAllControls: %v", err)
	}
	if len(rows) != 10 {
		t.Errorf("expected 10 controls, got %d", len(rows))
	}
}

func TestClose_Idempotent(t *testing.T) {
	path := t.TempDir() + "/close-idem.db"
	backend, err := NewSQLiteBackend(path)
	if err != nil {
		t.Fatalf("NewSQLiteBackend: %v", err)
	}

	if err := backend.Close(context.Background()); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := backend.Close(context.Background()); err != nil {
		t.Errorf("second Close should be nil, got: %v", err)
	}
}

func TestClose_RenamesTempFile(t *testing.T) {
	path := t.TempDir() + "/rename-test.db"
	tempPath := path + ".tmp"

	backend, err := NewSQLiteBackend(path)
	if err != nil {
		t.Fatalf("NewSQLiteBackend: %v", err)
	}

	if _, err := backend.db.Exec("CREATE TABLE test_rename (x INT)"); err != nil {
		t.Fatalf("exec test table: %v", err)
	}

	if err := backend.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if _, err := backend.db.Exec("SELECT 1"); err == nil {
		t.Error("expected error on closed db, got nil")
	}

	if _, err := backend.ReadVulnerability(context.Background(), "nonexistent"); err == nil {
		t.Error("expected error reading from closed db")
	}

	var finalData []byte
	err = func() error {
		var err error
		finalData, err = os.ReadFile(path)
		return err
	}()
	if err != nil {
		t.Fatalf("read final db file: %v", err)
	}
	if len(finalData) == 0 {
		t.Error("final db file is empty")
	}

	if _, err := os.Stat(tempPath); err == nil {
		t.Error("temp file still exists after Close")
	}
}

func TestMappingPrimaryKey(t *testing.T) {
	b := setupTestDB(t)
	ctx := context.Background()

	err1 := b.WriteMapping(ctx, "vuln-pk", "ctrl-pk", "FW-PK", "direct", 0.9, "first")
	if err1 != nil {
		t.Fatalf("first WriteMapping: %v", err1)
	}

	err2 := b.WriteMapping(ctx, "vuln-pk", "ctrl-pk", "FW-PK", "indirect", 0.8, "second")
	if err2 != nil {
		t.Fatalf("second WriteMapping: %v", err2)
	}

	rows, err := b.ListMappings(ctx, "vuln-pk")
	if err != nil {
		t.Fatalf("ListMappings: %v", err)
	}

	if len(rows) != 2 {
		t.Fatalf("expected 2 mappings (different mapping_types coexist), got %d", len(rows))
	}

	byType := make(map[string]MappingRow)
	for _, r := range rows {
		byType[r.MappingType] = r
	}

	if byType["direct"].Confidence != 0.9 {
		t.Errorf("direct confidence = %f, want 0.9", byType["direct"].Confidence)
	}
	if byType["indirect"].Confidence != 0.8 {
		t.Errorf("indirect confidence = %f, want 0.8", byType["indirect"].Confidence)
	}

	err3 := b.WriteMapping(ctx, "vuln-pk", "ctrl-pk", "FW-PK", "direct", 0.7, "updated")
	if err3 != nil {
		t.Fatalf("third WriteMapping (upsert same type): %v", err3)
	}

	rows2, _ := b.ListMappings(ctx, "vuln-pk")
	if len(rows2) != 2 {
		t.Fatalf("expected 2 mappings after upsert of same type, got %d", len(rows2))
	}
	for _, r := range rows2 {
		if r.MappingType == "direct" && r.Confidence != 0.7 {
			t.Errorf("direct confidence after upsert = %f, want 0.7", r.Confidence)
		}
	}
}

func TestReadControl_NotFound(t *testing.T) {
	b := setupTestDB(t)
	ctx := context.Background()

	_, err := b.ReadControl(ctx, "nonexistent-control")
	if err == nil {
		t.Fatal("expected error for nonexistent control, got nil")
	}
}

func TestReadControl_AfterWrite(t *testing.T) {
	b := setupTestDB(t)
	ctx := context.Background()

	ctrl := map[string]interface{}{
		"Framework": "RW-FW",
		"ControlID": "RW-1",
		"Title":     "Read Write Test",
		"Family":    "RW-Family",
		"Level":     "high",
	}
	if err := b.WriteControl(ctx, "rw-ctrl", ctrl); err != nil {
		t.Fatalf("WriteControl: %v", err)
	}

	data, err := b.ReadControl(ctx, "rw-ctrl")
	if err != nil {
		t.Fatalf("ReadControl: %v", err)
	}

	var got map[string]interface{}
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	for k, v := range ctrl {
		if got[k] != v {
			t.Errorf("field %q = %v, want %v", k, got[k], v)
		}
	}
}

func TestReadControl_FullRecordPreserved(t *testing.T) {
	b := setupTestDB(t)
	ctx := context.Background()

	ctrl := map[string]interface{}{
		"Framework":   "PRESERVE-FW",
		"ControlID":   "PR-1",
		"Title":       "Preserve Test",
		"Family":      "PreserveFamily",
		"Description": "PreserveDesc",
		"Level":       "critical",
		"ExtraField":  "extra-value",
		"NumberField": 42,
	}
	if err := b.WriteControl(ctx, "preserve-ctrl", ctrl); err != nil {
		t.Fatalf("WriteControl: %v", err)
	}

	data, err := b.ReadControl(ctx, "preserve-ctrl")
	if err != nil {
		t.Fatalf("ReadControl: %v", err)
	}

	var got map[string]interface{}
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if got["ExtraField"] != "extra-value" {
		t.Errorf("ExtraField = %v, want extra-value", got["ExtraField"])
	}
	if got["NumberField"] != float64(42) {
		t.Errorf("NumberField = %v, want 42", got["NumberField"])
	}
}

func TestWriteControl_LongDescription(t *testing.T) {
	b := setupTestDB(t)
	ctx := context.Background()

	longDesc := make([]byte, 10000)
	for i := range longDesc {
		longDesc[i] = 'x'
	}

	ctrl := map[string]interface{}{
		"Framework":   "LONG-FW",
		"ControlID":   "LONG-1",
		"Title":       "Long Description Control",
		"Description": string(longDesc),
	}
	if err := b.WriteControl(ctx, "long-ctrl", ctrl); err != nil {
		t.Fatalf("WriteControl: %v", err)
	}

	rows, err := b.ListAllControls(ctx)
	if err != nil {
		t.Fatalf("ListAllControls: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 control, got %d", len(rows))
	}
	if rows[0].Description != string(longDesc) {
		t.Errorf("description length = %d, want %d", len(rows[0].Description), len(longDesc))
	}
}

func TestWriteControl_SpecialCharacters(t *testing.T) {
	b := setupTestDB(t)
	ctx := context.Background()

	tests := []struct {
		name string
		ctrl map[string]interface{}
	}{
		{
			name: "unicode",
			ctrl: map[string]interface{}{
				"Framework":   "UNI-FW",
				"ControlID":   "UNI-1",
				"Title":       "Control with \u00e9\u00f1\u00fc\u2603\u2764\ufe0f",
				"Description": "Description with \u4e2d\u6587\u65e5\u672c\u8a9e",
			},
		},
		{
			name: "quotes",
			ctrl: map[string]interface{}{
				"Framework":   "QUOTE-FW",
				"ControlID":   "Q-1",
				"Title":       `Title with "double" and 'single' quotes`,
				"Description": `Desc with "quotes" and 'apostrophes'`,
			},
		},
		{
			name: "newlines",
			ctrl: map[string]interface{}{
				"Framework":   "NL-FW",
				"ControlID":   "NL-1",
				"Title":       "Title with\nnewlines",
				"Description": "Line 1\nLine 2\r\nLine 3",
			},
		},
		{
			name: "backslashes",
			ctrl: map[string]interface{}{
				"Framework":   "BS-FW",
				"ControlID":   "BS-1",
				"Title":       `Path: C:\Users\test`,
				"Description": `Regex: \d+\.\w+`,
			},
		},
		{
			name: "html_like",
			ctrl: map[string]interface{}{
				"Framework":   "HTML-FW",
				"ControlID":   "H-1",
				"Title":       "Control with <script>alert('xss')</script>",
				"Description": "<p>HTML content</p>",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			id := "special-" + tc.name
			if err := b.WriteControl(ctx, id, tc.ctrl); err != nil {
				t.Fatalf("WriteControl: %v", err)
			}

			data, err := b.ReadControl(ctx, id)
			if err != nil {
				t.Fatalf("ReadControl: %v", err)
			}

			var got map[string]interface{}
			if err := json.Unmarshal(data, &got); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}

			if got["Title"] != tc.ctrl["Title"] {
				t.Errorf("Title = %q, want %q", got["Title"], tc.ctrl["Title"])
			}
			if got["Description"] != tc.ctrl["Description"] {
				t.Errorf("Description = %q, want %q", got["Description"], tc.ctrl["Description"])
			}
		})
	}
}

func TestWriteControl_NoOptionalFields(t *testing.T) {
	b := setupTestDB(t)
	ctx := context.Background()

	ctrl := map[string]interface{}{
		"Framework": "MIN-FW",
		"ControlID": "MIN-1",
		"Title":     "Minimal Control",
	}
	if err := b.WriteControl(ctx, "min-ctrl", ctrl); err != nil {
		t.Fatalf("WriteControl: %v", err)
	}

	rows, err := b.ListAllControls(ctx)
	if err != nil {
		t.Fatalf("ListAllControls: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 control, got %d", len(rows))
	}

	r := rows[0]
	if r.Family != "" {
		t.Errorf("Family = %q, want empty", r.Family)
	}
	if r.Description != "" {
		t.Errorf("Description = %q, want empty", r.Description)
	}
	if len(r.RelatedCWEs) != 0 {
		t.Errorf("RelatedCWEs = %v, want empty", r.RelatedCWEs)
	}
}

func TestWriteControl_SingleCWE(t *testing.T) {
	b := setupTestDB(t)
	ctx := context.Background()

	ctrl := map[string]interface{}{
		"Framework":   "SINGLE-FW",
		"ControlID":   "S-1",
		"Title":       "Single CWE Control",
		"RelatedCWEs": []string{"CWE-123"},
	}
	if err := b.WriteControl(ctx, "single-cwe", ctrl); err != nil {
		t.Fatalf("WriteControl: %v", err)
	}

	rows, err := b.ListAllControls(ctx)
	if err != nil {
		t.Fatalf("ListAllControls: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 control, got %d", len(rows))
	}
	if len(rows[0].RelatedCWEs) != 1 || rows[0].RelatedCWEs[0] != "CWE-123" {
		t.Errorf("RelatedCWEs = %v, want [CWE-123]", rows[0].RelatedCWEs)
	}
}

func TestWriteControl_ManyCWEs(t *testing.T) {
	b := setupTestDB(t)
	ctx := context.Background()

	cwes := make([]string, 50)
	for i := range cwes {
		cwes[i] = fmt.Sprintf("CWE-%d", i+1)
	}

	ctrl := map[string]interface{}{
		"Framework":   "MANY-FW",
		"ControlID":   "M-1",
		"Title":       "Many CWEs Control",
		"RelatedCWEs": cwes,
	}
	if err := b.WriteControl(ctx, "many-cwe", ctrl); err != nil {
		t.Fatalf("WriteControl: %v", err)
	}

	rows, err := b.ListAllControls(ctx)
	if err != nil {
		t.Fatalf("ListAllControls: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 control, got %d", len(rows))
	}
	if len(rows[0].RelatedCWEs) != 50 {
		t.Errorf("RelatedCWEs count = %d, want 50", len(rows[0].RelatedCWEs))
	}
}

func TestWriteControl_EmptyStrings(t *testing.T) {
	b := setupTestDB(t)
	ctx := context.Background()

	ctrl := map[string]interface{}{
		"Framework":   "EMPTY-FW",
		"ControlID":   "E-1",
		"Title":       "",
		"Family":      "",
		"Description": "",
	}
	if err := b.WriteControl(ctx, "empty-ctrl", ctrl); err != nil {
		t.Fatalf("WriteControl: %v", err)
	}

	data, err := b.ReadControl(ctx, "empty-ctrl")
	if err != nil {
		t.Fatalf("ReadControl: %v", err)
	}

	var got map[string]interface{}
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if got["Title"] != "" {
		t.Errorf("Title = %q, want empty", got["Title"])
	}
	if got["Family"] != "" {
		t.Errorf("Family = %q, want empty", got["Family"])
	}
}

func TestListControlsByCWE_SubstringMatch(t *testing.T) {
	b := setupTestDB(t)
	ctx := context.Background()

	ctrl := map[string]interface{}{
		"Framework":   "PART-FW",
		"ControlID":   "P-1",
		"Title":       "Has CWE-791",
		"RelatedCWEs": []string{"CWE-791"},
	}
	if err := b.WriteControl(ctx, "partial-cwe", ctrl); err != nil {
		t.Fatalf("WriteControl: %v", err)
	}

	rows, err := b.ListControlsByCWE(ctx, "CWE-79")
	if err != nil {
		t.Fatalf("ListControlsByCWE: %v", err)
	}
	if len(rows) != 1 {
		t.Errorf("expected 1 control for CWE-79 (substring matches CWE-791), got %d", len(rows))
	}
}

func TestListControlsByCWE_NonExistent(t *testing.T) {
	b := setupTestDB(t)
	ctx := context.Background()

	ctrl := map[string]interface{}{
		"Framework":   "NONE-FW",
		"ControlID":   "N-1",
		"Title":       "Has other CWEs",
		"RelatedCWEs": []string{"CWE-100", "CWE-200"},
	}
	if err := b.WriteControl(ctx, "none-cwe", ctrl); err != nil {
		t.Fatalf("WriteControl: %v", err)
	}

	rows, err := b.ListControlsByCWE(ctx, "CWE-999")
	if err != nil {
		t.Fatalf("ListControlsByCWE: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("expected 0 controls for CWE-999, got %d", len(rows))
	}
}

func TestListControlsByCWE_NoCWEsOnControl(t *testing.T) {
	b := setupTestDB(t)
	ctx := context.Background()

	ctrl := map[string]interface{}{
		"Framework": "NO-CWE-FW",
		"ControlID": "NC-1",
		"Title":     "No CWEs",
	}
	if err := b.WriteControl(ctx, "no-cwe", ctrl); err != nil {
		t.Fatalf("WriteControl: %v", err)
	}

	rows, err := b.ListControlsByCWE(ctx, "CWE-79")
	if err != nil {
		t.Fatalf("ListControlsByCWE: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("expected 0 controls, got %d", len(rows))
	}
}

func TestListControlsByCWE_EmptyDatabase(t *testing.T) {
	b := setupTestDB(t)
	ctx := context.Background()

	rows, err := b.ListControlsByCWE(ctx, "CWE-79")
	if err != nil {
		t.Fatalf("ListControlsByCWE: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("expected 0 controls from empty DB, got %d", len(rows))
	}
}

func TestListControlsByFramework_CaseSensitive(t *testing.T) {
	b := setupTestDB(t)
	ctx := context.Background()

	ctrl := map[string]interface{}{
		"Framework": "NIST",
		"ControlID": "CS-1",
		"Title":     "Case Sensitive Test",
	}
	if err := b.WriteControl(ctx, "cs-ctrl", ctrl); err != nil {
		t.Fatalf("WriteControl: %v", err)
	}

	rows, err := b.ListControlsByFramework(ctx, "nist")
	if err != nil {
		t.Fatalf("ListControlsByFramework: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("expected 0 controls for lowercase 'nist', got %d", len(rows))
	}

	rows, err = b.ListControlsByFramework(ctx, "NIST")
	if err != nil {
		t.Fatalf("ListControlsByFramework: %v", err)
	}
	if len(rows) != 1 {
		t.Errorf("expected 1 control for 'NIST', got %d", len(rows))
	}
}

func TestListControlsByFramework_EmptyFramework(t *testing.T) {
	b := setupTestDB(t)
	ctx := context.Background()

	rows, err := b.ListControlsByFramework(ctx, "")
	if err != nil {
		t.Fatalf("ListControlsByFramework: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("expected 0 controls for empty framework, got %d", len(rows))
	}
}

func TestListControlsByFramework_NonExistent(t *testing.T) {
	b := setupTestDB(t)
	ctx := context.Background()

	ctrl := map[string]interface{}{
		"Framework": "EXISTING-FW",
		"ControlID": "EF-1",
		"Title":     "Existing Framework Control",
	}
	if err := b.WriteControl(ctx, "ef-ctrl", ctrl); err != nil {
		t.Fatalf("WriteControl: %v", err)
	}

	rows, err := b.ListControlsByFramework(ctx, "NONEXISTENT")
	if err != nil {
		t.Fatalf("ListControlsByFramework: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("expected 0 controls for nonexistent framework, got %d", len(rows))
	}
}

func TestListControlsByFramework_MultipleControls(t *testing.T) {
	b := setupTestDB(t)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		ctrl := map[string]interface{}{
			"Framework": "MULTI-FW",
			"ControlID": fmt.Sprintf("MC-%d", i),
			"Title":     fmt.Sprintf("Multi Control %d", i),
		}
		if err := b.WriteControl(ctx, fmt.Sprintf("multi-ctrl-%d", i), ctrl); err != nil {
			t.Fatalf("WriteControl %d: %v", i, err)
		}
	}

	rows, err := b.ListControlsByFramework(ctx, "MULTI-FW")
	if err != nil {
		t.Fatalf("ListControlsByFramework: %v", err)
	}
	if len(rows) != 5 {
		t.Errorf("expected 5 controls, got %d", len(rows))
	}

	controlIDs := map[string]bool{}
	for _, r := range rows {
		controlIDs[r.ControlID] = true
	}
	for i := 0; i < 5; i++ {
		if !controlIDs[fmt.Sprintf("MC-%d", i)] {
			t.Errorf("control MC-%d not found", i)
		}
	}
}

func TestListMappings_NonExistentVulnerability(t *testing.T) {
	b := setupTestDB(t)
	ctx := context.Background()

	rows, err := b.ListMappings(ctx, "nonexistent-vuln")
	if err != nil {
		t.Fatalf("ListMappings: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("expected 0 mappings for nonexistent vulnerability, got %d", len(rows))
	}
}

func TestListMappings_AllFieldsPreserved(t *testing.T) {
	b := setupTestDB(t)
	ctx := context.Background()

	if err := b.WriteMapping(ctx, "v-field", "c-field", "FW-FIELD", "inferred", 0.42, "test evidence string"); err != nil {
		t.Fatalf("WriteMapping: %v", err)
	}

	rows, err := b.ListMappings(ctx, "v-field")
	if err != nil {
		t.Fatalf("ListMappings: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 mapping, got %d", len(rows))
	}

	m := rows[0]
	if m.VulnerabilityID != "v-field" {
		t.Errorf("VulnerabilityID = %q, want v-field", m.VulnerabilityID)
	}
	if m.ControlID != "c-field" {
		t.Errorf("ControlID = %q, want c-field", m.ControlID)
	}
	if m.Framework != "FW-FIELD" {
		t.Errorf("Framework = %q, want FW-FIELD", m.Framework)
	}
	if m.MappingType != "inferred" {
		t.Errorf("MappingType = %q, want inferred", m.MappingType)
	}
	if m.Confidence != 0.42 {
		t.Errorf("Confidence = %f, want 0.42", m.Confidence)
	}
	if m.Evidence != "test evidence string" {
		t.Errorf("Evidence = %q, want 'test evidence string'", m.Evidence)
	}
}

func TestListMappings_DifferentVulnerabilities(t *testing.T) {
	b := setupTestDB(t)
	ctx := context.Background()

	if err := b.WriteMapping(ctx, "v-a", "c-1", "FW-A", "direct", 0.9, "ev-a"); err != nil {
		t.Fatalf("WriteMapping a: %v", err)
	}
	if err := b.WriteMapping(ctx, "v-b", "c-2", "FW-B", "indirect", 0.5, "ev-b"); err != nil {
		t.Fatalf("WriteMapping b: %v", err)
	}

	rowsA, err := b.ListMappings(ctx, "v-a")
	if err != nil {
		t.Fatalf("ListMappings v-a: %v", err)
	}
	if len(rowsA) != 1 {
		t.Fatalf("expected 1 mapping for v-a, got %d", len(rowsA))
	}

	rowsB, err := b.ListMappings(ctx, "v-b")
	if err != nil {
		t.Fatalf("ListMappings v-b: %v", err)
	}
	if len(rowsB) != 1 {
		t.Fatalf("expected 1 mapping for v-b, got %d", len(rowsB))
	}

	if rowsA[0].ControlID == rowsB[0].ControlID {
		t.Error("different vulnerabilities returned same control mapping")
	}
}

func TestListAllControls_EmptyDatabase(t *testing.T) {
	b := setupTestDB(t)
	ctx := context.Background()

	rows, err := b.ListAllControls(ctx)
	if err != nil {
		t.Fatalf("ListAllControls: %v", err)
	}
	if rows != nil {
		t.Errorf("expected nil slice for empty DB, got %d rows", len(rows))
	}
}

func TestListAllVulnerabilities_AfterWrites(t *testing.T) {
	b := setupTestDB(t)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		vuln := map[string]interface{}{
			"cve_id":   fmt.Sprintf("CVE-2024-%04d", i),
			"severity": "HIGH",
		}
		if err := b.WriteVulnerability(ctx, fmt.Sprintf("vuln-list-%d", i), vuln); err != nil {
			t.Fatalf("WriteVulnerability %d: %v", i, err)
		}
	}

	rows, err := b.ListAllVulnerabilities(ctx)
	if err != nil {
		t.Fatalf("ListAllVulnerabilities: %v", err)
	}
	if len(rows) != 5 {
		t.Errorf("expected 5 vulnerabilities, got %d", len(rows))
	}
}

func TestListAllVulnerabilities_RecordContent(t *testing.T) {
	b := setupTestDB(t)
	ctx := context.Background()

	vuln := map[string]interface{}{
		"cve_id":      "CVE-2024-1234",
		"description": "test desc",
		"score":       9.1,
	}
	if err := b.WriteVulnerability(ctx, "vuln-content", vuln); err != nil {
		t.Fatalf("WriteVulnerability: %v", err)
	}

	rows, err := b.ListAllVulnerabilities(ctx)
	if err != nil {
		t.Fatalf("ListAllVulnerabilities: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}
	if rows[0].ID != "vuln-content" {
		t.Errorf("ID = %q, want vuln-content", rows[0].ID)
	}

	var got map[string]interface{}
	if err := json.Unmarshal(rows[0].Record, &got); err != nil {
		t.Fatalf("unmarshal record: %v", err)
	}
	if got["cve_id"] != "CVE-2024-1234" {
		t.Errorf("cve_id = %v, want CVE-2024-1234", got["cve_id"])
	}
}

func TestReadVulnerability_NotFound(t *testing.T) {
	b := setupTestDB(t)
	ctx := context.Background()

	_, err := b.ReadVulnerability(ctx, "nonexistent-vuln")
	if err == nil {
		t.Fatal("expected error for nonexistent vulnerability, got nil")
	}
}

func TestWriteVulnerability_Overwrite(t *testing.T) {
	b := setupTestDB(t)
	ctx := context.Background()

	v1 := map[string]interface{}{"cve_id": "CVE-2024-0001", "severity": "HIGH"}
	if err := b.WriteVulnerability(ctx, "vuln-overwrite", v1); err != nil {
		t.Fatalf("WriteVulnerability v1: %v", err)
	}

	v2 := map[string]interface{}{"cve_id": "CVE-2024-0001", "severity": "LOW", "patched": true}
	if err := b.WriteVulnerability(ctx, "vuln-overwrite", v2); err != nil {
		t.Fatalf("WriteVulnerability v2: %v", err)
	}

	data, err := b.ReadVulnerability(ctx, "vuln-overwrite")
	if err != nil {
		t.Fatalf("ReadVulnerability: %v", err)
	}

	var got map[string]interface{}
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got["severity"] != "LOW" {
		t.Errorf("severity = %v, want LOW", got["severity"])
	}
	if got["patched"] != true {
		t.Errorf("patched = %v, want true", got["patched"])
	}
}

func TestWriteVulnerability_NestedStructures(t *testing.T) {
	b := setupTestDB(t)
	ctx := context.Background()

	vuln := map[string]interface{}{
		"cve_id": "CVE-2024-NESTED",
		"nested": map[string]interface{}{
			"level1": map[string]interface{}{
				"level2": "deep value",
			},
		},
		"array_field": []interface{}{1, "two", 3.0},
		"cpes":        []string{"cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"},
	}
	if err := b.WriteVulnerability(ctx, "vuln-nested", vuln); err != nil {
		t.Fatalf("WriteVulnerability: %v", err)
	}

	data, err := b.ReadVulnerability(ctx, "vuln-nested")
	if err != nil {
		t.Fatalf("ReadVulnerability: %v", err)
	}

	var got map[string]interface{}
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	nested, ok := got["nested"].(map[string]interface{})
	if !ok {
		t.Fatal("nested field missing or wrong type")
	}
	l1, ok := nested["level1"].(map[string]interface{})
	if !ok {
		t.Fatal("level1 missing or wrong type")
	}
	if l1["level2"] != "deep value" {
		t.Errorf("level2 = %v, want 'deep value'", l1["level2"])
	}

	arr, ok := got["array_field"].([]interface{})
	if !ok {
		t.Fatal("array_field missing or wrong type")
	}
	if len(arr) != 3 {
		t.Errorf("array_field length = %d, want 3", len(arr))
	}
}

func TestWriteVulnerability_CWEArrays(t *testing.T) {
	b := setupTestDB(t)
	ctx := context.Background()

	cwes := []string{"CWE-79", "CWE-89", "CWE-22", "CWE-352"}
	vuln := map[string]interface{}{
		"cve_id":     "CVE-2024-CWEARR",
		"weaknesses": cwes,
	}
	if err := b.WriteVulnerability(ctx, "vuln-cwearr", vuln); err != nil {
		t.Fatalf("WriteVulnerability: %v", err)
	}

	data, err := b.ReadVulnerability(ctx, "vuln-cwearr")
	if err != nil {
		t.Fatalf("ReadVulnerability: %v", err)
	}

	var got map[string]interface{}
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	arr, ok := got["weaknesses"].([]interface{})
	if !ok {
		t.Fatal("weaknesses missing or wrong type")
	}
	if len(arr) != 4 {
		t.Errorf("weaknesses length = %d, want 4", len(arr))
	}
}

func TestWriteVulnerability_CPEArrays(t *testing.T) {
	b := setupTestDB(t)
	ctx := context.Background()

	cpes := []string{
		"cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
		"cpe:2.3:a:apache:log4j:2.15.0:*:*:*:*:*:*:*",
		"cpe:2.3:a:apache:log4j:2.16.0:*:*:*:*:*:*:*",
	}
	vuln := map[string]interface{}{
		"cve_id": "CVE-2024-CPEARR",
		"cpes":   cpes,
	}
	if err := b.WriteVulnerability(ctx, "vuln-cpearr", vuln); err != nil {
		t.Fatalf("WriteVulnerability: %v", err)
	}

	data, err := b.ReadVulnerability(ctx, "vuln-cpearr")
	if err != nil {
		t.Fatalf("ReadVulnerability: %v", err)
	}

	var got map[string]interface{}
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	arr, ok := got["cpes"].([]interface{})
	if !ok {
		t.Fatal("cpes missing or wrong type")
	}
	if len(arr) != 3 {
		t.Errorf("cpes length = %d, want 3", len(arr))
	}
	if arr[0] != cpes[0] {
		t.Errorf("first CPE = %v, want %v", arr[0], cpes[0])
	}
}

func TestConcurrentReads(t *testing.T) {
	b := setupTestDB(t)
	ctx := context.Background()

	for i := 0; i < 10; i++ {
		ctrl := map[string]interface{}{
			"Framework": "READ-FW",
			"ControlID": fmt.Sprintf("R-%d", i),
			"Title":     fmt.Sprintf("Read Control %d", i),
		}
		if err := b.WriteControl(ctx, fmt.Sprintf("read-ctrl-%d", i), ctrl); err != nil {
			t.Fatalf("WriteControl %d: %v", i, err)
		}
	}

	var wg sync.WaitGroup
	errs := make(chan error, 10)

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, err := b.ReadControl(ctx, fmt.Sprintf("read-ctrl-%d", idx))
			if err != nil {
				errs <- err
			}
		}(i)
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("concurrent read error: %v", err)
	}
}

func TestConcurrentMixedReadWrite(t *testing.T) {
	b := setupTestDB(t)
	ctx := context.Background()

	var wg sync.WaitGroup
	errs := make(chan error, 20)

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			ctrl := map[string]interface{}{
				"Framework": "MIX-FW",
				"ControlID": fmt.Sprintf("MIX-%d", idx),
				"Title":     fmt.Sprintf("Mixed Control %d", idx),
			}
			if err := b.WriteControl(ctx, fmt.Sprintf("mix-ctrl-%d", idx), ctrl); err != nil {
				errs <- err
			}
		}(i)

		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			vuln := map[string]interface{}{
				"cve_id": fmt.Sprintf("CVE-2024-%04d", idx),
			}
			if err := b.WriteVulnerability(ctx, fmt.Sprintf("mix-vuln-%d", idx), vuln); err != nil {
				errs <- err
			}
		}(i)
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("concurrent mixed r/w error: %v", err)
	}

	ctrlRows, err := b.ListAllControls(ctx)
	if err != nil {
		t.Fatalf("ListAllControls: %v", err)
	}
	if len(ctrlRows) != 10 {
		t.Errorf("expected 10 controls, got %d", len(ctrlRows))
	}

	vulnRows, err := b.ListAllVulnerabilities(ctx)
	if err != nil {
		t.Fatalf("ListAllVulnerabilities: %v", err)
	}
	if len(vulnRows) != 10 {
		t.Errorf("expected 10 vulnerabilities, got %d", len(vulnRows))
	}
}

func TestConcurrentVulnerabilityWrites(t *testing.T) {
	b := setupTestDB(t)
	ctx := context.Background()

	var wg sync.WaitGroup
	errs := make(chan error, 10)

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			vuln := map[string]interface{}{
				"cve_id":   fmt.Sprintf("CVE-2024-%04d", idx),
				"severity": "HIGH",
			}
			if err := b.WriteVulnerability(ctx, fmt.Sprintf("conc-vuln-%d", idx), vuln); err != nil {
				errs <- err
			}
		}(i)
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("concurrent vuln write error: %v", err)
	}

	rows, err := b.ListAllVulnerabilities(ctx)
	if err != nil {
		t.Fatalf("ListAllVulnerabilities: %v", err)
	}
	if len(rows) != 10 {
		t.Errorf("expected 10 vulnerabilities, got %d", len(rows))
	}
}

func TestConcurrentMappingWrites(t *testing.T) {
	b := setupTestDB(t)
	ctx := context.Background()

	var wg sync.WaitGroup
	errs := make(chan error, 10)

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			if err := b.WriteMapping(ctx, fmt.Sprintf("cv-%d", idx), fmt.Sprintf("cc-%d", idx), "CMAP-FW", "direct", 0.9, "evidence"); err != nil {
				errs <- err
			}
		}(i)
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("concurrent mapping write error: %v", err)
	}

	for i := 0; i < 10; i++ {
		rows, err := b.ListMappings(ctx, fmt.Sprintf("cv-%d", i))
		if err != nil {
			t.Fatalf("ListMappings %d: %v", i, err)
		}
		if len(rows) != 1 {
			t.Errorf("expected 1 mapping for cv-%d, got %d", i, len(rows))
		}
	}
}

func TestOperationsAfterClose_WriteControl(t *testing.T) {
	path := t.TempDir() + "/after-close-ctrl.db"
	backend, err := NewSQLiteBackend(path)
	if err != nil {
		t.Fatalf("NewSQLiteBackend: %v", err)
	}
	backend.Close(context.Background())

	ctrl := map[string]interface{}{
		"Framework": "AC-FW",
		"ControlID": "AC-1",
		"Title":     "After Close",
	}
	err = backend.WriteControl(context.Background(), "ac-ctrl", ctrl)
	if err == nil {
		t.Error("expected error writing control after close, got nil")
	}
}

func TestOperationsAfterClose_WriteVulnerability(t *testing.T) {
	path := t.TempDir() + "/after-close-vuln.db"
	backend, err := NewSQLiteBackend(path)
	if err != nil {
		t.Fatalf("NewSQLiteBackend: %v", err)
	}
	backend.Close(context.Background())

	err = backend.WriteVulnerability(context.Background(), "ac-vuln", map[string]interface{}{"test": true})
	if err == nil {
		t.Error("expected error writing vulnerability after close, got nil")
	}
}

func TestOperationsAfterClose_WriteMapping(t *testing.T) {
	path := t.TempDir() + "/after-close-map.db"
	backend, err := NewSQLiteBackend(path)
	if err != nil {
		t.Fatalf("NewSQLiteBackend: %v", err)
	}
	backend.Close(context.Background())

	err = backend.WriteMapping(context.Background(), "v", "c", "FW", "direct", 0.9, "ev")
	if err == nil {
		t.Error("expected error writing mapping after close, got nil")
	}
}

func TestOperationsAfterClose_ListAllControls(t *testing.T) {
	path := t.TempDir() + "/after-close-listc.db"
	backend, err := NewSQLiteBackend(path)
	if err != nil {
		t.Fatalf("NewSQLiteBackend: %v", err)
	}
	backend.Close(context.Background())

	_, err = backend.ListAllControls(context.Background())
	if err == nil {
		t.Error("expected error listing controls after close, got nil")
	}
}

func TestOperationsAfterClose_ListAllVulnerabilities(t *testing.T) {
	path := t.TempDir() + "/after-close-listv.db"
	backend, err := NewSQLiteBackend(path)
	if err != nil {
		t.Fatalf("NewSQLiteBackend: %v", err)
	}
	backend.Close(context.Background())

	_, err = backend.ListAllVulnerabilities(context.Background())
	if err == nil {
		t.Error("expected error listing vulnerabilities after close, got nil")
	}
}

func TestOperationsAfterClose_ListControlsByFramework(t *testing.T) {
	path := t.TempDir() + "/after-close-listfw.db"
	backend, err := NewSQLiteBackend(path)
	if err != nil {
		t.Fatalf("NewSQLiteBackend: %v", err)
	}
	backend.Close(context.Background())

	_, err = backend.ListControlsByFramework(context.Background(), "FW")
	if err == nil {
		t.Error("expected error listing by framework after close, got nil")
	}
}

func TestOperationsAfterClose_ListMappings(t *testing.T) {
	path := t.TempDir() + "/after-close-listm.db"
	backend, err := NewSQLiteBackend(path)
	if err != nil {
		t.Fatalf("NewSQLiteBackend: %v", err)
	}
	backend.Close(context.Background())

	_, err = backend.ListMappings(context.Background(), "vuln")
	if err == nil {
		t.Error("expected error listing mappings after close, got nil")
	}
}

func TestOperationsAfterClose_ListControlsByCWE(t *testing.T) {
	path := t.TempDir() + "/after-close-listcwe.db"
	backend, err := NewSQLiteBackend(path)
	if err != nil {
		t.Fatalf("NewSQLiteBackend: %v", err)
	}
	backend.Close(context.Background())

	_, err = backend.ListControlsByCWE(context.Background(), "CWE-79")
	if err == nil {
		t.Error("expected error listing by CWE after close, got nil")
	}
}

func TestWriteControl_MultipleControlsSameFramework(t *testing.T) {
	b := setupTestDB(t)
	ctx := context.Background()

	frameworks := []string{"FW-1", "FW-1", "FW-2", "FW-2", "FW-2"}
	for i, fw := range frameworks {
		ctrl := map[string]interface{}{
			"Framework": fw,
			"ControlID": fmt.Sprintf("SC-%d", i),
			"Title":     fmt.Sprintf("Same FW Control %d", i),
		}
		if err := b.WriteControl(ctx, fmt.Sprintf("sf-ctrl-%d", i), ctrl); err != nil {
			t.Fatalf("WriteControl %d: %v", i, err)
		}
	}

	rows1, err := b.ListControlsByFramework(ctx, "FW-1")
	if err != nil {
		t.Fatalf("ListControlsByFramework FW-1: %v", err)
	}
	if len(rows1) != 2 {
		t.Errorf("expected 2 controls for FW-1, got %d", len(rows1))
	}

	rows2, err := b.ListControlsByFramework(ctx, "FW-2")
	if err != nil {
		t.Fatalf("ListControlsByFramework FW-2: %v", err)
	}
	if len(rows2) != 3 {
		t.Errorf("expected 3 controls for FW-2, got %d", len(rows2))
	}

	allRows, err := b.ListAllControls(ctx)
	if err != nil {
		t.Fatalf("ListAllControls: %v", err)
	}
	if len(allRows) != 5 {
		t.Errorf("expected 5 total controls, got %d", len(allRows))
	}
}

func TestWriteMapping_EmptyEvidence(t *testing.T) {
	b := setupTestDB(t)
	ctx := context.Background()

	if err := b.WriteMapping(ctx, "v-empty", "c-empty", "FW", "direct", 0.9, ""); err != nil {
		t.Fatalf("WriteMapping: %v", err)
	}

	rows, err := b.ListMappings(ctx, "v-empty")
	if err != nil {
		t.Fatalf("ListMappings: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 mapping, got %d", len(rows))
	}
	if rows[0].Evidence != "" {
		t.Errorf("Evidence = %q, want empty", rows[0].Evidence)
	}
}

func TestWriteMapping_ZeroConfidence(t *testing.T) {
	b := setupTestDB(t)
	ctx := context.Background()

	if err := b.WriteMapping(ctx, "v-zero", "c-zero", "FW", "direct", 0.0, "ev"); err != nil {
		t.Fatalf("WriteMapping: %v", err)
	}

	rows, err := b.ListMappings(ctx, "v-zero")
	if err != nil {
		t.Fatalf("ListMappings: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 mapping, got %d", len(rows))
	}
	if rows[0].Confidence != 0.0 {
		t.Errorf("Confidence = %f, want 0.0", rows[0].Confidence)
	}
}

func TestWriteMapping_FullConfidence(t *testing.T) {
	b := setupTestDB(t)
	ctx := context.Background()

	if err := b.WriteMapping(ctx, "v-full", "c-full", "FW", "direct", 1.0, "ev"); err != nil {
		t.Fatalf("WriteMapping: %v", err)
	}

	rows, err := b.ListMappings(ctx, "v-full")
	if err != nil {
		t.Fatalf("ListMappings: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 mapping, got %d", len(rows))
	}
	if rows[0].Confidence != 1.0 {
		t.Errorf("Confidence = %f, want 1.0", rows[0].Confidence)
	}
}

func TestListAllControls_PreservesRecordJSON(t *testing.T) {
	b := setupTestDB(t)
	ctx := context.Background()

	ctrl := map[string]interface{}{
		"Framework":   "JSON-FW",
		"ControlID":   "J-1",
		"Title":       "JSON Preserve",
		"CustomField": "custom-value",
		"Number":      123,
	}
	if err := b.WriteControl(ctx, "json-ctrl", ctrl); err != nil {
		t.Fatalf("WriteControl: %v", err)
	}

	rows, err := b.ListAllControls(ctx)
	if err != nil {
		t.Fatalf("ListAllControls: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 control, got %d", len(rows))
	}

	var got map[string]interface{}
	if err := json.Unmarshal(rows[0].Record, &got); err != nil {
		t.Fatalf("unmarshal record: %v", err)
	}
	if got["CustomField"] != "custom-value" {
		t.Errorf("CustomField = %v, want custom-value", got["CustomField"])
	}
	if got["Number"] != float64(123) {
		t.Errorf("Number = %v, want 123", got["Number"])
	}
}

func TestWriteVulnerability_EmptyRecord(t *testing.T) {
	b := setupTestDB(t)
	ctx := context.Background()

	vuln := map[string]interface{}{}
	if err := b.WriteVulnerability(ctx, "empty-vuln", vuln); err != nil {
		t.Fatalf("WriteVulnerability: %v", err)
	}

	data, err := b.ReadVulnerability(ctx, "empty-vuln")
	if err != nil {
		t.Fatalf("ReadVulnerability: %v", err)
	}

	if string(data) != "{}" {
		t.Errorf("expected '{}', got %s", string(data))
	}
}

func TestListControlsByFramework_MultipleDistinctFrameworks(t *testing.T) {
	b := setupTestDB(t)
	ctx := context.Background()

	frameworks := map[string]int{"NIST": 3, "ISO27001": 2, "SOC2": 4, "PCI-DSS": 1}
	idx := 0
	for fw, count := range frameworks {
		for i := 0; i < count; i++ {
			ctrl := map[string]interface{}{
				"Framework": fw,
				"ControlID": fmt.Sprintf("DF-%d", idx),
				"Title":     fmt.Sprintf("Distinct FW %d", idx),
			}
			if err := b.WriteControl(ctx, fmt.Sprintf("df-ctrl-%d", idx), ctrl); err != nil {
				t.Fatalf("WriteControl %d: %v", idx, err)
			}
			idx++
		}
	}

	for fw, expected := range frameworks {
		rows, err := b.ListControlsByFramework(ctx, fw)
		if err != nil {
			t.Fatalf("ListControlsByFramework %s: %v", fw, err)
		}
		if len(rows) != expected {
			t.Errorf("framework %s: expected %d controls, got %d", fw, expected, len(rows))
		}
	}

	allRows, err := b.ListAllControls(ctx)
	if err != nil {
		t.Fatalf("ListAllControls: %v", err)
	}
	if len(allRows) != 10 {
		t.Errorf("expected 10 total controls, got %d", len(allRows))
	}
}

type unmarshallableType struct {
	Ch chan int
}

func TestWriteVulnerability_Unmarshallable(t *testing.T) {
	b := setupTestDB(t)
	ctx := context.Background()

	err := b.WriteVulnerability(ctx, "bad-vuln", unmarshallableType{Ch: make(chan int)})
	if err == nil {
		t.Fatal("expected error marshaling unmarshallable type, got nil")
	}
}

func TestWriteControl_Unmarshallable(t *testing.T) {
	b := setupTestDB(t)
	ctx := context.Background()

	err := b.WriteControl(ctx, "bad-ctrl", unmarshallableType{Ch: make(chan int)})
	if err == nil {
		t.Fatal("expected error marshaling unmarshallable type, got nil")
	}
}

func TestWriteControl_NonStructControl(t *testing.T) {
	b := setupTestDB(t)
	ctx := context.Background()

	err := b.WriteControl(ctx, "non-struct-ctrl", "just a string")
	if err == nil {
		t.Fatal("expected error unmarshaling non-struct control, got nil")
	}
}

func TestNewSQLiteBackend_InitializeError(t *testing.T) {
	tmpDir := t.TempDir()
	path := tmpDir + "/test.db"
	backend, err := NewSQLiteBackend(path)
	if err != nil {
		t.Fatalf("NewSQLiteBackend: %v", err)
	}
	backend.Close(context.Background())

	// Use /proc/nonexistent which can never be created as a directory.
	_, err = NewSQLiteBackend("/proc/nonexistent/foo/bar/test.db")
	if err == nil {
		t.Fatal("expected error for unwritable path, got nil")
	}
}

func TestNewSQLiteBackend_InvalidPath(t *testing.T) {
	_, err := NewSQLiteBackend("/proc/nonexistent/foo/bar/test.db")
	if err == nil {
		t.Fatal("expected error creating backend with invalid path, got nil")
	}
}

func TestClose_AfterCloseReturnsNil(t *testing.T) {
	path := t.TempDir() + "/double-close.db"
	b, err := NewSQLiteBackend(path)
	if err != nil {
		t.Fatalf("NewSQLiteBackend: %v", err)
	}

	if err := b.Close(context.Background()); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := b.Close(context.Background()); err != nil {
		t.Errorf("second Close should return nil, got: %v", err)
	}
	if err := b.Close(context.Background()); err != nil {
		t.Errorf("third Close should return nil, got: %v", err)
	}
}

func TestClose_WALCheckpointError(t *testing.T) {
	path := t.TempDir() + "/close-wal-err.db"
	b, err := NewSQLiteBackend(path)
	if err != nil {
		t.Fatalf("NewSQLiteBackend: %v", err)
	}

	b.db.Close()
	b.closed = false

	err = b.Close(context.Background())
	if err == nil {
		t.Fatal("expected error when db already closed for wal_checkpoint, got nil")
	}
}

func TestListAllVulnerabilities_CanceledContext(t *testing.T) {
	b := setupTestDB(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := b.ListAllVulnerabilities(ctx)
	if err == nil {
		t.Fatal("expected error on canceled context, got nil")
	}
}

func TestListMappings_CanceledContext(t *testing.T) {
	b := setupTestDB(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := b.ListMappings(ctx, "any-vuln")
	if err == nil {
		t.Fatal("expected error on canceled context, got nil")
	}
}

func TestListControlsByCPE_CanceledContext(t *testing.T) {
	b := setupTestDB(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := b.ListControlsByCPE(ctx, "cpe:2.3:a:any:app:1.0:*:*:*:*:*:*:*")
	if err == nil {
		t.Fatal("expected error on canceled context, got nil")
	}
}

func TestListAllControls_CanceledContext(t *testing.T) {
	b := setupTestDB(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := b.ListAllControls(ctx)
	if err == nil {
		t.Fatal("expected error on canceled context, got nil")
	}
}

func TestListControlsByCWE_CanceledContext(t *testing.T) {
	b := setupTestDB(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := b.ListControlsByCWE(ctx, "CWE-79")
	if err == nil {
		t.Fatal("expected error on canceled context, got nil")
	}
}

func TestListControlsByFramework_CanceledContext(t *testing.T) {
	b := setupTestDB(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := b.ListControlsByFramework(ctx, "NIST")
	if err == nil {
		t.Fatal("expected error on canceled context, got nil")
	}
}

func TestReadVulnerability_CanceledContext(t *testing.T) {
	b := setupTestDB(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := b.ReadVulnerability(ctx, "any-id")
	if err == nil {
		t.Fatal("expected error on canceled context, got nil")
	}
}

func TestReadControl_CanceledContext(t *testing.T) {
	b := setupTestDB(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := b.ReadControl(ctx, "any-id")
	if err == nil {
		t.Fatal("expected error on canceled context, got nil")
	}
}

func TestWriteVulnerability_CanceledContext(t *testing.T) {
	b := setupTestDB(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := b.WriteVulnerability(ctx, "any-id", map[string]interface{}{"test": true})
	if err == nil {
		t.Fatal("expected error on canceled context, got nil")
	}
}

func TestWriteControl_CanceledContext(t *testing.T) {
	b := setupTestDB(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := b.WriteControl(ctx, "any-id", map[string]interface{}{"Framework": "FW", "ControlID": "C-1", "Title": "T"})
	if err == nil {
		t.Fatal("expected error on canceled context, got nil")
	}
}

func TestWriteMapping_CanceledContext(t *testing.T) {
	b := setupTestDB(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := b.WriteMapping(ctx, "v", "c", "FW", "direct", 0.9, "ev")
	if err == nil {
		t.Fatal("expected error on canceled context, got nil")
	}
}

func TestExtractVulnCWEs_InvalidJSON(t *testing.T) {
	cwes := extractVulnCWEs([]byte("not valid json"))
	if cwes != nil {
		t.Errorf("expected nil for invalid JSON, got %v", cwes)
	}
}

func TestExtractVulnCWEs_EmptyJSON(t *testing.T) {
	cwes := extractVulnCWEs([]byte(`{}`))
	if len(cwes) != 0 {
		t.Errorf("expected empty for empty JSON, got %v", cwes)
	}
}

func TestExtractVulnCWEs_NoCVEField(t *testing.T) {
	cwes := extractVulnCWEs([]byte(`{"id":"CVE-2024-1234"}`))
	if len(cwes) != 0 {
		t.Errorf("expected empty with no cve field, got %v", cwes)
	}
}

func TestExtractVulnCWEs_NoWeaknesses(t *testing.T) {
	cwes := extractVulnCWEs([]byte(`{"id":"CVE-2024-1234","cve":{"id":"CVE-2024-1234"}}`))
	if len(cwes) != 0 {
		t.Errorf("expected empty with no weaknesses, got %v", cwes)
	}
}

func TestExtractVulnCWEs_NonEnglish(t *testing.T) {
	cwes := extractVulnCWEs([]byte(`{"cve":{"weaknesses":[{"description":[{"lang":"fr","value":"CWE-79"}]}]}}`))
	if len(cwes) != 0 {
		t.Errorf("expected empty for non-English weakness, got %v", cwes)
	}
}

func TestExtractVulnCWEs_NonCWEPrefix(t *testing.T) {
	cwes := extractVulnCWEs([]byte(`{"cve":{"weaknesses":[{"description":[{"lang":"en","value":"NVD-CWE-Other"}]}]}}`))
	if len(cwes) != 0 {
		t.Errorf("expected empty for non-CWE- prefix, got %v", cwes)
	}
}

func TestExtractVulnCWEs_Deduplicates(t *testing.T) {
	cwes := extractVulnCWEs([]byte(`{"cve":{"weaknesses":[{"description":[{"lang":"en","value":"CWE-79"}]},{"description":[{"lang":"en","value":"CWE-79"}]}]}}`))
	if len(cwes) != 1 {
		t.Errorf("expected 1 deduplicated CWE, got %d: %v", len(cwes), cwes)
	}
}

func TestExtractVulnCWEs_MultipleWeaknesses(t *testing.T) {
	cwes := extractVulnCWEs([]byte(`{"cve":{"weaknesses":[{"description":[{"lang":"en","value":"CWE-79"},{"lang":"en","value":"CWE-89"}]}]}}`))
	if len(cwes) != 2 {
		t.Errorf("expected 2 CWEs, got %d: %v", len(cwes), cwes)
	}
}

func TestListControlsByCPE_ListControlsByCWEError(t *testing.T) {
	b := setupTestDB(t)
	ctx := context.Background()

	vuln := makeNVDVuln("CVE-2024-CWEERR", "cpe:2.3:a:cweerr:app:1.0:*:*:*:*:*:*:*", []string{"CWE-79"})
	if err := b.WriteVulnerability(ctx, "vuln-cwe-err", vuln); err != nil {
		t.Fatalf("WriteVulnerability: %v", err)
	}

	b.db.Exec("DROP TABLE grc_controls")
	b.db.Exec("CREATE TABLE grc_controls (id TEXT PRIMARY KEY)")

	_, err := b.ListControlsByCPE(ctx, "cpe:2.3:a:cweerr:app:1.0:*:*:*:*:*:*:*")
	if err == nil {
		t.Fatal("expected error when ListControlsByCWE fails inside ListControlsByCPE, got nil")
	}
}

func TestListControlsByCPE_ListAllVulnsError(t *testing.T) {
	b := setupTestDB(t)
	ctx := context.Background()

	b.db.Exec("DROP TABLE vulnerabilities")
	b.db.Exec("CREATE TABLE vulnerabilities (id TEXT PRIMARY KEY)")

	_, err := b.ListControlsByCPE(ctx, "cpe:2.3:a:any:app:1.0:*:*:*:*:*:*:*")
	if err == nil {
		t.Fatal("expected error when ListAllVulnerabilities fails inside ListControlsByCPE, got nil")
	}
}

func TestListControlsByCPE_VulnWithCPEButNoMatchingControls(t *testing.T) {
	b := setupTestDB(t)
	ctx := context.Background()

	vuln := makeNVDVuln("CVE-2024-NOMATCH", "cpe:2.3:a:nomatch:app:1.0:*:*:*:*:*:*:*", []string{"CWE-999"})
	if err := b.WriteVulnerability(ctx, "vuln-nomatch", vuln); err != nil {
		t.Fatalf("WriteVulnerability: %v", err)
	}

	ctrl := map[string]interface{}{
		"Framework":   "NOMATCH-FW",
		"ControlID":   "NM-1",
		"Title":       "Unrelated Control",
		"RelatedCWEs": []string{"CWE-79"},
	}
	if err := b.WriteControl(ctx, "nomatch-ctrl", ctrl); err != nil {
		t.Fatalf("WriteControl: %v", err)
	}

	rows, err := b.ListControlsByCPE(ctx, "cpe:2.3:a:nomatch:app:1.0:*:*:*:*:*:*:*")
	if err != nil {
		t.Fatalf("ListControlsByCPE: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("expected 0 controls when CWE has no matching controls, got %d", len(rows))
	}
}

func TestListControlsByCPE_MultipleVulnsDifferentCWEs(t *testing.T) {
	b := setupTestDB(t)
	ctx := context.Background()

	vuln1 := makeNVDVuln("CVE-2024-MULTI1", "cpe:2.3:a:multi:app:1.0:*:*:*:*:*:*:*", []string{"CWE-79"})
	vuln2 := makeNVDVuln("CVE-2024-MULTI2", "cpe:2.3:a:multi:app:2.0:*:*:*:*:*:*:*", []string{"CWE-89"})
	if err := b.WriteVulnerability(ctx, "vuln-multi-1", vuln1); err != nil {
		t.Fatalf("WriteVulnerability vuln1: %v", err)
	}
	if err := b.WriteVulnerability(ctx, "vuln-multi-2", vuln2); err != nil {
		t.Fatalf("WriteVulnerability vuln2: %v", err)
	}

	ctrl79 := map[string]interface{}{
		"Framework":   "MULTI-CPE-FW",
		"ControlID":   "MCP-79",
		"Title":       "XSS Control",
		"RelatedCWEs": []string{"CWE-79"},
	}
	ctrl89 := map[string]interface{}{
		"Framework":   "MULTI-CPE-FW",
		"ControlID":   "MCP-89",
		"Title":       "SQLi Control",
		"RelatedCWEs": []string{"CWE-89"},
	}
	if err := b.WriteControl(ctx, "multi-cpe-79", ctrl79); err != nil {
		t.Fatalf("WriteControl ctrl79: %v", err)
	}
	if err := b.WriteControl(ctx, "multi-cpe-89", ctrl89); err != nil {
		t.Fatalf("WriteControl ctrl89: %v", err)
	}

	cpe := "cpe:2.3:a:multi:app"
	rows, err := b.ListControlsByCPE(ctx, cpe)
	if err != nil {
		t.Fatalf("ListControlsByCPE: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("expected 2 controls from different CWEs, got %d", len(rows))
	}

	ids := map[string]bool{}
	for _, r := range rows {
		ids[r.ControlID] = true
	}
	if !ids["MCP-79"] || !ids["MCP-89"] {
		t.Errorf("expected both MCP-79 and MCP-89, got %v", ids)
	}
}

func TestClose_RenamesTempFile_Failure(t *testing.T) {
	path := t.TempDir() + "/rename-fail.db"
	b, err := NewSQLiteBackend(path)
	if err != nil {
		t.Fatalf("NewSQLiteBackend: %v", err)
	}

	os.MkdirAll(path, 0755)

	err = b.Close(context.Background())
	if err == nil {
		t.Fatal("expected error when temp file can't be renamed to a directory, got nil")
	}
}

func TestNewSQLiteBackend_ThenForceCloseDB(t *testing.T) {
	path := t.TempDir() + "/force-close.db"
	b, err := NewSQLiteBackend(path)
	if err != nil {
		t.Fatalf("NewSQLiteBackend: %v", err)
	}

	b.db.Close()
	b.closed = false

	err = b.Close(context.Background())
	if err == nil {
		t.Fatal("expected error when db is already closed and wal_checkpoint fails, got nil")
	}
}

func TestOperationsAfterClose_ListControlsByCPE(t *testing.T) {
	path := t.TempDir() + "/after-close-cpe.db"
	backend, err := NewSQLiteBackend(path)
	if err != nil {
		t.Fatalf("NewSQLiteBackend: %v", err)
	}
	backend.Close(context.Background())

	_, err = backend.ListControlsByCPE(context.Background(), "cpe:2.3:a:any:app:1.0:*:*:*:*:*:*:*")
	if err == nil {
		t.Error("expected error listing by CPE after close, got nil")
	}
}

func TestWriteControl_MarshalErrorLocked(t *testing.T) {
	b := setupTestDB(t)
	ctx := context.Background()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		b.mu.Lock()
		time.Sleep(50 * time.Millisecond)
		b.mu.Unlock()
	}()

	time.Sleep(5 * time.Millisecond)

	done := make(chan struct{})
	go func() {
		defer close(done)
		b.WriteControl(ctx, "lock-test", unmarshallableType{Ch: make(chan int)})
	}()

	<-done
	wg.Wait()
}

func TestWriteVulnerability_MarshalErrorLocked(t *testing.T) {
	b := setupTestDB(t)
	ctx := context.Background()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		b.mu.Lock()
		time.Sleep(50 * time.Millisecond)
		b.mu.Unlock()
	}()

	time.Sleep(5 * time.Millisecond)

	done := make(chan struct{})
	go func() {
		defer close(done)
		b.WriteVulnerability(ctx, "lock-test", unmarshallableType{Ch: make(chan int)})
	}()

	<-done
	wg.Wait()
}

func TestInitialize_PragmaError(t *testing.T) {
	db, err := sql.Open("sqlite", t.TempDir()+"/pragma-fail.db")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	db.Close()

	b := &SQLiteBackend{
		db: db,
	}

	err = b.initialize()
	if err == nil {
		t.Fatal("expected error from initialize with closed db, got nil")
	}
}

func TestInitialize_SchemaError(t *testing.T) {
	path := t.TempDir() + "/schema-fail.db"
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	_, err = db.Exec("CREATE TABLE vulnerabilities (id TEXT PRIMARY KEY, record BLOB NOT NULL)")
	if err != nil {
		db.Close()
		t.Fatalf("create table: %v", err)
	}

	b := &SQLiteBackend{
		db: db,
	}

	err = b.initialize()
	db.Close()
	if err != nil {
		t.Fatalf("first initialize should succeed: %v", err)
	}
}

func TestInitialize_SchemaExecError(t *testing.T) {
	path := t.TempDir() + "/schema-exec-fail.db"
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	defer db.Close()

	_, err = db.Exec("CREATE VIEW vulnerabilities AS SELECT 1")
	if err != nil {
		t.Fatalf("create view: %v", err)
	}

	b := &SQLiteBackend{
		db: db,
	}

	err = b.initialize()
	if err == nil {
		t.Fatal("expected error when schema can't create table (view exists), got nil")
	}
}

func TestScanControlRows_ColumnMismatch(t *testing.T) {
	path := t.TempDir() + "/scan-fail.db"
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	defer db.Close()

	_, err = db.Exec("CREATE TABLE grc_controls (id TEXT PRIMARY KEY, record BLOB NOT NULL)")
	if err != nil {
		t.Fatalf("create table: %v", err)
	}
	_, err = db.Exec("INSERT INTO grc_controls (id, record) VALUES ('x', '\"test\"')")
	if err != nil {
		t.Fatalf("insert: %v", err)
	}

	rows, err := db.Query("SELECT id, record FROM grc_controls")
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer rows.Close()

	_, err = scanControlRows(rows)
	if err == nil {
		t.Fatal("expected scan error with column mismatch, got nil")
	}
}

func TestListMappings_ScanError(t *testing.T) {
	b := setupTestDB(t)

	b.db.Exec("DROP TABLE vulnerability_grc_mappings")
	// Create table with mismatched column order to force a scan error:
	// real schema has (vulnerability_id, control_id, framework, mapping_type,
	// confidence REAL, evidence TEXT) but we put evidence first and use INTEGER
	// for confidence so the float64 scan gets an incompatible type.
	b.db.Exec(`CREATE TABLE vulnerability_grc_mappings (
		vulnerability_id TEXT NOT NULL,
		control_id TEXT NOT NULL,
		framework TEXT NOT NULL,
		mapping_type TEXT NOT NULL,
		evidence TEXT NOT NULL,
		confidence TEXT NOT NULL
	)`)
	b.db.Exec(`INSERT INTO vulnerability_grc_mappings VALUES ('v','c','f','m','e','not-a-number')`)

	ctx := context.Background()
	_, err := b.ListMappings(ctx, "v")
	t.Logf("ListMappings error: %v", err)
	if err == nil {
		t.Fatal("expected scan error with type mismatch, got nil")
	}
}

func TestListAllVulnerabilities_ScanError(t *testing.T) {
	b := setupTestDB(t)

	b.db.Exec("DROP TABLE vulnerabilities")
	b.db.Exec(`CREATE TABLE vulnerabilities (
		id INTEGER PRIMARY KEY,
		record INTEGER NOT NULL
	)`)
	b.db.Exec(`INSERT INTO vulnerabilities VALUES (1, 2)`)

	ctx := context.Background()
	_, err := b.ListAllVulnerabilities(ctx)
	t.Logf("ListAllVulnerabilities error: %v", err)
	if err == nil {
		t.Fatal("expected scan error with type mismatch, got nil")
	}
}

func TestListControlsByFramework_ScanError(t *testing.T) {
	b := setupTestDB(t)

	b.db.Exec("DROP TABLE grc_controls")
	b.db.Exec("CREATE TABLE grc_controls (id TEXT PRIMARY KEY)")

	ctx := context.Background()
	_, err := b.ListControlsByFramework(ctx, "FW")
	if err == nil {
		t.Fatal("expected error with column mismatch, got nil")
	}
}

func TestListControlsByCWE_ScanError(t *testing.T) {
	b := setupTestDB(t)

	b.db.Exec("DROP TABLE grc_controls")
	b.db.Exec("CREATE TABLE grc_controls (id TEXT PRIMARY KEY)")

	ctx := context.Background()
	_, err := b.ListControlsByCWE(ctx, "CWE-79")
	if err == nil {
		t.Fatal("expected error with column mismatch, got nil")
	}
}

func TestListAllControls_ScanError(t *testing.T) {
	b := setupTestDB(t)

	b.db.Exec("DROP TABLE grc_controls")
	b.db.Exec("CREATE TABLE grc_controls (id TEXT PRIMARY KEY)")

	ctx := context.Background()
	_, err := b.ListAllControls(ctx)
	if err == nil {
		t.Fatal("expected error with column mismatch, got nil")
	}
}

func TestClose_DbCloseError(t *testing.T) {
	path := t.TempDir() + "/close-db-err.db"
	b, err := NewSQLiteBackend(path)
	if err != nil {
		t.Fatalf("NewSQLiteBackend: %v", err)
	}

	b.db.Close()
	b.closed = false

	err = b.Close(context.Background())
	if err == nil {
		t.Fatal("expected error when db.Close fails (already closed), got nil")
	}
}

func TestClose_RenameErrorTempFileGone(t *testing.T) {
	path := t.TempDir() + "/close-norename.db"
	b, err := NewSQLiteBackend(path)
	if err != nil {
		t.Fatalf("NewSQLiteBackend: %v", err)
	}

	os.Remove(b.tempPath)
	b.tempPath = "/nonexistent/path/that/does/not/exist.db"

	err = b.Close(context.Background())
	if err != nil {
		t.Fatalf("Close should succeed when temp file doesn't exist: %v", err)
	}
}
