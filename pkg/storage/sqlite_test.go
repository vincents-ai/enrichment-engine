package storage

import (
	"context"
	"encoding/json"
	"os"
	"sync"
	"testing"
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

func TestListControlsByCPE_ReturnsAll(t *testing.T) {
	b := setupTestDB(t)
	ctx := context.Background()

	ctrl := map[string]interface{}{
		"Framework": "FW-CPE",
		"ControlID": "CP-1",
		"Title":     "CPE Test Control",
	}
	if err := b.WriteControl(ctx, "cpe-ctrl", ctrl); err != nil {
		t.Fatalf("WriteControl: %v", err)
	}

	allRows, err := b.ListAllControls(ctx)
	if err != nil {
		t.Fatalf("ListAllControls: %v", err)
	}

	cpeRows, err := b.ListControlsByCPE(ctx, "cpe:2.3:a:fake:app:*:*:*:*:*:*:*:*")
	if err != nil {
		t.Fatalf("ListControlsByCPE: %v", err)
	}

	if len(cpeRows) != len(allRows) {
		t.Errorf("ListControlsByCPE returned %d, ListAllControls returned %d", len(cpeRows), len(allRows))
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
	if len(rows) != 1 {
		t.Fatalf("expected 1 mapping (upsert), got %d", len(rows))
	}
	if rows[0].MappingType != "indirect" {
		t.Errorf("MappingType = %q, want %q (should be updated)", rows[0].MappingType, "indirect")
	}
	if rows[0].Confidence != 0.8 {
		t.Errorf("Confidence = %f, want 0.8", rows[0].Confidence)
	}
}
