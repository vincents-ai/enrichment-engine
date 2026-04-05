package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/shift/enrichment-engine/pkg/storage"
)

func seedExportDB(t *testing.T, tmpDir string) {
	t.Helper()
	dbPath := tmpDir + "/enrichment.db"
	store, err := storage.NewSQLiteBackend(dbPath)
	if err != nil {
		t.Fatalf("create db: %v", err)
	}

	ctx := t.Context()
	store.WriteVulnerability(ctx, "CVE-2021-44228", map[string]interface{}{
		"id":  "CVE-2021-44228",
		"cve": map[string]interface{}{"id": "CVE-2021-44228"},
	})
	store.WriteControl(ctx, "ctrl-1", map[string]interface{}{
		"Framework": "HIPAA", "ControlID": "164.308.a.1", "Title": "Security Management Process", "RelatedCWEs": []string{"CWE-502"},
	})
	store.WriteMapping(ctx, "CVE-2021-44228", "ctrl-1", "HIPAA", "cwe", 0.8, "CWE-502 shared")
	store.Close(ctx)
}

func TestExportEmpty(t *testing.T) {
	tmpDir := t.TempDir()
	origWorkspace := workspace
	workspace = tmpDir
	defer func() { workspace = origWorkspace }()

	outputPath := filepath.Join(tmpDir, "bom.json")

	cmd := exportCmd()
	cmd.SetArgs([]string{"--output", outputPath})

	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute export: %v", err)
	}

	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}

	var bom map[string]interface{}
	if err := json.Unmarshal(data, &bom); err != nil {
		t.Fatalf("parse BOM JSON: %v", err)
	}
	if bom["bomFormat"] != "CycloneDX" {
		t.Errorf("expected bomFormat CycloneDX, got %v", bom["bomFormat"])
	}
	if bom["specVersion"] != "1.5" {
		t.Errorf("expected specVersion 1.5, got %v", bom["specVersion"])
	}
}

func TestExportWithVulnAndMappings(t *testing.T) {
	tmpDir := t.TempDir()
	origWorkspace := workspace
	workspace = tmpDir
	defer func() { workspace = origWorkspace }()

	seedExportDB(t, tmpDir)

	outputPath := filepath.Join(tmpDir, "bom.json")

	cmd := exportCmd()
	cmd.SetArgs([]string{"--output", outputPath})

	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute export: %v", err)
	}

	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}

	var bom map[string]interface{}
	if err := json.Unmarshal(data, &bom); err != nil {
		t.Fatalf("parse BOM JSON: %v", err)
	}

	vulns, ok := bom["vulnerabilities"].([]interface{})
	if !ok || len(vulns) != 1 {
		t.Fatalf("expected 1 vulnerability, got %v", bom["vulnerabilities"])
	}

	vuln := vulns[0].(map[string]interface{})
	if vuln["id"] != "CVE-2021-44228" {
		t.Errorf("expected CVE ID CVE-2021-44228, got %v", vuln["id"])
	}

	affects, ok := vuln["affects"].([]interface{})
	if !ok || len(affects) != 1 {
		t.Fatalf("expected 1 affect, got %v", vuln["affects"])
	}
}

func TestExportStdout(t *testing.T) {
	tmpDir := t.TempDir()
	origWorkspace := workspace
	workspace = tmpDir
	defer func() { workspace = origWorkspace }()

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	cmd := exportCmd()
	cmd.SetArgs([]string{})

	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)

	execErr := cmd.Execute()

	w.Close()
	os.Stdout = oldStdout

	var stdout bytes.Buffer
	stdout.ReadFrom(r)

	if execErr != nil {
		t.Fatalf("execute export: %v", execErr)
	}

	var bom map[string]interface{}
	if err := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &bom); err != nil {
		t.Fatalf("parse stdout JSON: %v (output: %s)", err, stdout.String())
	}
	if bom["bomFormat"] != "CycloneDX" {
		t.Errorf("expected bomFormat CycloneDX, got %v", bom["bomFormat"])
	}
}

func TestExportMultipleMappings(t *testing.T) {
	tmpDir := t.TempDir()
	origWorkspace := workspace
	workspace = tmpDir
	defer func() { workspace = origWorkspace }()

	dbPath := tmpDir + "/enrichment.db"
	store, err := storage.NewSQLiteBackend(dbPath)
	if err != nil {
		t.Fatalf("create db: %v", err)
	}

	ctx := t.Context()
	store.WriteVulnerability(ctx, "CVE-2021-44228", map[string]interface{}{
		"id":  "CVE-2021-44228",
		"cve": map[string]interface{}{"id": "CVE-2021-44228"},
	})
	store.WriteControl(ctx, "ctrl-1", map[string]interface{}{
		"Framework": "HIPAA", "ControlID": "164.308.a.1", "Title": "HIPAA Control 1", "RelatedCWEs": []string{"CWE-502"},
	})
	store.WriteControl(ctx, "ctrl-2", map[string]interface{}{
		"Framework": "GDPR", "ControlID": "5.1.f", "Title": "GDPR Control", "RelatedCWEs": []string{"CWE-502"},
	})
	store.WriteMapping(ctx, "CVE-2021-44228", "ctrl-1", "HIPAA", "cwe", 0.8, "CWE-502")
	store.WriteMapping(ctx, "CVE-2021-44228", "ctrl-2", "GDPR", "cwe", 0.8, "CWE-502")
	store.Close(ctx)

	outputPath := filepath.Join(tmpDir, "bom.json")

	cmd := exportCmd()
	cmd.SetArgs([]string{"--output", outputPath})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute export: %v", err)
	}

	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}

	var bom map[string]interface{}
	if err := json.Unmarshal(data, &bom); err != nil {
		t.Fatalf("parse BOM: %v", err)
	}

	vulns, ok := bom["vulnerabilities"].([]interface{})
	if !ok || len(vulns) != 1 {
		t.Fatalf("expected 1 vulnerability, got %v", bom["vulnerabilities"])
	}

	vuln := vulns[0].(map[string]interface{})
	affects, ok := vuln["affects"].([]interface{})
	if !ok || len(affects) != 2 {
		t.Fatalf("expected 2 affects, got %v", vuln["affects"])
	}
}
