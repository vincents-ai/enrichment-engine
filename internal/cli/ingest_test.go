package cli

import (
	"bytes"
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	_ "github.com/glebarez/go-sqlite/compat"
)

func TestIngestFile(t *testing.T) {
	tmpDir := t.TempDir()
	origWorkspace := workspace
	workspace = tmpDir
	defer func() { workspace = origWorkspace }()

	singleVuln := `{"id":"CVE-2021-44228","cve":{"id":"CVE-2021-44228","published":"2021-12-10T15:15:00.000Z","weaknesses":[{"description":[{"lang":"en","value":"CWE-502"}]}],"configurations":[]}}`

	filePath := filepath.Join(tmpDir, "vuln.json")
	if err := os.WriteFile(filePath, []byte(singleVuln), 0644); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	cmd := ingestCmd()
	cmd.SetArgs([]string{"--file", filePath})

	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute ingest: %v", err)
	}

	dbPath := tmpDir + "/enrichment.db"
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		t.Fatal("expected enrichment.db to exist after ingest")
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()

	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM vulnerabilities").Scan(&count); err != nil {
		t.Fatalf("count vulnerabilities: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 vulnerability, got %d", count)
	}

	var vulnID string
	if err := db.QueryRow("SELECT id FROM vulnerabilities").Scan(&vulnID); err != nil {
		t.Fatalf("scan vuln id: %v", err)
	}
	if vulnID != "CVE-2021-44228" {
		t.Errorf("expected CVE-2021-44228, got %s", vulnID)
	}
}

func TestIngestFileArray(t *testing.T) {
	tmpDir := t.TempDir()
	origWorkspace := workspace
	workspace = tmpDir
	defer func() { workspace = origWorkspace }()

	arrayVulns := `[{"id":"CVE-2021-44228","cve":{}},{"id":"CVE-2021-45105","cve":{}}]`

	filePath := filepath.Join(tmpDir, "vulns.json")
	if err := os.WriteFile(filePath, []byte(arrayVulns), 0644); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	cmd := ingestCmd()
	cmd.SetArgs([]string{"--file", filePath})

	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute ingest: %v", err)
	}

	dbPath := tmpDir + "/enrichment.db"
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()

	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM vulnerabilities").Scan(&count); err != nil {
		t.Fatalf("count vulnerabilities: %v", err)
	}
	if count != 2 {
		t.Fatalf("expected 2 vulnerabilities, got %d", count)
	}
}

func TestIngestStdin(t *testing.T) {
	tmpDir := t.TempDir()
	origWorkspace := workspace
	workspace = tmpDir
	defer func() { workspace = origWorkspace }()

	vuln := `{"id":"CVE-2023-0001","cve":{"id":"CVE-2023-0001","published":"2023-01-01T00:00:00.000Z","weaknesses":[],"configurations":[]}}`

	cmd := ingestCmd()
	cmd.SetArgs([]string{})

	oldStdin := os.Stdin
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdin = r

	go func() {
		w.Write([]byte(vuln))
		w.Close()
	}()

	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)

	execErr := cmd.Execute()

	r.Close()
	os.Stdin = oldStdin

	if execErr != nil {
		t.Fatalf("execute ingest: %v", execErr)
	}

	dbPath := tmpDir + "/enrichment.db"
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()

	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM vulnerabilities").Scan(&count); err != nil {
		t.Fatalf("count vulnerabilities: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 vulnerability, got %d", count)
	}
}

func TestIngestInvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	origWorkspace := workspace
	workspace = tmpDir
	defer func() { workspace = origWorkspace }()

	filePath := filepath.Join(tmpDir, "bad.json")
	if err := os.WriteFile(filePath, []byte("not json{{{"), 0644); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	cmd := ingestCmd()
	cmd.SetArgs([]string{"--file", filePath})

	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)

	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestIngestEmptyFile(t *testing.T) {
	tmpDir := t.TempDir()
	origWorkspace := workspace
	workspace = tmpDir
	defer func() { workspace = origWorkspace }()

	filePath := filepath.Join(tmpDir, "empty.json")
	if err := os.WriteFile(filePath, []byte(""), 0644); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	cmd := ingestCmd()
	cmd.SetArgs([]string{"--file", filePath})

	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)

	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error for empty input")
	}
}
