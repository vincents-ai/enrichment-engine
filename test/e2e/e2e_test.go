package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

var (
	binaryPath string
	buildOnce  sync.Once
	buildErr   error
)

func TestMain(m *testing.M) {
	buildOnce.Do(func() {
		dir, err := os.MkdirTemp("", "enrich-e2e-*")
		if err != nil {
			buildErr = err
			return
		}
		binaryPath = filepath.Join(dir, "enrich")
		cmd := exec.Command("go", "build", "-o", binaryPath, "../../cmd/enrich")
		cmd.Stdout = os.Stderr
		cmd.Stderr = os.Stderr
		buildErr = cmd.Run()
	})
	if buildErr != nil {
		fmt.Fprintf(os.Stderr, "SKIP: cannot build binary: %v\n", buildErr)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func enrich(t *testing.T, workspace string, args ...string) (stdout, stderr string, exitCode int) {
	t.Helper()
	fullArgs := []string{"-w", workspace, "-l", "error"}
	fullArgs = append(fullArgs, args...)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, binaryPath, fullArgs...)
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	stdout = outBuf.String()
	stderr = errBuf.String()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1
		}
	}
	return
}

func enrichStdin(t *testing.T, workspace string, stdinData []byte, args ...string) (stdout, stderr string, exitCode int) {
	t.Helper()
	fullArgs := []string{"-w", workspace, "-l", "error"}
	fullArgs = append(fullArgs, args...)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, binaryPath, fullArgs...)
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	cmd.Stdin = bytes.NewReader(stdinData)
	err := cmd.Run()
	stdout = outBuf.String()
	stderr = errBuf.String()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1
		}
	}
	return
}

func fixturePath(t *testing.T, name string) string {
	t.Helper()
	p := filepath.Join("fixtures", name)
	abs, err := filepath.Abs(p)
	if err != nil {
		t.Fatalf("fixture path: %v", err)
	}
	if _, err := os.Stat(abs); err != nil {
		t.Fatalf("fixture not found: %s", abs)
	}
	return abs
}

func fixtureBytes(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(fixturePath(t, name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return data
}

func TestE2E_Version(t *testing.T) {
	dir := t.TempDir()
	stdout, _, exitCode := enrich(t, dir, "version")
	if exitCode != 0 {
		t.Fatalf("expected exit 0, got %d: %s", exitCode, stdout)
	}
	if !strings.Contains(stdout, "enrichment-engine") {
		t.Fatalf("expected 'enrichment-engine' in output, got: %s", stdout)
	}
}

func TestE2E_Providers(t *testing.T) {
	dir := t.TempDir()
	stdout, _, exitCode := enrich(t, dir, "providers")
	if exitCode != 0 {
		t.Fatalf("expected exit 0, got %d: %s", exitCode, stdout)
	}
	for _, provider := range []string{"hipaa", "pci_dss"} {
		if !strings.Contains(stdout, provider) {
			t.Errorf("expected provider %q in output, got: %s", provider, stdout)
		}
	}
}

func TestE2E_IngestSingleFile(t *testing.T) {
	dir := t.TempDir()
	fp := fixturePath(t, "log4shell.json")
	stdout, _, exitCode := enrich(t, dir, "ingest", "-f", fp)
	if exitCode != 0 {
		t.Fatalf("expected exit 0, got %d: stderr=%s stdout=%s", exitCode, stdout, stdout)
	}
	if !strings.Contains(stdout, "1 vulnerabilities") {
		t.Fatalf("expected '1 vulnerabilities' in output, got: %s", stdout)
	}
}

func TestE2E_IngestBatch(t *testing.T) {
	dir := t.TempDir()
	fp := fixturePath(t, "batch_cves.json")
	stdout, _, exitCode := enrich(t, dir, "ingest", "-f", fp)
	if exitCode != 0 {
		t.Fatalf("expected exit 0, got %d: %s", exitCode, stdout)
	}
	if !strings.Contains(stdout, "2 vulnerabilities") {
		t.Fatalf("expected '2 vulnerabilities' in output, got: %s", stdout)
	}
}

func TestE2E_IngestStdin(t *testing.T) {
	dir := t.TempDir()
	data := fixtureBytes(t, "log4shell.json")
	stdout, _, exitCode := enrichStdin(t, dir, data, "ingest")
	if exitCode != 0 {
		t.Fatalf("expected exit 0, got %d: %s", exitCode, stdout)
	}
	if !strings.Contains(stdout, "1 vulnerabilities") {
		t.Fatalf("expected '1 vulnerabilities' in output, got: %s", stdout)
	}
}

func TestE2E_IngestMalformed(t *testing.T) {
	dir := t.TempDir()
	fp := fixturePath(t, "malformed.json")
	_, _, exitCode := enrich(t, dir, "ingest", "-f", fp)
	if exitCode == 0 {
		t.Fatal("expected non-zero exit code for malformed JSON")
	}
}

func TestE2E_StatusBeforeRun(t *testing.T) {
	dir := t.TempDir()
	fp := fixturePath(t, "log4shell.json")

	_, _, exitCode := enrich(t, dir, "ingest", "-f", fp)
	if exitCode != 0 {
		t.Fatalf("ingest failed: exit %d", exitCode)
	}

	stdout, _, exitCode := enrich(t, dir, "status")
	if exitCode != 0 {
		t.Fatalf("status failed: exit %d", exitCode)
	}
	if !strings.Contains(stdout, "Vulnerabilities: 1") {
		t.Fatalf("expected 'Vulnerabilities: 1' in status, got: %s", stdout)
	}
	if !strings.Contains(stdout, "Controls: 0") {
		t.Fatalf("expected 'Controls: 0' in status (no run yet), got: %s", stdout)
	}
}

func TestE2E_RunAllProviders(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow test: run --all loads 45 GRC providers (~30s)")
	}
	dir := t.TempDir()
	fp := fixturePath(t, "log4shell.json")

	_, _, exitCode := enrich(t, dir, "ingest", "-f", fp)
	if exitCode != 0 {
		t.Fatalf("ingest failed: exit %d", exitCode)
	}

	stdout, _, exitCode := enrich(t, dir, "run", "--all", "--max-parallel", "1")
	if exitCode != 0 {
		t.Fatalf("run --all failed: exit %d, stderr: %s", exitCode, stdout)
	}
	if !strings.Contains(stdout, "Enrichment complete") {
		t.Fatalf("expected 'Enrichment complete' in output, got: %s", stdout)
	}
}

func TestE2E_ExportAfterEnrichment(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow test: requires run --all (~30s)")
	}
	dir := t.TempDir()
	fp := fixturePath(t, "log4shell.json")

	_, _, exitCode := enrich(t, dir, "ingest", "-f", fp)
	if exitCode != 0 {
		t.Fatalf("ingest failed: exit %d", exitCode)
	}

	_, _, exitCode = enrich(t, dir, "run", "--all", "--max-parallel", "1")
	if exitCode != 0 {
		t.Fatalf("run --all failed: exit %d", exitCode)
	}

	outFile := filepath.Join(dir, "bom.json")
	stdout, _, exitCode := enrich(t, dir, "export", "-o", outFile)
	if exitCode != 0 {
		t.Fatalf("export failed: exit %d, stdout=%s", exitCode, stdout)
	}

	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("read export file: %v", err)
	}

	var bom map[string]interface{}
	if err := json.Unmarshal(data, &bom); err != nil {
		t.Fatalf("export is not valid JSON: %v", err)
	}

	if bf, ok := bom["bomFormat"].(string); !ok || bf != "CycloneDX" {
		t.Fatalf("expected bomFormat=CycloneDX, got: %v", bom["bomFormat"])
	}
}

func TestE2E_ExportToStdout(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow test: requires run --all (~30s)")
	}
	dir := t.TempDir()
	fp := fixturePath(t, "log4shell.json")

	_, _, exitCode := enrich(t, dir, "ingest", "-f", fp)
	if exitCode != 0 {
		t.Fatalf("ingest failed: exit %d", exitCode)
	}

	_, _, exitCode = enrich(t, dir, "run", "--all", "--max-parallel", "1")
	if exitCode != 0 {
		t.Fatalf("run --all failed: exit %d", exitCode)
	}

	stdout, _, exitCode := enrich(t, dir, "export")
	if exitCode != 0 {
		t.Fatalf("export failed: exit %d", exitCode)
	}
	if !strings.Contains(stdout, "CycloneDX") {
		t.Fatalf("expected 'CycloneDX' in export stdout, got: %s", stdout)
	}
}

func TestE2E_ExportEmptyDB(t *testing.T) {
	dir := t.TempDir()

	stdout, _, exitCode := enrich(t, dir, "export")
	if exitCode != 0 {
		t.Fatalf("export failed: exit %d, stdout=%s", exitCode, stdout)
	}

	var bom map[string]interface{}
	if err := json.Unmarshal([]byte(stdout), &bom); err != nil {
		t.Fatalf("export is not valid JSON: %v", err)
	}

	if bf, ok := bom["bomFormat"].(string); !ok || bf != "CycloneDX" {
		t.Fatalf("expected bomFormat=CycloneDX, got: %v", bom["bomFormat"])
	}

	if _, exists := bom["vulnerabilities"]; exists {
		vulns := bom["vulnerabilities"]
		if arr, ok := vulns.([]interface{}); ok && len(arr) != 0 {
			t.Fatalf("expected 0 vulnerabilities in empty export, got: %d", len(arr))
		}
	}
}

func TestE2E_RunSpecificProvider(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow test: requires provider run")
	}
	dir := t.TempDir()
	fp := fixturePath(t, "log4shell.json")

	_, _, exitCode := enrich(t, dir, "ingest", "-f", fp)
	if exitCode != 0 {
		t.Fatalf("ingest failed: exit %d", exitCode)
	}

	stdout, _, exitCode := enrich(t, dir, "run", "--provider", "hipaa", "--max-parallel", "1")
	if exitCode != 0 {
		t.Fatalf("run --provider hipaa failed: exit %d, stdout=%s", exitCode, stdout)
	}
	if !strings.Contains(stdout, "Enrichment complete") {
		t.Fatalf("expected 'Enrichment complete' in output, got: %s", stdout)
	}
}
