package integration

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

var (
	enrichBinary string
	binaryOnce   sync.Once
	binaryErr    error
)

func buildEnrichBinary(t *testing.T) string {
	t.Helper()
	binaryOnce.Do(func() {
		tmpDir, err := os.MkdirTemp("", "enrich-cli-test-*")
		if err != nil {
			binaryErr = err
			return
		}
		binPath := tmpDir + "/enrich"
		cmd := exec.Command("go", "build", "-o", binPath, "./cmd/enrich")
		cmd.Dir = repoRoot()
		out, err := cmd.CombinedOutput()
		if err != nil {
			binaryErr = err
			t.Logf("build output:\n%s", string(out))
			return
		}
		enrichBinary = binPath
	})
	if binaryErr != nil {
		t.Fatalf("build enrich binary: %v", binaryErr)
	}
	return enrichBinary
}

func repoRoot() string {
	dir, err := os.Getwd()
	if err != nil {
		return "."
	}
	for {
		if _, err := os.Stat(dir + "/go.mod"); err == nil {
			return dir
		}
		parent := dir[:strings.LastIndex(dir, "/")]
		if parent == dir {
			return "."
		}
		dir = parent
	}
}

func runSubprocess(t *testing.T, args ...string) (string, int) {
	t.Helper()
	bin := buildEnrichBinary(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	out, err := cmd.CombinedOutput()
	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			t.Fatalf("subprocess failed to run: %v", err)
		}
	}
	return string(out), exitCode
}

func TestSubprocess_Version(t *testing.T) {
	out, code := runSubprocess(t, "version")
	if code != 0 {
		t.Fatalf("expected exit 0, got %d\noutput:\n%s", code, out)
	}
	if !strings.Contains(out, "v") {
		t.Fatalf("expected semver or 'dev' in output, got:\n%s", out)
	}
}

func TestSubprocess_Providers(t *testing.T) {
	out, code := runSubprocess(t, "providers")
	if code != 0 {
		t.Fatalf("expected exit 0, got %d\noutput:\n%s", code, out)
	}
	if !strings.Contains(out, "hipaa") {
		t.Fatalf("expected 'hipaa' in providers output, got:\n%s", out)
	}
}

func TestSubprocess_RunEmpty(t *testing.T) {
	tmpDir := t.TempDir()
	out, code := runSubprocess(t, "--workspace", tmpDir, "--log-level", "error", "run")
	if code != 0 {
		t.Fatalf("expected exit 0, got %d\noutput:\n%s", code, out)
	}
}

func TestSubprocess_Status(t *testing.T) {
	tmpDir := t.TempDir()
	out, code := runSubprocess(t, "--workspace", tmpDir, "status")
	if code != 0 {
		t.Fatalf("expected exit 0, got %d\noutput:\n%s", code, out)
	}
	if !strings.Contains(out, tmpDir) {
		t.Fatalf("expected workspace path %q in output, got:\n%s", tmpDir, out)
	}
}

func TestSubprocess_InvalidFlag(t *testing.T) {
	_, code := runSubprocess(t, "--nonexistent-flag")
	if code == 0 {
		t.Fatal("expected non-zero exit for invalid flag")
	}
}
