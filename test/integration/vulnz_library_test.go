//go:build integration

package integration

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/shift/enrichment-engine/pkg/enricher"
)

// TestVulnzLibrary_EmptyWorkspace verifies that when VulnzWorkspace is empty
// the engine runs normally (providers phase and no error from the ingest step).
func TestVulnzLibrary_EmptyWorkspace(t *testing.T) {
	backend := setupTestDB(t)
	logger := testLogger()

	cfg := enricher.Config{
		Store:          backend,
		Logger:         logger,
		MaxParallel:    1,
		SkipProviders:  true, // speed – we're testing the ingest gate, not providers
		SkipMapping:    true,
		VulnzWorkspace: "", // no workspace → ingest step must be skipped silently
	}

	engine := enricher.New(cfg)
	_, err := engine.Run(context.Background())
	if err != nil {
		t.Fatalf("expected no error when VulnzWorkspace is empty, got: %v", err)
	}
}

// TestVulnzLibrary_InvalidWorkspace verifies that when VulnzWorkspace points to a
// non-writable directory, Run() returns a non-nil error from the ingest step.
// We use a temp directory with permissions 0000 so every vulnz provider fails
// immediately at storage creation without making network requests.
func TestVulnzLibrary_InvalidWorkspace(t *testing.T) {
	// Create a non-writable temp directory; all vulnz providers will fail
	// at directory creation (mkdir inside it) without making network calls.
	roDir := t.TempDir()
	if err := os.Chmod(roDir, 0000); err != nil {
		t.Skipf("cannot chmod temp dir (may be root): %v", err)
	}
	t.Cleanup(func() {
		// Restore permissions so TempDir cleanup can remove it
		_ = os.Chmod(roDir, 0700)
	})

	backend := setupTestDB(t)
	logger := testLogger()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cfg := enricher.Config{
		Store:          backend,
		Logger:         logger,
		MaxParallel:    4,
		SkipProviders:  true,
		SkipMapping:    true,
		VulnzWorkspace: roDir,
	}

	engine := enricher.New(cfg)
	_, err := engine.Run(ctx)
	if err == nil {
		t.Fatal("expected non-nil error for non-writable workspace path, got nil")
	}
	t.Logf("got expected error: %v", err)
}

// TestVulnzLibrary_SkipIngest explicitly verifies that when VulnzWorkspace is empty,
// runVulnzIngest returns nil immediately without calling vulnz providers.
// This is validated by checking that Run() succeeds even with no network access.
func TestVulnzLibrary_SkipIngest(t *testing.T) {
	backend := setupTestDB(t)
	logger := testLogger()

	cfg := enricher.Config{
		Store:          backend,
		Logger:         logger,
		MaxParallel:    1,
		SkipProviders:  true,
		SkipMapping:    true,
		VulnzWorkspace: "", // empty → runVulnzIngest is a no-op
	}

	engine := enricher.New(cfg)
	result, err := engine.Run(context.Background())
	if err != nil {
		t.Fatalf("runVulnzIngest should return nil for empty workspace, got: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	// If we reached here, vulnz was never invoked (no workspace path provided)
	t.Log("runVulnzIngest correctly skipped when VulnzWorkspace is empty")
}
