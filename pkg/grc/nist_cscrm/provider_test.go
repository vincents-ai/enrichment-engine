package nist_cscrm

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/shift/enrichment-engine/pkg/storage"
)

// mockBackend is a minimal storage backend for testing.
type mockBackend struct {
	controls map[string]interface{}
}

func (m *mockBackend) WriteVulnerability(_ context.Context, _ string, _ interface{}) error {
	return nil
}
func (m *mockBackend) WriteControl(_ context.Context, id string, control interface{}) error {
	if m.controls == nil {
		m.controls = make(map[string]interface{})
	}
	m.controls[id] = control
	return nil
}
func (m *mockBackend) WriteMapping(_ context.Context, _, _, _, _ string, _ float64, _ string) error {
	return nil
}
func (m *mockBackend) ReadVulnerability(_ context.Context, _ string) ([]byte, error) { return nil, nil }
func (m *mockBackend) ReadControl(_ context.Context, _ string) ([]byte, error)       { return nil, nil }
func (m *mockBackend) ListMappings(_ context.Context, _ string) ([]storage.MappingRow, error) {
	return nil, nil
}
func (m *mockBackend) Close(_ context.Context) error { return nil }
func (m *mockBackend) ListAllVulnerabilities(_ context.Context) ([]storage.VulnerabilityRow, error) {
	return nil, nil
}
func (m *mockBackend) ListAllControls(_ context.Context) ([]storage.ControlRow, error) {
	return nil, nil
}
func (m *mockBackend) ListControlsByCWE(_ context.Context, _ string) ([]storage.ControlRow, error) {
	return nil, nil
}
func (m *mockBackend) ListControlsByCPE(_ context.Context, _ string) ([]storage.ControlRow, error) {
	return nil, nil
}
func (m *mockBackend) ListControlsByFramework(_ context.Context, _ string) ([]storage.ControlRow, error) {
	return nil, nil
}
func (m *mockBackend) ListControlsByTag(_ context.Context, _ string) ([]storage.ControlRow, error) {
	return nil, nil
}

type failWriteBackend struct{}

func (f *failWriteBackend) WriteVulnerability(_ context.Context, _ string, _ interface{}) error {
	return nil
}
func (f *failWriteBackend) WriteControl(_ context.Context, _ string, _ interface{}) error {
	return os.ErrPermission
}
func (f *failWriteBackend) WriteMapping(_ context.Context, _, _, _, _ string, _ float64, _ string) error {
	return nil
}
func (f *failWriteBackend) ReadVulnerability(_ context.Context, _ string) ([]byte, error) {
	return nil, nil
}
func (f *failWriteBackend) ReadControl(_ context.Context, _ string) ([]byte, error) {
	return nil, nil
}
func (f *failWriteBackend) ListMappings(_ context.Context, _ string) ([]storage.MappingRow, error) {
	return nil, nil
}
func (f *failWriteBackend) ListAllVulnerabilities(_ context.Context) ([]storage.VulnerabilityRow, error) {
	return nil, nil
}
func (f *failWriteBackend) ListAllControls(_ context.Context) ([]storage.ControlRow, error) {
	return nil, nil
}
func (f *failWriteBackend) ListControlsByCWE(_ context.Context, _ string) ([]storage.ControlRow, error) {
	return nil, nil
}
func (f *failWriteBackend) ListControlsByCPE(_ context.Context, _ string) ([]storage.ControlRow, error) {
	return nil, nil
}
func (f *failWriteBackend) ListControlsByFramework(_ context.Context, _ string) ([]storage.ControlRow, error) {
	return nil, nil
}
func (f *failWriteBackend) ListControlsByTag(_ context.Context, _ string) ([]storage.ControlRow, error) {
	return nil, nil
}
func (f *failWriteBackend) Close(_ context.Context) error { return nil }

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// TestProvider_Run asserts count >= 20.
func TestProvider_Run(t *testing.T) {
	backend := &mockBackend{}
	p := New(backend, testLogger())
	count, err := p.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() returned error: %v", err)
	}
	if count < 20 {
		t.Errorf("expected at least 20 controls, got %d", count)
	}
	if len(backend.controls) < 20 {
		t.Errorf("expected at least 20 controls in backend, got %d", len(backend.controls))
	}
}

// TestProvider_SRFamily asserts sr-3 and sr-11 controls are present.
func TestProvider_SRFamily(t *testing.T) {
	controls := staticControls()
	found := make(map[string]bool)
	for _, ctrl := range controls {
		id := strings.ToLower(ctrl.ControlID)
		found[id] = true
	}
	for _, want := range []string{"sr-3", "sr-11"} {
		if !found[want] {
			t.Errorf("expected control %q to be present", want)
		}
	}
}

// TestProvider_CWEMappings asserts sr-11 has CWE-494 or CWE-829.
func TestProvider_CWEMappings(t *testing.T) {
	controls := staticControls()
	for _, ctrl := range controls {
		if strings.ToLower(ctrl.ControlID) == "sr-11" {
			for _, cwe := range ctrl.RelatedCWEs {
				if cwe == "CWE-494" || cwe == "CWE-829" {
					return // pass
				}
			}
			t.Errorf("SR-11 expected CWE-494 or CWE-829, got %v", ctrl.RelatedCWEs)
			return
		}
	}
	t.Error("SR-11 control not found")
}

// TestProviderName verifies the name.
func TestProviderName(t *testing.T) {
	p := New(nil, nil)
	if got := p.Name(); got != "nist_cscrm" {
		t.Errorf("Name() = %q, want %q", got, "nist_cscrm")
	}
}

// TestProviderWriteError checks that write errors are silently skipped.
func TestProviderWriteError(t *testing.T) {
	p := New(&failWriteBackend{}, testLogger())
	count, err := p.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() returned error: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 controls written on error, got %d", count)
	}
}

// TestStaticControls_AllValid checks all controls have required fields.
func TestStaticControls_AllValid(t *testing.T) {
	controls := staticControls()
	for _, ctrl := range controls {
		if ctrl.ControlID == "" {
			t.Errorf("control has empty ControlID: %+v", ctrl)
		}
		if ctrl.Framework != FrameworkID {
			t.Errorf("control %s has wrong Framework %q", ctrl.ControlID, ctrl.Framework)
		}
		if ctrl.Title == "" {
			t.Errorf("control %s has empty Title", ctrl.ControlID)
		}
		if ctrl.Family == "" {
			t.Errorf("control %s has empty Family", ctrl.ControlID)
		}
		if len(ctrl.References) == 0 {
			t.Errorf("control %s has no References", ctrl.ControlID)
		}
		for _, cwe := range ctrl.RelatedCWEs {
			if !strings.HasPrefix(cwe, "CWE-") {
				t.Errorf("control %s has invalid CWE format: %s", ctrl.ControlID, cwe)
			}
		}
	}
}

// TestStaticControls_Tags verifies expected tags are present across the control set.
func TestStaticControls_Tags(t *testing.T) {
	controls := staticControls()
	tagSeen := make(map[string]bool)
	for _, ctrl := range controls {
		for _, tag := range ctrl.Tags {
			tagSeen[tag] = true
		}
	}
	wantTags := []string{"supply-chain", "integrity", "governance", "sdlc"}
	for _, tag := range wantTags {
		if !tagSeen[tag] {
			t.Errorf("expected tag %q to appear in at least one control", tag)
		}
	}
}

// TestStorageKeys verifies that keys are prefixed with FrameworkID.
func TestStorageKeys(t *testing.T) {
	backend := &mockBackend{}
	p := New(backend, testLogger())
	p.Run(context.Background())
	for key := range backend.controls {
		if !strings.HasPrefix(key, FrameworkID+"/") {
			t.Errorf("storage key %q does not start with %q", key, FrameworkID+"/")
		}
	}
}
