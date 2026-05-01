package openssf_scorecard

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/vincents-ai/enrichment-engine/pkg/storage"
)

// mockBackend is a minimal in-memory storage.Backend for testing.
type mockBackend struct {
	controls map[string]interface{}
	err      error
}

func (m *mockBackend) WriteVulnerability(_ context.Context, _ string, _ interface{}) error {
	return nil
}
func (m *mockBackend) WriteControl(_ context.Context, id string, control interface{}) error {
	if m.err != nil {
		return m.err
	}
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

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// TestProvider_Run asserts that Run writes exactly 18 controls.
func TestProvider_Run(t *testing.T) {
	backend := &mockBackend{}
	p := New(backend, testLogger())

	count, err := p.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() returned unexpected error: %v", err)
	}
	if count != 18 {
		t.Errorf("Run() count = %d, want 18", count)
	}
	if len(backend.controls) != 18 {
		t.Errorf("backend has %d controls, want 18", len(backend.controls))
	}
}

// TestProvider_AllHaveTags asserts that every control has at least one tag.
func TestProvider_AllHaveTags(t *testing.T) {
	controls := staticControls()
	for _, ctrl := range controls {
		if len(ctrl.Tags) == 0 {
			t.Errorf("control %s (%s) has no tags", ctrl.ControlID, ctrl.Title)
		}
	}
}

// TestProvider_SignedReleasesHasCWE asserts that SC-SIGNED contains CWE-494.
func TestProvider_SignedReleasesHasCWE(t *testing.T) {
	controls := staticControls()
	for _, ctrl := range controls {
		if ctrl.ControlID == "SC-SIGNED" {
			for _, cwe := range ctrl.RelatedCWEs {
				if cwe == "CWE-494" {
					return
				}
			}
			t.Errorf("SC-SIGNED RelatedCWEs = %v, want to contain CWE-494", ctrl.RelatedCWEs)
			return
		}
	}
	t.Error("SC-SIGNED control not found")
}

// TestProvider_Name asserts the provider name.
func TestProvider_Name(t *testing.T) {
	p := &Provider{}
	if got := p.Name(); got != "openssf_scorecard" {
		t.Errorf("Name() = %q, want %q", got, "openssf_scorecard")
	}
}

// TestProvider_FrameworkID asserts all controls use the correct framework ID.
func TestProvider_FrameworkID(t *testing.T) {
	controls := staticControls()
	for _, ctrl := range controls {
		if ctrl.Framework != FrameworkID {
			t.Errorf("control %s Framework = %q, want %q", ctrl.ControlID, ctrl.Framework, FrameworkID)
		}
	}
}

// TestProvider_AllHaveReferences asserts that every control has at least one reference.
func TestProvider_AllHaveReferences(t *testing.T) {
	controls := staticControls()
	for _, ctrl := range controls {
		if len(ctrl.References) == 0 {
			t.Errorf("control %s has no references", ctrl.ControlID)
		}
		for _, ref := range ctrl.References {
			if ref.URL == "" {
				t.Errorf("control %s reference has empty URL", ctrl.ControlID)
			}
		}
	}
}

// TestProvider_RunWriteError asserts that write errors are tolerated and reflected in count.
func TestProvider_RunWriteError(t *testing.T) {
	backend := &mockBackend{err: os.ErrPermission}
	p := New(backend, testLogger())

	count, err := p.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() should not return error on individual write failures: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 controls written when all writes fail, got %d", count)
	}
}
