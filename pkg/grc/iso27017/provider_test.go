package iso27017

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/vincents-ai/enrichment-engine/pkg/storage"
)

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

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestProvider_Run(t *testing.T) {
	backend := &mockBackend{}
	p := New(backend, testLogger())
	count, err := p.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() returned error: %v", err)
	}
	if count < 10 {
		t.Errorf("expected at least 10 controls, got %d", count)
	}
}

func TestProvider_FrameworkID(t *testing.T) {
	controls := staticControls()
	for _, ctrl := range controls {
		if ctrl.Framework != FrameworkID {
			t.Errorf("control %s has wrong Framework %q", ctrl.ControlID, ctrl.Framework)
		}
	}
}

func TestStaticControls_NoEmptyFields(t *testing.T) {
	controls := staticControls()
	for _, ctrl := range controls {
		if ctrl.ControlID == "" {
			t.Errorf("control has empty ControlID")
		}
		if ctrl.Title == "" {
			t.Errorf("control %s has empty Title", ctrl.ControlID)
		}
		for _, cwe := range ctrl.RelatedCWEs {
			if !strings.HasPrefix(cwe, "CWE-") {
				t.Errorf("control %s has invalid CWE: %s", ctrl.ControlID, cwe)
			}
		}
	}
}
