package bait

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/vincents-ai/enrichment-engine/pkg/storage"
)

type mockBackend struct {
	controls map[string]interface{}
	err      error
}

func (m *mockBackend) WriteVulnerability(ctx context.Context, id string, record interface{}) error {
	return nil
}
func (m *mockBackend) WriteControl(ctx context.Context, id string, control interface{}) error {
	if m.err != nil {
		return m.err
	}
	if m.controls == nil {
		m.controls = make(map[string]interface{})
	}
	m.controls[id] = control
	return nil
}
func (m *mockBackend) WriteMapping(ctx context.Context, vulnID, controlID, framework, mappingType string, confidence float64, evidence string) error {
	return nil
}
func (m *mockBackend) ReadVulnerability(ctx context.Context, id string) ([]byte, error) {
	return nil, nil
}
func (m *mockBackend) ReadControl(ctx context.Context, id string) ([]byte, error) { return nil, nil }
func (m *mockBackend) ListMappings(ctx context.Context, vulnID string) ([]storage.MappingRow, error) {
	return nil, nil
}
func (m *mockBackend) Close(ctx context.Context) error { return nil }
func (m *mockBackend) ListAllVulnerabilities(ctx context.Context) ([]storage.VulnerabilityRow, error) {
	return nil, nil
}
func (m *mockBackend) ListAllControls(ctx context.Context) ([]storage.ControlRow, error) {
	return nil, nil
}
func (m *mockBackend) ListControlsByCWE(ctx context.Context, cwe string) ([]storage.ControlRow, error) {
	return nil, nil
}
func (m *mockBackend) ListControlsByCPE(ctx context.Context, cpe string) ([]storage.ControlRow, error) {
	return nil, nil
}
func (m *mockBackend) ListControlsByFramework(ctx context.Context, framework string) ([]storage.ControlRow, error) {
	return nil, nil
}
func (m *mockBackend) ListControlsByTag(_ context.Context, _ string) ([]storage.ControlRow, error) {
	return nil, nil
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestBaitControlsLoaded(t *testing.T) {
	controls := staticControls()
	const want = 14
	if len(controls) < want {
		t.Errorf("staticControls() returned %d controls, want >= %d", len(controls), want)
	}
}

func TestBaitFrameworkID(t *testing.T) {
	controls := staticControls()
	for _, ctrl := range controls {
		if ctrl.Framework != FrameworkID {
			t.Errorf("control %s has Framework %q, want %q", ctrl.ControlID, ctrl.Framework, FrameworkID)
		}
	}
}

func TestBaitNoEmptyTitles(t *testing.T) {
	controls := staticControls()
	for _, ctrl := range controls {
		if ctrl.Title == "" {
			t.Errorf("control %s has empty Title", ctrl.ControlID)
		}
		if ctrl.ControlID == "" {
			t.Error("found control with empty ControlID")
		}
	}
}

func TestBaitProviderRun(t *testing.T) {
	backend := &mockBackend{}
	p := New(backend, testLogger())
	count, err := p.Run(context.Background())
	if err != nil {
		t.Fatalf("Run returned unexpected error: %v", err)
	}
	const want = 14
	if count != want {
		t.Errorf("Run() count = %d, want %d", count, want)
	}
	if len(backend.controls) != want {
		t.Errorf("backend controls count = %d, want %d", len(backend.controls), want)
	}
}
