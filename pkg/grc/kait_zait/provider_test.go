package kait_zait

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/shift/enrichment-engine/pkg/storage"
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

func TestKaitZaitControlsLoaded(t *testing.T) {
	kait := kaitControls()
	zait := zaitControls()
	const wantKAIT = 7
	const wantZAIT = 7
	if len(kait) < wantKAIT {
		t.Errorf("kaitControls() returned %d controls, want >= %d", len(kait), wantKAIT)
	}
	if len(zait) < wantZAIT {
		t.Errorf("zaitControls() returned %d controls, want >= %d", len(zait), wantZAIT)
	}
}

func TestKaitZaitFrameworkID(t *testing.T) {
	for _, ctrl := range kaitControls() {
		if ctrl.Framework != FrameworkKAIT {
			t.Errorf("control %s has Framework %q, want %q", ctrl.ControlID, ctrl.Framework, FrameworkKAIT)
		}
	}
	for _, ctrl := range zaitControls() {
		if ctrl.Framework != FrameworkZAIT {
			t.Errorf("control %s has Framework %q, want %q", ctrl.ControlID, ctrl.Framework, FrameworkZAIT)
		}
	}
}

func TestKaitZaitNoEmptyTitles(t *testing.T) {
	for _, ctrl := range kaitControls() {
		if ctrl.Title == "" {
			t.Errorf("control %s has empty Title", ctrl.ControlID)
		}
		if ctrl.ControlID == "" {
			t.Error("found control with empty ControlID")
		}
	}
	for _, ctrl := range zaitControls() {
		if ctrl.Title == "" {
			t.Errorf("control %s has empty Title", ctrl.ControlID)
		}
		if ctrl.ControlID == "" {
			t.Error("found control with empty ControlID")
		}
	}
}

func TestKaitZaitProviderRun(t *testing.T) {
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
