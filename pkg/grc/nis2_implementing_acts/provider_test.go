package nis2_implementing_acts

import (
	"context"
	"fmt"
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
func (m *mockBackend) Close(ctx context.Context) error { return nil }

func TestNew(t *testing.T) {
	backend := &mockBackend{}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	p := New(backend, logger)
	if p == nil {
		t.Fatal("New returned nil")
	}
	if p.store != backend {
		t.Error("store not set")
	}
	if p.logger != logger {
		t.Error("logger not set")
	}
}

func TestEmbeddedControls(t *testing.T) {
	controls := embeddedControls()

	if len(controls) != 31 {
		t.Errorf("expected 31 embedded controls, got %d", len(controls))
	}

	families := make(map[string]int)
	for _, ctrl := range controls {
		families[ctrl.Family]++
	}

	if families["Sectoral Baselines (Annex I)"] != 7 {
		t.Errorf("expected 7 Sectoral Baselines (Annex I), got %d", families["Sectoral Baselines (Annex I)"])
	}
	if families["Sectoral Baselines (Annex II)"] != 6 {
		t.Errorf("expected 6 Sectoral Baselines (Annex II), got %d", families["Sectoral Baselines (Annex II)"])
	}
	if families["Technical Measures"] != 8 {
		t.Errorf("expected 8 Technical Measures, got %d", families["Technical Measures"])
	}
	if families["Governance Measures"] != 5 {
		t.Errorf("expected 5 Governance Measures, got %d", families["Governance Measures"])
	}
	if families["Sector-Specific Requirements"] != 5 {
		t.Errorf("expected 5 Sector-Specific Requirements, got %d", families["Sector-Specific Requirements"])
	}

	if controls[0].ControlID != "NIS2IA-SEC-1.1" {
		t.Errorf("expected first control NIS2IA-SEC-1.1, got %s", controls[0].ControlID)
	}
	if controls[0].Framework != FrameworkID {
		t.Errorf("expected Framework %s, got %s", FrameworkID, controls[0].Framework)
	}

	levels := make(map[string]int)
	for _, ctrl := range controls {
		levels[ctrl.Level]++
	}
	if levels["essential"] != 7 {
		t.Errorf("expected 7 essential-level controls, got %d", levels["essential"])
	}
	if levels["important"] != 6 {
		t.Errorf("expected 6 important-level controls, got %d", levels["important"])
	}
}

func TestEmbeddedControlsUniqueIDs(t *testing.T) {
	controls := embeddedControls()
	ids := make(map[string]bool)
	for _, ctrl := range controls {
		if ids[ctrl.ControlID] {
			t.Errorf("duplicate control ID: %s", ctrl.ControlID)
		}
		ids[ctrl.ControlID] = true
	}
}

func TestProviderWriteEmbeddedControls(t *testing.T) {
	backend := &mockBackend{}
	p := &Provider{store: backend, logger: slog.Default()}

	count, err := p.writeEmbeddedControls(context.Background())
	if err != nil {
		t.Fatalf("writeEmbeddedControls failed: %v", err)
	}

	if count != 31 {
		t.Errorf("expected 31 controls written, got %d", count)
	}
	if len(backend.controls) != 31 {
		t.Errorf("expected 31 controls in backend, got %d", len(backend.controls))
	}
}

func TestRun(t *testing.T) {
	backend := &mockBackend{}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	p := New(backend, logger)
	count, err := p.Run(context.Background())
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if count != 31 {
		t.Errorf("expected 31 controls written, got %d", count)
	}
}

func TestRunWriteError(t *testing.T) {
	backend := &mockBackend{err: fmt.Errorf("write failed")}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	p := New(backend, logger)
	count, err := p.Run(context.Background())
	if err != nil {
		t.Fatalf("Run should not return error on write failure, got: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 controls written, got %d", count)
	}
}

func TestProviderName(t *testing.T) {
	p := &Provider{}
	if got := p.Name(); got != "nis2_implementing_acts" {
		t.Errorf("Name() = %q, want %q", got, "nis2_implementing_acts")
	}
}

func TestEmbeddedControlsStoredCorrectly(t *testing.T) {
	backend := &mockBackend{}
	p := New(backend, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	p.Run(context.Background())

	for id, ctrl := range backend.controls {
		c, ok := ctrl.(Control)
		if !ok {
			t.Errorf("expected Control, got %T for id %s", ctrl, id)
			continue
		}
		if c.Framework != FrameworkID {
			t.Errorf("expected Framework %s, got %s", FrameworkID, c.Framework)
		}
	}
}
