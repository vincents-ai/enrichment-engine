package cis_benchmarks

import (
	"context"
	"log/slog"
	"testing"

	"github.com/shift/enrichment-engine/pkg/storage"
)

type mockBackend struct {
	controls map[string]interface{}
}

func (m *mockBackend) WriteVulnerability(ctx context.Context, id string, record interface{}) error {
	return nil
}
func (m *mockBackend) WriteControl(ctx context.Context, id string, control interface{}) error {
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

func TestEmbeddedControls(t *testing.T) {
	controls := embeddedControls()

	if len(controls) != 39 {
		t.Errorf("expected 39 embedded controls, got %d", len(controls))
	}

	families := make(map[string]int)
	for _, ctrl := range controls {
		families[ctrl.Family]++
	}

	if families["Operating System"] != 15 {
		t.Errorf("expected 15 Operating System, got %d", families["Operating System"])
	}
	if families["Container"] != 7 {
		t.Errorf("expected 7 Container, got %d", families["Container"])
	}
	if families["Kubernetes"] != 10 {
		t.Errorf("expected 10 Kubernetes, got %d", families["Kubernetes"])
	}
	if families["Database"] != 7 {
		t.Errorf("expected 7 Database, got %d", families["Database"])
	}

	if controls[0].ControlID != "OS-1.1" {
		t.Errorf("expected first control OS-1.1, got %s", controls[0].ControlID)
	}
	if controls[0].Framework != "CIS_BENCHMARKS_V2" {
		t.Errorf("expected Framework CIS_BENCHMARKS_V2, got %s", controls[0].Framework)
	}
}

func TestProviderWriteEmbeddedControls(t *testing.T) {
	backend := &mockBackend{}
	p := &Provider{store: backend, logger: slog.Default()}

	count, err := p.writeEmbeddedControls(context.Background())
	if err != nil {
		t.Fatalf("writeEmbeddedControls failed: %v", err)
	}

	if count != 39 {
		t.Errorf("expected 39 controls written, got %d", count)
	}
	if len(backend.controls) != 39 {
		t.Errorf("expected 39 controls in backend, got %d", len(backend.controls))
	}
}

func TestProviderName(t *testing.T) {
	p := &Provider{}
	if got := p.Name(); got != "cis_benchmarks" {
		t.Errorf("Name() = %q, want %q", got, "cis_benchmarks")
	}
}
