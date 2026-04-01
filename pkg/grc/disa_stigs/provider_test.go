package disa_stigs

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

	if len(controls) != 35 {
		t.Errorf("expected 35 embedded controls, got %d", len(controls))
	}

	families := make(map[string]int)
	for _, ctrl := range controls {
		families[ctrl.Family]++
	}

	if families["Windows Server"] != 12 {
		t.Errorf("expected 12 Windows Server, got %d", families["Windows Server"])
	}
	if families["Red Hat Enterprise Linux"] != 13 {
		t.Errorf("expected 13 Red Hat Enterprise Linux, got %d", families["Red Hat Enterprise Linux"])
	}
	if families["Application"] != 10 {
		t.Errorf("expected 10 Application, got %d", families["Application"])
	}

	if controls[0].ControlID != "WS-2022.1.1" {
		t.Errorf("expected first control WS-2022.1.1, got %s", controls[0].ControlID)
	}
	if controls[0].Framework != "DISA_STIGS_V2R1" {
		t.Errorf("expected Framework DISA_STIGS_V2R1, got %s", controls[0].Framework)
	}
}

func TestProviderWriteEmbeddedControls(t *testing.T) {
	backend := &mockBackend{}
	p := &Provider{store: backend, logger: slog.Default()}

	count, err := p.writeEmbeddedControls(context.Background())
	if err != nil {
		t.Fatalf("writeEmbeddedControls failed: %v", err)
	}

	if count != 35 {
		t.Errorf("expected 35 controls written, got %d", count)
	}
	if len(backend.controls) != 35 {
		t.Errorf("expected 35 controls in backend, got %d", len(backend.controls))
	}
}

func TestProviderName(t *testing.T) {
	p := &Provider{}
	if got := p.Name(); got != "disa_stigs" {
		t.Errorf("Name() = %q, want %q", got, "disa_stigs")
	}
}
