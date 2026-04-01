package cobit

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

	if len(controls) != 43 {
		t.Errorf("expected 43 embedded controls, got %d", len(controls))
	}

	families := make(map[string]int)
	for _, ctrl := range controls {
		families[ctrl.Family]++
	}

	if families["Governance"] != 5 {
		t.Errorf("expected 5 Governance, got %d", families["Governance"])
	}
	if families["APO - Align, Plan and Organize"] != 14 {
		t.Errorf("expected 14 APO, got %d", families["APO - Align, Plan and Organize"])
	}
	if families["BAI - Build, Acquire and Implement"] != 11 {
		t.Errorf("expected 11 BAI, got %d", families["BAI - Build, Acquire and Implement"])
	}
	if families["DSS - Deliver, Service and Support"] != 7 {
		t.Errorf("expected 7 DSS, got %d", families["DSS - Deliver, Service and Support"])
	}
	if families["MEA - Monitor, Evaluate and Assess"] != 6 {
		t.Errorf("expected 6 MEA, got %d", families["MEA - Monitor, Evaluate and Assess"])
	}

	if controls[0].ControlID != "EDM01" {
		t.Errorf("expected first control EDM01, got %s", controls[0].ControlID)
	}
	if controls[0].Framework != "COBIT_2019" {
		t.Errorf("expected Framework COBIT_2019, got %s", controls[0].Framework)
	}
}

func TestProviderWriteEmbeddedControls(t *testing.T) {
	backend := &mockBackend{}
	p := &Provider{store: backend, logger: slog.Default()}

	count, err := p.writeEmbeddedControls(context.Background())
	if err != nil {
		t.Fatalf("writeEmbeddedControls failed: %v", err)
	}

	if count != 43 {
		t.Errorf("expected 43 controls written, got %d", count)
	}
	if len(backend.controls) != 43 {
		t.Errorf("expected 43 controls in backend, got %d", len(backend.controls))
	}
}

func TestProviderName(t *testing.T) {
	p := &Provider{}
	if got := p.Name(); got != "cobit" {
		t.Errorf("Name() = %q, want %q", got, "cobit")
	}
}
