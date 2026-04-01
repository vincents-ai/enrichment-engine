package hipaa

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
func (m *mockBackend) ListAllVulnerabilities(ctx context.Context) ([]storage.VulnerabilityRow, error) { return nil, nil }
func (m *mockBackend) ListAllControls(ctx context.Context) ([]storage.ControlRow, error) { return nil, nil }
func (m *mockBackend) ListControlsByCWE(ctx context.Context, cwe string) ([]storage.ControlRow, error) { return nil, nil }
func (m *mockBackend) ListControlsByCPE(ctx context.Context, cpe string) ([]storage.ControlRow, error) { return nil, nil }
func (m *mockBackend) ListControlsByFramework(ctx context.Context, framework string) ([]storage.ControlRow, error) { return nil, nil }
func (m *mockBackend) Close(ctx context.Context) error { return nil }

func TestEmbeddedControls(t *testing.T) {
	controls := embeddedControls()

	if len(controls) != 46 {
		t.Errorf("expected 46 embedded controls, got %d", len(controls))
	}

	families := make(map[string]int)
	for _, ctrl := range controls {
		families[ctrl.Family]++
	}

	if families["Administrative Safeguards"] != 16 {
		t.Errorf("expected 16 Administrative Safeguards, got %d", families["Administrative Safeguards"])
	}
	if families["Physical Safeguards"] != 12 {
		t.Errorf("expected 12 Physical Safeguards, got %d", families["Physical Safeguards"])
	}
	if families["Technical Safeguards"] != 9 {
		t.Errorf("expected 9 Technical Safeguards, got %d", families["Technical Safeguards"])
	}
	if families["Organizational Requirements"] != 5 {
		t.Errorf("expected 5 Organizational Requirements, got %d", families["Organizational Requirements"])
	}
	if families["Policies and Procedures"] != 4 {
		t.Errorf("expected 4 Policies and Procedures, got %d", families["Policies and Procedures"])
	}

	if controls[0].ControlID != "164.308(a)(1)" {
		t.Errorf("expected first control 164.308(a)(1), got %s", controls[0].ControlID)
	}
	if controls[0].Framework != "HIPAA_SECURITY_RULE_2013" {
		t.Errorf("expected Framework HIPAA_SECURITY_RULE_2013, got %s", controls[0].Framework)
	}
}

func TestProviderWriteEmbeddedControls(t *testing.T) {
	backend := &mockBackend{}
	p := &Provider{store: backend, logger: slog.Default()}

	count, err := p.writeEmbeddedControls(context.Background())
	if err != nil {
		t.Fatalf("writeEmbeddedControls failed: %v", err)
	}

	if count != 46 {
		t.Errorf("expected 46 controls written, got %d", count)
	}
	if len(backend.controls) != 46 {
		t.Errorf("expected 46 controls in backend, got %d", len(backend.controls))
	}
}

func TestProviderName(t *testing.T) {
	p := &Provider{}
	if got := p.Name(); got != "hipaa" {
		t.Errorf("Name() = %q, want %q", got, "hipaa")
	}
}
