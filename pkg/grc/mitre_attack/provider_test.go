package mitre_attack

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

	if len(controls) != 52 {
		t.Errorf("expected 52 embedded controls, got %d", len(controls))
	}

	families := make(map[string]int)
	for _, ctrl := range controls {
		families[ctrl.Family]++
	}

	if families["Initial Access"] != 5 {
		t.Errorf("expected 5 Initial Access, got %d", families["Initial Access"])
	}
	if families["Execution"] != 5 {
		t.Errorf("expected 5 Execution, got %d", families["Execution"])
	}
	if families["Persistence"] != 5 {
		t.Errorf("expected 5 Persistence, got %d", families["Persistence"])
	}
	if families["Privilege Escalation"] != 4 {
		t.Errorf("expected 4 Privilege Escalation, got %d", families["Privilege Escalation"])
	}
	if families["Defense Evasion"] != 5 {
		t.Errorf("expected 5 Defense Evasion, got %d", families["Defense Evasion"])
	}
	if families["Credential Access"] != 5 {
		t.Errorf("expected 5 Credential Access, got %d", families["Credential Access"])
	}
	if families["Discovery"] != 5 {
		t.Errorf("expected 5 Discovery, got %d", families["Discovery"])
	}
	if families["Lateral Movement"] != 4 {
		t.Errorf("expected 4 Lateral Movement, got %d", families["Lateral Movement"])
	}
	if families["Collection"] != 3 {
		t.Errorf("expected 3 Collection, got %d", families["Collection"])
	}
	if families["Exfiltration"] != 3 {
		t.Errorf("expected 3 Exfiltration, got %d", families["Exfiltration"])
	}
	if families["Command and Control"] != 4 {
		t.Errorf("expected 4 Command and Control, got %d", families["Command and Control"])
	}
	if families["Impact"] != 4 {
		t.Errorf("expected 4 Impact, got %d", families["Impact"])
	}

	if controls[0].ControlID != "DC-TA0001-T1566" {
		t.Errorf("expected first control DC-TA0001-T1566, got %s", controls[0].ControlID)
	}
	if controls[0].Framework != "MITRE_ATTACK_V14" {
		t.Errorf("expected Framework MITRE_ATTACK_V14, got %s", controls[0].Framework)
	}
}

func TestProviderWriteEmbeddedControls(t *testing.T) {
	backend := &mockBackend{}
	p := &Provider{store: backend, logger: slog.Default()}

	count, err := p.writeEmbeddedControls(context.Background())
	if err != nil {
		t.Fatalf("writeEmbeddedControls failed: %v", err)
	}

	if count != 52 {
		t.Errorf("expected 52 controls written, got %d", count)
	}
	if len(backend.controls) != 52 {
		t.Errorf("expected 52 controls in backend, got %d", len(backend.controls))
	}
}

func TestProviderName(t *testing.T) {
	p := &Provider{}
	if got := p.Name(); got != "mitre_attack" {
		t.Errorf("Name() = %q, want %q", got, "mitre_attack")
	}
}
