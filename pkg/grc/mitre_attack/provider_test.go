package mitre_attack

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/shift/enrichment-engine/pkg/grc"
	"github.com/shift/enrichment-engine/pkg/storage"
)

type mockBackend struct {
	controls map[string]interface{}
	failAll  bool
	failSet  map[string]bool
}

func (m *mockBackend) WriteVulnerability(ctx context.Context, id string, record interface{}) error {
	return nil
}
func (m *mockBackend) WriteControl(ctx context.Context, id string, control interface{}) error {
	if m.failAll {
		return errors.New("write error")
	}
	if m.failSet != nil && m.failSet[id] {
		return errors.New("write error")
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
func (m *mockBackend) Close(ctx context.Context) error { return nil }

func TestNew(t *testing.T) {
	mock := &mockBackend{}
	logger := slog.Default()
	p := New(mock, logger)
	if p == nil {
		t.Fatal("New() returned nil")
	}
	if p.store != mock {
		t.Error("New() did not set store")
	}
	if p.logger != logger {
		t.Error("New() did not set logger")
	}
}

func TestProviderName(t *testing.T) {
	p := New(&mockBackend{}, nil)
	if p.Name() != "mitre_attack" {
		t.Errorf("expected name 'mitre_attack', got %q", p.Name())
	}
}

func TestFrameworkID(t *testing.T) {
	if FrameworkID != "MITRE_ATTACK_V14" {
		t.Errorf("expected FrameworkID 'MITRE_ATTACK_V14', got %q", FrameworkID)
	}
}

func TestCatalogURL(t *testing.T) {
	if CatalogURL != "" {
		t.Errorf("expected empty CatalogURL, got %q", CatalogURL)
	}
}

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

func TestEmbeddedControlsFields(t *testing.T) {
	controls := embeddedControls()
	for _, ctrl := range controls {
		if ctrl.ControlID == "" {
			t.Error("found control with empty ControlID")
		}
		if ctrl.Title == "" {
			t.Errorf("control %s: empty Title", ctrl.ControlID)
		}
		if ctrl.Description == "" {
			t.Errorf("control %s: empty Description", ctrl.ControlID)
		}
		if ctrl.Family == "" {
			t.Errorf("control %s: empty Family", ctrl.ControlID)
		}
		if ctrl.Level != "standard" {
			t.Errorf("control %s: expected level 'standard', got %q", ctrl.ControlID, ctrl.Level)
		}
		if len(ctrl.References) == 0 {
			t.Errorf("control %s: empty References", ctrl.ControlID)
		}
		if ctrl.References[0].Source != "MITRE ATT&CK v14 Enterprise" {
			t.Errorf("control %s: wrong reference source %q", ctrl.ControlID, ctrl.References[0].Source)
		}
	}
}

func TestEmbeddedControlsNoDuplicates(t *testing.T) {
	controls := embeddedControls()
	ids := map[string]bool{}
	for _, ctrl := range controls {
		if ids[ctrl.ControlID] {
			t.Errorf("duplicate control ID: %s", ctrl.ControlID)
		}
		ids[ctrl.ControlID] = true
	}
}

func TestRunViaProviderMethod(t *testing.T) {
	backend := &mockBackend{}
	p := New(backend, slog.Default())
	ctx := context.Background()
	count, err := p.Run(ctx)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	if count != 52 {
		t.Errorf("expected 52 controls, got %d", count)
	}
}

func TestRun(t *testing.T) {
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

func TestRunWithWriteErrorAll(t *testing.T) {
	mock := &mockBackend{failAll: true}
	p := &Provider{store: mock, logger: slog.Default()}
	ctx := context.Background()
	count, err := p.writeEmbeddedControls(ctx)
	if err != nil {
		t.Fatalf("writeEmbeddedControls should not return error even on write failures: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 controls written on all errors, got %d", count)
	}
}

func TestRunPartialWriteError(t *testing.T) {
	controls := embeddedControls()
	failSet := make(map[string]bool)
	failCount := len(controls) / 2
	for i := 0; i < failCount; i++ {
		id := FrameworkID + "/" + controls[i].ControlID
		failSet[id] = true
	}
	mock := &mockBackend{failSet: failSet}
	p := &Provider{store: mock, logger: slog.Default()}
	ctx := context.Background()
	count, err := p.writeEmbeddedControls(ctx)
	if err != nil {
		t.Fatalf("writeEmbeddedControls error: %v", err)
	}
	expected := len(controls) - failCount
	if count != expected {
		t.Errorf("expected %d controls written (partial failure), got %d", expected, count)
	}
}

func TestControlValuesStored(t *testing.T) {
	mock := &mockBackend{}
	p := &Provider{store: mock, logger: slog.Default()}
	ctx := context.Background()
	count, err := p.writeEmbeddedControls(ctx)
	if err != nil {
		t.Fatalf("writeEmbeddedControls error: %v", err)
	}
	if count == 0 {
		t.Fatal("no controls written")
	}
	for id, stored := range mock.controls {
		ctrl, ok := stored.(grc.Control)
		if !ok {
			t.Errorf("control %q: not a grc.Control", id)
			continue
		}
		if ctrl.Framework != FrameworkID {
			t.Errorf("control %q: wrong framework %q", id, ctrl.Framework)
		}
		if ctrl.ControlID == "" {
			t.Errorf("control %q: empty ControlID after storage", id)
		}
	}
}

func TestControlIDsHavePrefix(t *testing.T) {
	controls := embeddedControls()
	for _, ctrl := range controls {
		if len(ctrl.ControlID) < 4 {
			t.Errorf("control ID %q too short", ctrl.ControlID)
		}
	}
}
