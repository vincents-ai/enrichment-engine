package cobit

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/shift/enrichment-engine/pkg/grc"
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

type failWriteBackend struct{}

func (f *failWriteBackend) WriteVulnerability(ctx context.Context, id string, record interface{}) error {
	return nil
}
func (f *failWriteBackend) WriteControl(ctx context.Context, id string, control interface{}) error {
	return os.ErrPermission
}
func (f *failWriteBackend) WriteMapping(ctx context.Context, vulnID, controlID, framework, mappingType string, confidence float64, evidence string) error {
	return nil
}
func (f *failWriteBackend) ReadVulnerability(ctx context.Context, id string) ([]byte, error) {
	return nil, nil
}
func (f *failWriteBackend) ReadControl(ctx context.Context, id string) ([]byte, error) {
	return nil, nil
}
func (f *failWriteBackend) ListMappings(ctx context.Context, vulnID string) ([]storage.MappingRow, error) {
	return nil, nil
}
func (f *failWriteBackend) Close(ctx context.Context) error { return nil }
func (f *failWriteBackend) ListAllVulnerabilities(ctx context.Context) ([]storage.VulnerabilityRow, error) {
	return nil, nil
}
func (f *failWriteBackend) ListAllControls(ctx context.Context) ([]storage.ControlRow, error) {
	return nil, nil
}
func (f *failWriteBackend) ListControlsByCWE(ctx context.Context, cwe string) ([]storage.ControlRow, error) {
	return nil, nil
}
func (f *failWriteBackend) ListControlsByCPE(ctx context.Context, cpe string) ([]storage.ControlRow, error) {
	return nil, nil
}
func (f *failWriteBackend) ListControlsByFramework(ctx context.Context, framework string) ([]storage.ControlRow, error) {
	return nil, nil
}

func (f *failWriteBackend) ListControlsByTag(_ context.Context, _ string) ([]storage.ControlRow, error) {
	return nil, nil
}

func TestNew(t *testing.T) {
	p := New(nil, nil)
	if p == nil {
		t.Fatal("New() returned nil")
	}
	if got := p.Name(); got != "cobit" {
		t.Errorf("Name() = %q, want %q", got, "cobit")
	}
}

func TestProviderName(t *testing.T) {
	p := &Provider{}
	if got := p.Name(); got != "cobit" {
		t.Errorf("Name() = %q, want %q", got, "cobit")
	}
}

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

func TestRunWithWriteError(t *testing.T) {
	p := New(&failWriteBackend{}, slog.Default())

	count, err := p.Run(context.Background())
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 controls on write error, got %d", count)
	}
}

func TestRunViaNew(t *testing.T) {
	backend := &mockBackend{}
	p := New(backend, slog.Default())

	count, err := p.Run(context.Background())
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if count != 43 {
		t.Errorf("expected 43 controls, got %d", count)
	}
}

func TestEmbeddedControlsFields(t *testing.T) {
	controls := embeddedControls()
	for _, ctrl := range controls {
		if ctrl.ControlID == "" {
			t.Errorf("control has empty ControlID")
		}
		if ctrl.Title == "" {
			t.Errorf("control %s has empty Title", ctrl.ControlID)
		}
		if ctrl.Description == "" {
			t.Errorf("control %s has empty Description", ctrl.ControlID)
		}
		if ctrl.Family == "" {
			t.Errorf("control %s has empty Family", ctrl.ControlID)
		}
		if ctrl.Level != "governance" {
			t.Errorf("control %s: expected level 'governance', got %s", ctrl.ControlID, ctrl.Level)
		}
		if ctrl.Framework != FrameworkID {
			t.Errorf("control %s: expected Framework %s, got %s", ctrl.ControlID, FrameworkID, ctrl.Framework)
		}
	}
}

func TestEmbeddedControlsReferences(t *testing.T) {
	controls := embeddedControls()
	for _, ctrl := range controls {
		if len(ctrl.References) == 0 {
			t.Errorf("control %s has no references", ctrl.ControlID)
			continue
		}
		if ctrl.References[0].Source != "COBIT 2019" {
			t.Errorf("control %s: expected source 'COBIT 2019', got %s", ctrl.ControlID, ctrl.References[0].Source)
		}
		if ctrl.References[0].Section != ctrl.ControlID {
			t.Errorf("control %s: expected section %s, got %s", ctrl.ControlID, ctrl.ControlID, ctrl.References[0].Section)
		}
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

func TestEmbeddedControlsStoredCorrectly(t *testing.T) {
	backend := &mockBackend{}
	p := &Provider{store: backend, logger: slog.Default()}
	p.writeEmbeddedControls(context.Background())

	for id, ctrl := range backend.controls {
		c, ok := ctrl.(grc.Control)
		if !ok {
			t.Errorf("expected grc.Control, got %T for id %s", ctrl, id)
			continue
		}
		if !strings.HasPrefix(id, FrameworkID+"/") {
			t.Errorf("expected id to start with %s/, got %s", FrameworkID, id)
		}
		if c.Framework != FrameworkID {
			t.Errorf("expected Framework %s, got %s", FrameworkID, c.Framework)
		}
	}
}
