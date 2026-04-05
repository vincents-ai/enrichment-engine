package scap_xccdf

import (
	"context"
	"log/slog"
	"os"
	"strings"
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
	logger := slog.Default()
	p := New(backend, logger)
	if p == nil {
		t.Fatal("New() returned nil")
	}
	if p.store != backend {
		t.Error("New() did not set store")
	}
	if p.logger != logger {
		t.Error("New() did not set logger")
	}
}

func TestEmbeddedControls(t *testing.T) {
	controls := embeddedControls()

	if len(controls) != 34 {
		t.Errorf("expected 34 embedded controls, got %d", len(controls))
	}

	families := make(map[string]int)
	for _, ctrl := range controls {
		families[ctrl.Family]++
	}

	if families["System Settings"] != 5 {
		t.Errorf("expected 5 System Settings, got %d", families["System Settings"])
	}
	if families["Access Control"] != 7 {
		t.Errorf("expected 7 Access Control, got %d", families["Access Control"])
	}
	if families["Network"] != 5 {
		t.Errorf("expected 5 Network, got %d", families["Network"])
	}
	if families["Logging"] != 5 {
		t.Errorf("expected 5 Logging, got %d", families["Logging"])
	}
	if families["Services"] != 4 {
		t.Errorf("expected 4 Services, got %d", families["Services"])
	}
	if families["Software"] != 4 {
		t.Errorf("expected 4 Software, got %d", families["Software"])
	}
	if families["Windows System"] != 4 {
		t.Errorf("expected 4 Windows System, got %d", families["Windows System"])
	}

	if controls[0].ControlID != "SCAP-RHEL-8-1.1" {
		t.Errorf("expected first control SCAP-RHEL-8-1.1, got %s", controls[0].ControlID)
	}
	if controls[0].Framework != "SCAP_XCCDF_1_3" {
		t.Errorf("expected Framework SCAP_XCCDF_1_3, got %s", controls[0].Framework)
	}
}

func TestProviderWriteEmbeddedControls(t *testing.T) {
	backend := &mockBackend{}
	p := &Provider{store: backend, logger: slog.Default()}

	count, err := p.writeEmbeddedControls(context.Background())
	if err != nil {
		t.Fatalf("writeEmbeddedControls failed: %v", err)
	}

	if count != 34 {
		t.Errorf("expected 34 controls written, got %d", count)
	}
	if len(backend.controls) != 34 {
		t.Errorf("expected 34 controls in backend, got %d", len(backend.controls))
	}
}

func TestProviderWriteEmbeddedControlsError(t *testing.T) {
	backend := &mockBackend{err: os.ErrPermission}
	p := &Provider{store: backend, logger: slog.Default()}

	count, err := p.writeEmbeddedControls(context.Background())
	if err != nil {
		t.Fatalf("writeEmbeddedControls should not return error on individual write failures: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 controls written when all writes fail, got %d", count)
	}
}

func TestProviderName(t *testing.T) {
	p := &Provider{}
	if got := p.Name(); got != "scap_xccdf" {
		t.Errorf("Name() = %q, want %q", got, "scap_xccdf")
	}
}

func TestRelatedCWEsPopulated(t *testing.T) {
	controls := embeddedControls()
	populatedCount := 0
	for _, ctrl := range controls {
		if len(ctrl.RelatedCWEs) > 0 {
			populatedCount++
			for _, cwe := range ctrl.RelatedCWEs {
				if !strings.HasPrefix(cwe, "CWE-") {
					t.Errorf("control %s has invalid CWE format: %s", ctrl.ControlID, cwe)
				}
			}
		}
	}
	if populatedCount == 0 {
		t.Errorf("expected some SCAP XCCDF controls to have RelatedCWEs populated, got 0")
	}
}

func TestScapCWEs(t *testing.T) {
	cwes := scapCWEs("SCAP-RHEL-8-1.2")
	if len(cwes) != 2 {
		t.Errorf("expected 2 CWEs for SCAP-RHEL-8-1.2, got %d", len(cwes))
	}
	cwes = scapCWEs("nonexistent")
	if cwes != nil {
		t.Errorf("expected nil for unknown control, got %v", cwes)
	}
}

func TestRun(t *testing.T) {
	backend := &mockBackend{}
	p := New(backend, slog.Default())

	count, err := p.Run(context.Background())
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if count != 34 {
		t.Errorf("expected 34 controls, got %d", count)
	}
}

func TestRunWithWriteError(t *testing.T) {
	backend := &mockBackend{err: os.ErrPermission}
	p := New(backend, slog.Default())

	count, err := p.Run(context.Background())
	if err != nil {
		t.Fatalf("Run should not return error on individual write failures: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 controls written when all writes fail, got %d", count)
	}
}
