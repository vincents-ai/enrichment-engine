package fedramp

import (
	"context"
	"log/slog"
	"strings"
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

func TestEmbeddedControls(t *testing.T) {
	controls := embeddedControls()

	if len(controls) != 51 {
		t.Errorf("expected 51 embedded controls, got %d", len(controls))
	}

	families := make(map[string]int)
	for _, ctrl := range controls {
		families[ctrl.Family]++
	}

	if families["Access Control"] != 12 {
		t.Errorf("expected 12 Access Control, got %d", families["Access Control"])
	}
	if families["Audit and Accountability"] != 8 {
		t.Errorf("expected 8 Audit and Accountability, got %d", families["Audit and Accountability"])
	}
	if families["Configuration Management"] != 5 {
		t.Errorf("expected 5 Configuration Management, got %d", families["Configuration Management"])
	}
	if families["Identification and Authentication"] != 5 {
		t.Errorf("expected 5 Identification and Authentication, got %d", families["Identification and Authentication"])
	}
	if families["Incident Response"] != 5 {
		t.Errorf("expected 5 Incident Response, got %d", families["Incident Response"])
	}
	if families["System and Communications Protection"] != 6 {
		t.Errorf("expected 6 System and Communications Protection, got %d", families["System and Communications Protection"])
	}
	if families["System and Information Integrity"] != 6 {
		t.Errorf("expected 6 System and Information Integrity, got %d", families["System and Information Integrity"])
	}
	if families["Privacy"] != 4 {
		t.Errorf("expected 4 Privacy, got %d", families["Privacy"])
	}

	if controls[0].ControlID != "AC-1" {
		t.Errorf("expected first control AC-1, got %s", controls[0].ControlID)
	}
	if controls[0].Framework != "FEDRAMP_REV5" {
		t.Errorf("expected Framework FEDRAMP_REV5, got %s", controls[0].Framework)
	}
}

func TestProviderWriteEmbeddedControls(t *testing.T) {
	backend := &mockBackend{}
	p := &Provider{store: backend, logger: slog.Default()}

	count, err := p.writeEmbeddedControls(context.Background())
	if err != nil {
		t.Fatalf("writeEmbeddedControls failed: %v", err)
	}

	if count != 51 {
		t.Errorf("expected 51 controls written, got %d", count)
	}
	if len(backend.controls) != 51 {
		t.Errorf("expected 51 controls in backend, got %d", len(backend.controls))
	}
}

func TestProviderName(t *testing.T) {
	p := &Provider{}
	if got := p.Name(); got != "fedramp" {
		t.Errorf("Name() = %q, want %q", got, "fedramp")
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
		t.Errorf("expected some FedRAMP controls to have RelatedCWEs populated, got 0")
	}
}
