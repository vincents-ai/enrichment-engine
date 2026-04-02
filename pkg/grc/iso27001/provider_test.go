package iso27001

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

func (m *mockBackend) ReadControl(ctx context.Context, id string) ([]byte, error) {
	return nil, nil
}

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
func (m *mockBackend) Close(ctx context.Context) error {
	return nil
}

func TestEmbeddedControls(t *testing.T) {
	controls := embeddedControls()

	if len(controls) != 93 {
		t.Errorf("expected 93 embedded controls, got %d", len(controls))
	}

	// Verify all 4 themes are present
	families := make(map[string]int)
	for _, ctrl := range controls {
		families[ctrl.Family]++
	}

	if families["Organizational controls"] != 37 {
		t.Errorf("expected 37 Organizational controls, got %d", families["Organizational controls"])
	}
	if families["People controls"] != 8 {
		t.Errorf("expected 8 People controls, got %d", families["People controls"])
	}
	if families["Physical controls"] != 14 {
		t.Errorf("expected 14 Physical controls, got %d", families["Physical controls"])
	}
	if families["Technological controls"] != 34 {
		t.Errorf("expected 34 Technological controls, got %d", families["Technological controls"])
	}

	// Verify specific controls
	if controls[0].ControlID != "A.5.1" {
		t.Errorf("expected first control A.5.1, got %s", controls[0].ControlID)
	}
	if controls[0].Framework != "ISO_27001_2022" {
		t.Errorf("expected Framework ISO_27001_2022, got %s", controls[0].Framework)
	}
	if controls[0].Level != "standard" {
		t.Errorf("expected Level standard, got %s", controls[0].Level)
	}

	// Last control should be A.8.34
	last := controls[len(controls)-1]
	if last.ControlID != "A.8.34" {
		t.Errorf("expected last control A.8.34, got %s", last.ControlID)
	}
}

func TestProviderWriteEmbeddedControls(t *testing.T) {
	backend := &mockBackend{}
	p := &Provider{
		store:  backend,
		logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn})),
	}

	count, err := p.writeEmbeddedControls(context.Background())
	if err != nil {
		t.Fatalf("writeEmbeddedControls failed: %v", err)
	}

	if count != 93 {
		t.Errorf("expected 93 controls written, got %d", count)
	}

	if len(backend.controls) != 93 {
		t.Errorf("expected 93 controls in backend, got %d", len(backend.controls))
	}
}

func TestProviderName(t *testing.T) {
	p := &Provider{}
	if got := p.Name(); got != "iso27001" {
		t.Errorf("Name() = %q, want %q", got, "iso27001")
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
		t.Errorf("expected some ISO 27001 controls to have RelatedCWEs populated, got 0")
	}
}
