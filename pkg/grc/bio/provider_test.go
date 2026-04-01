package bio

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

func (m *mockBackend) ReadControl(ctx context.Context, id string) ([]byte, error) {
	return nil, nil
}

func (m *mockBackend) ListMappings(ctx context.Context, vulnID string) ([]storage.MappingRow, error) {
	return nil, nil
}

func (m *mockBackend) Close(ctx context.Context) error {
	return nil
}

func TestEmbeddedControls(t *testing.T) {
	controls := embeddedControls()

	if len(controls) < 20 {
		t.Errorf("expected at least 20 embedded controls, got %d", len(controls))
	}

	if controls[0].Framework != "BIO_2_1" {
		t.Errorf("expected Framework BIO_2_1, got %s", controls[0].Framework)
	}

	if controls[0].ControlID != "B.1.1" {
		t.Errorf("expected first control B.1.1, got %s", controls[0].ControlID)
	}

	families := make(map[string]int)
	for _, ctrl := range controls {
		families[ctrl.Family]++
	}

	expectedFamilies := []string{
		"B.1 Informatiebeveiligingsbeleid",
		"B.5 Toegangscontrole",
		"B.12 Incidentmanagement",
		"B.13 Bedrijfscontinuïteit",
	}

	for _, f := range expectedFamilies {
		if families[f] == 0 {
			t.Errorf("expected family %q to have controls, got 0", f)
		}
	}

	levels := make(map[string]int)
	for _, ctrl := range controls {
		levels[ctrl.Level]++
	}

	for _, l := range []string{"basis", "versterkt", "geavanceerd"} {
		if l != "geavanceerd" && levels[l] == 0 {
			t.Errorf("expected level %q to have controls, got 0", l)
		}
	}
}

func TestProviderWriteEmbeddedControls(t *testing.T) {
	backend := &mockBackend{}
	p := &Provider{store: backend, logger: slog.Default()}

	count, err := p.writeEmbeddedControls(context.Background())
	if err != nil {
		t.Fatalf("writeEmbeddedControls failed: %v", err)
	}

	if count < 20 {
		t.Errorf("expected at least 20 controls written, got %d", count)
	}

	if len(backend.controls) < 20 {
		t.Errorf("expected at least 20 controls in backend, got %d", len(backend.controls))
	}
}

func TestProviderName(t *testing.T) {
	p := &Provider{}
	if got := p.Name(); got != "bio" {
		t.Errorf("Name() = %q, want %q", got, "bio")
	}
}
