package veris_vcdb

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

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestNew(t *testing.T) {
	p := New(nil, nil)
	if p == nil {
		t.Fatal("New() returned nil")
	}
	if got := p.Name(); got != "veris_vcdb" {
		t.Errorf("Name() = %q, want %q", got, "veris_vcdb")
	}
}

func TestProviderName(t *testing.T) {
	mock := &mockBackend{}
	p := New(mock, nil)
	if p.Name() != "veris_vcdb" {
		t.Errorf("expected name 'veris_vcdb', got %q", p.Name())
	}
}

func TestEmbeddedControls(t *testing.T) {
	controls := embeddedControls()
	if len(controls) < 20 {
		t.Errorf("expected at least 20 embedded controls, got %d", len(controls))
	}
	for _, ctrl := range controls {
		if ctrl.Framework != FrameworkID {
			t.Errorf("control %s: expected framework %s, got %s", ctrl.ControlID, FrameworkID, ctrl.Framework)
		}
		if ctrl.ControlID == "" {
			t.Error("found control with empty ControlID")
		}
		if ctrl.Title == "" {
			t.Errorf("control %s: empty Title", ctrl.ControlID)
		}
		if ctrl.Family == "" {
			t.Errorf("control %s: empty Family", ctrl.ControlID)
		}
	}
	ids := map[string]bool{}
	for _, ctrl := range controls {
		if ids[ctrl.ControlID] {
			t.Errorf("duplicate control ID: %s", ctrl.ControlID)
		}
		ids[ctrl.ControlID] = true
	}
}

func TestProviderWriteEmbeddedControls(t *testing.T) {
	mock := &mockBackend{}
	p := New(mock, nil)
	ctx := context.Background()
	count, err := p.Run(ctx)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	if count != len(mock.controls) {
		t.Errorf("Run() returned %d, but %d controls stored", count, len(mock.controls))
	}
	if count < 20 {
		t.Errorf("expected at least 20 controls written, got %d", count)
	}
}

func TestRunWithWriteError(t *testing.T) {
	p := New(&failWriteBackend{}, testLogger())

	count, err := p.Run(context.Background())
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 controls on write error, got %d", count)
	}
}

func TestEmbeddedControlsFields(t *testing.T) {
	controls := embeddedControls()
	for _, ctrl := range controls {
		if ctrl.Description == "" {
			t.Errorf("control %s has empty Description", ctrl.ControlID)
		}
		if ctrl.Level == "" {
			t.Errorf("control %s has empty Level", ctrl.ControlID)
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
		hasVERIS := false
		for _, ref := range ctrl.References {
			if strings.Contains(ref.Source, "VERIS") {
				hasVERIS = true
			}
		}
		if !hasVERIS {
			t.Errorf("control %s has no VERIS reference", ctrl.ControlID)
		}
	}
}

func TestEmbeddedControlsRelatedCWEs(t *testing.T) {
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
		t.Errorf("expected some controls to have RelatedCWEs populated, got 0")
	}
}

func TestEmbeddedControlsImplementationGuidance(t *testing.T) {
	controls := embeddedControls()
	populatedCount := 0
	for _, ctrl := range controls {
		if ctrl.ImplementationGuidance != "" {
			populatedCount++
		}
	}
	if populatedCount == 0 {
		t.Errorf("expected some controls to have ImplementationGuidance, got 0")
	}
}

func TestEmbeddedControlsAssessmentMethods(t *testing.T) {
	controls := embeddedControls()
	populatedCount := 0
	for _, ctrl := range controls {
		if len(ctrl.AssessmentMethods) > 0 {
			populatedCount++
		}
	}
	if populatedCount == 0 {
		t.Errorf("expected some controls to have AssessmentMethods, got 0")
	}
}

func TestEmbeddedControlsStoredCorrectly(t *testing.T) {
	backend := &mockBackend{}
	p := New(backend, testLogger())
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

func TestRunWithNilLogger(t *testing.T) {
	mock := &mockBackend{}
	p := New(mock, nil)
	count, err := p.Run(context.Background())
	if err != nil {
		t.Fatalf("Run with nil logger failed: %v", err)
	}
	if count < 20 {
		t.Errorf("expected at least 20 controls, got %d", count)
	}
}

func TestWriteEmbeddedControlsWithLogger(t *testing.T) {
	backend := &mockBackend{}
	p := New(backend, testLogger())
	count, err := p.writeEmbeddedControls(context.Background())
	if err != nil {
		t.Fatalf("writeEmbeddedControls failed: %v", err)
	}
	if count != len(embeddedControls()) {
		t.Errorf("expected %d controls, got %d", len(embeddedControls()), count)
	}
}

func TestEmbeddedControlsFamilies(t *testing.T) {
	controls := embeddedControls()
	families := make(map[string]int)
	for _, ctrl := range controls {
		families[ctrl.Family]++
	}
	expectedFamilies := []string{"Actions", "Varieties", "Assets", "Attributes", "Disclosure", "Vector"}
	for _, fam := range expectedFamilies {
		if families[fam] == 0 {
			t.Errorf("expected controls in family %q, found none", fam)
		}
	}
}
