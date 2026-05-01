package misp

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/vincents-ai/enrichment-engine/pkg/grc"
	"github.com/vincents-ai/enrichment-engine/pkg/storage"
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

func (m *mockBackend) ListControlsByTag(_ context.Context, _ string) ([]storage.ControlRow, error) {
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
	if p.Name() != "misp" {
		t.Errorf("expected name 'misp', got %q", p.Name())
	}
}

func TestFrameworkID(t *testing.T) {
	if FrameworkID != "MISP_THREAT_V2" {
		t.Errorf("expected FrameworkID 'MISP_THREAT_V2', got %q", FrameworkID)
	}
}

func TestCatalogURL(t *testing.T) {
	if CatalogURL != "" {
		t.Errorf("expected empty CatalogURL, got %q", CatalogURL)
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
		if ctrl.Description == "" {
			t.Errorf("control %s: empty Description", ctrl.ControlID)
		}
		if ctrl.Level == "" {
			t.Errorf("control %s: empty Level", ctrl.ControlID)
		}
		if len(ctrl.References) == 0 {
			t.Errorf("control %s: empty References", ctrl.ControlID)
		}
		if ctrl.References[0].Source == "" {
			t.Errorf("control %s: empty Reference.Source", ctrl.ControlID)
		}
		if ctrl.ImplementationGuidance == "" {
			t.Errorf("control %s: empty ImplementationGuidance", ctrl.ControlID)
		}
		if len(ctrl.AssessmentMethods) == 0 {
			t.Errorf("control %s: empty AssessmentMethods", ctrl.ControlID)
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

func TestEmbeddedControlsAllHaveCWEs(t *testing.T) {
	controls := embeddedControls()
	for _, ctrl := range controls {
		if len(ctrl.RelatedCWEs) == 0 {
			t.Errorf("control %s: expected at least one RelatedCWE", ctrl.ControlID)
		}
		for _, cwe := range ctrl.RelatedCWEs {
			if len(cwe) < 4 {
				t.Errorf("control %s: invalid CWE format %q", ctrl.ControlID, cwe)
			}
		}
	}
}

func TestRun(t *testing.T) {
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

func TestRunWithLogger(t *testing.T) {
	mock := &mockBackend{}
	logger := slog.Default()
	p := New(mock, logger)
	ctx := context.Background()
	count, err := p.Run(ctx)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	if count < 20 {
		t.Errorf("expected at least 20 controls written, got %d", count)
	}
}

func TestRunWithNilLogger(t *testing.T) {
	mock := &mockBackend{}
	p := New(mock, nil)
	ctx := context.Background()
	count, err := p.Run(ctx)
	if err != nil {
		t.Fatalf("Run() with nil logger error: %v", err)
	}
	if count < 20 {
		t.Errorf("expected at least 20 controls written, got %d", count)
	}
}

func TestRunWriteErrorAll(t *testing.T) {
	mock := &mockBackend{failAll: true}
	p := New(mock, slog.Default())
	ctx := context.Background()
	count, err := p.Run(ctx)
	if err != nil {
		t.Fatalf("Run() should not return error even on write failures: %v", err)
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
	p := New(mock, slog.Default())
	ctx := context.Background()
	count, err := p.Run(ctx)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	expected := len(controls) - failCount
	if count != expected {
		t.Errorf("expected %d controls written (partial failure), got %d", expected, count)
	}
}

func TestControlValuesStored(t *testing.T) {
	mock := &mockBackend{}
	p := New(mock, nil)
	ctx := context.Background()
	count, err := p.Run(ctx)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
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

func TestEmbeddedControlsFamilies(t *testing.T) {
	controls := embeddedControls()
	families := make(map[string]int)
	for _, ctrl := range controls {
		families[ctrl.Family]++
	}
	expectedFamilies := []string{"IoC Categories", "Threat Types", "EU-Specific Feeds", "Operational", "Taxonomy"}
	for _, f := range expectedFamilies {
		if families[f] == 0 {
			t.Errorf("expected controls in family %q, got 0", f)
		}
	}
}

func TestEmbeddedControlsLevelValues(t *testing.T) {
	controls := embeddedControls()
	levels := make(map[string]int)
	for _, ctrl := range controls {
		levels[ctrl.Level]++
	}
	validLevels := map[string]bool{"critical": true, "high": true, "medium": true, "low": true}
	for level := range levels {
		if !validLevels[level] {
			t.Errorf("invalid level %q found", level)
		}
	}
}
