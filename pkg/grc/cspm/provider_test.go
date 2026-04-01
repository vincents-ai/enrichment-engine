package cspm

import (
	"context"
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
	if len(controls) < 25 {
		t.Errorf("expected at least 25 embedded controls, got %d", len(controls))
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
	if count < 25 {
		t.Errorf("expected at least 25 controls written, got %d", count)
	}
	for id := range mock.controls {
		expectedPrefix := FrameworkID + "/"
		if len(id) <= len(expectedPrefix) {
			t.Errorf("control ID %q too short", id)
		}
	}
}

func TestProviderName(t *testing.T) {
	mock := &mockBackend{}
	p := New(mock, nil)
	if p.Name() != "cspm" {
		t.Errorf("expected name 'cspm', got %q", p.Name())
	}
}
