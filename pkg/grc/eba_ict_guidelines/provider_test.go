package eba_ict_guidelines

import (
	"context"
	"log/slog"
	"os"
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
func (m *mockBackend) Close(ctx context.Context) error { return nil }
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

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// TestEBAICTControlsLoaded verifies that staticControls returns at least 40 controls.
func TestEBAICTControlsLoaded(t *testing.T) {
	controls := staticControls()
	const minControls = 40
	if len(controls) < minControls {
		t.Errorf("staticControls() returned %d controls, want >= %d", len(controls), minControls)
	}
}

// TestEBAICTFrameworkID verifies that all controls carry the correct FrameworkID.
func TestEBAICTFrameworkID(t *testing.T) {
	controls := staticControls()
	for _, ctrl := range controls {
		if ctrl.Framework != FrameworkID {
			t.Errorf("control %s has Framework %q, want %q", ctrl.ControlID, ctrl.Framework, FrameworkID)
		}
	}
}

// TestEBAICTNoEmptyTitles verifies that no control has an empty Title or ControlID.
func TestEBAICTNoEmptyTitles(t *testing.T) {
	controls := staticControls()
	for _, ctrl := range controls {
		if ctrl.Title == "" {
			t.Errorf("control %s has empty Title", ctrl.ControlID)
		}
		if ctrl.ControlID == "" {
			t.Error("found control with empty ControlID")
		}
	}
}

// TestEBAICTProviderRun calls Run() via a memory mock store and verifies >= 40 controls written.
func TestEBAICTProviderRun(t *testing.T) {
	backend := &mockBackend{}
	p := New(backend, testLogger())
	count, err := p.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() returned unexpected error: %v", err)
	}
	const minControls = 40
	if count < minControls {
		t.Errorf("Run() count = %d, want >= %d", count, minControls)
	}
	if len(backend.controls) < minControls {
		t.Errorf("backend controls count = %d, want >= %d", len(backend.controls), minControls)
	}
}

// TestEBAICTProviderName verifies the provider name.
func TestEBAICTProviderName(t *testing.T) {
	p := &Provider{}
	if got := p.Name(); got != "eba_ict_guidelines" {
		t.Errorf("Name() = %q, want %q", got, "eba_ict_guidelines")
	}
}

// TestEBAICTUniqueControlIDs verifies that no two controls share the same ControlID.
func TestEBAICTUniqueControlIDs(t *testing.T) {
	controls := staticControls()
	ids := make(map[string]bool)
	for _, ctrl := range controls {
		if ids[ctrl.ControlID] {
			t.Errorf("duplicate ControlID: %s", ctrl.ControlID)
		}
		ids[ctrl.ControlID] = true
	}
}

// TestEBAICTAllHaveReferences verifies that every control has at least one reference.
func TestEBAICTAllHaveReferences(t *testing.T) {
	controls := staticControls()
	for _, ctrl := range controls {
		if len(ctrl.References) == 0 {
			t.Errorf("control %s has no references", ctrl.ControlID)
		}
	}
}

// TestEBAICTRunWriteError verifies that Run() tolerates write errors and returns 0 on full failure.
func TestEBAICTRunWriteError(t *testing.T) {
	backend := &mockBackend{err: os.ErrPermission}
	p := New(backend, testLogger())
	count, err := p.Run(context.Background())
	if err != nil {
		t.Fatalf("Run should not return error on write failure, got: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 controls written on error, got %d", count)
	}
}
