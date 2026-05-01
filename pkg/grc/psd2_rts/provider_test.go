package psd2_rts

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/vincents-ai/enrichment-engine/pkg/storage"
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

func TestProvider_Run(t *testing.T) {
	backend := &mockBackend{}
	p := New(backend, testLogger())
	count, err := p.Run(context.Background())
	if err != nil {
		t.Fatalf("Run returned unexpected error: %v", err)
	}
	const want = 22
	if count != want {
		t.Errorf("Run() count = %d, want %d", count, want)
	}
	if len(backend.controls) != want {
		t.Errorf("backend controls count = %d, want %d", len(backend.controls), want)
	}
}

func TestProvider_AllHaveTags(t *testing.T) {
	controls := staticControls()
	for _, ctrl := range controls {
		if len(ctrl.Tags) == 0 {
			t.Errorf("control %s has no tags", ctrl.ControlID)
		}
	}
}

func TestProvider_ART22_CWE(t *testing.T) {
	controls := staticControls()
	for _, ctrl := range controls {
		if ctrl.ControlID != "ART-22" {
			continue
		}
		hasCWE295 := false
		hasCWE319 := false
		for _, cwe := range ctrl.RelatedCWEs {
			if cwe == "CWE-295" {
				hasCWE295 = true
			}
			if cwe == "CWE-319" {
				hasCWE319 = true
			}
		}
		if !hasCWE295 && !hasCWE319 {
			t.Errorf("ART-22 RelatedCWEs %v does not contain CWE-295 or CWE-319", ctrl.RelatedCWEs)
		}
		return
	}
	t.Fatal("ART-22 control not found")
}

func TestProvider_Name(t *testing.T) {
	p := &Provider{}
	if got := p.Name(); got != "psd2_rts" {
		t.Errorf("Name() = %q, want %q", got, "psd2_rts")
	}
}

func TestProvider_StaticControlsCount(t *testing.T) {
	controls := staticControls()
	const want = 22
	if len(controls) != want {
		t.Errorf("staticControls() returned %d controls, want %d", len(controls), want)
	}
}

func TestProvider_UniqueControlIDs(t *testing.T) {
	controls := staticControls()
	ids := make(map[string]bool)
	for _, ctrl := range controls {
		if ids[ctrl.ControlID] {
			t.Errorf("duplicate ControlID: %s", ctrl.ControlID)
		}
		ids[ctrl.ControlID] = true
	}
}

func TestProvider_AllHaveFrameworkID(t *testing.T) {
	controls := staticControls()
	for _, ctrl := range controls {
		if ctrl.Framework != FrameworkID {
			t.Errorf("control %s has Framework %q, want %q", ctrl.ControlID, ctrl.Framework, FrameworkID)
		}
	}
}

func TestProvider_AllHaveReferences(t *testing.T) {
	controls := staticControls()
	for _, ctrl := range controls {
		if len(ctrl.References) == 0 {
			t.Errorf("control %s has no references", ctrl.ControlID)
		}
	}
}

func TestProvider_RunWriteError(t *testing.T) {
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
