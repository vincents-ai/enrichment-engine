package csa_ccm

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"testing"

	"github.com/shift/enrichment-engine/pkg/grc"
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
func (m *mockBackend) Close(ctx context.Context) error { return nil }

func TestNew(t *testing.T) {
	backend := &mockBackend{}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	p := New(backend, logger)
	if p == nil {
		t.Fatal("New returned nil")
	}
	if p.store != backend {
		t.Error("store not set")
	}
	if p.logger != logger {
		t.Error("logger not set")
	}
}

func TestEmbeddedControls(t *testing.T) {
	controls := embeddedControls()

	if len(controls) != 65 {
		t.Errorf("expected 65 embedded controls, got %d", len(controls))
	}

	families := make(map[string]int)
	for _, ctrl := range controls {
		families[ctrl.Family]++
	}

	if families["IAM"] != 11 {
		t.Errorf("expected 11 IAM, got %d", families["IAM"])
	}
	if families["TVM"] != 7 {
		t.Errorf("expected 7 TVM, got %d", families["TVM"])
	}
	if families["DSP"] != 7 {
		t.Errorf("expected 7 DSP, got %d", families["DSP"])
	}
	if families["CIS"] != 7 {
		t.Errorf("expected 7 CIS, got %d", families["CIS"])
	}
	if families["IPY"] != 5 {
		t.Errorf("expected 5 IPY, got %d", families["IPY"])
	}
	if families["SAB"] != 5 {
		t.Errorf("expected 5 SAB, got %d", families["SAB"])
	}
	if families["SEF"] != 5 {
		t.Errorf("expected 5 SEF, got %d", families["SEF"])
	}
	if families["RSK"] != 4 {
		t.Errorf("expected 4 RSK, got %d", families["RSK"])
	}
	if families["GRC"] != 5 {
		t.Errorf("expected 5 GRC, got %d", families["GRC"])
	}
	if families["KEA"] != 5 {
		t.Errorf("expected 5 KEA, got %d", families["KEA"])
	}
	if families["INR"] != 4 {
		t.Errorf("expected 4 INR, got %d", families["INR"])
	}

	if controls[0].ControlID != "IAM-01" {
		t.Errorf("expected first control IAM-01, got %s", controls[0].ControlID)
	}
	if controls[0].Framework != "CSA_CCM_V4" {
		t.Errorf("expected Framework CSA_CCM_V4, got %s", controls[0].Framework)
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

func TestProviderWriteEmbeddedControls(t *testing.T) {
	backend := &mockBackend{}
	p := &Provider{store: backend, logger: slog.Default()}

	count, err := p.writeEmbeddedControls(context.Background())
	if err != nil {
		t.Fatalf("writeEmbeddedControls failed: %v", err)
	}

	if count != 65 {
		t.Errorf("expected 65 controls written, got %d", count)
	}
	if len(backend.controls) != 65 {
		t.Errorf("expected 65 controls in backend, got %d", len(backend.controls))
	}
}

func TestRun(t *testing.T) {
	backend := &mockBackend{}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	p := New(backend, logger)
	count, err := p.Run(context.Background())
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if count != 65 {
		t.Errorf("expected 65 controls written, got %d", count)
	}
}

func TestRunWriteError(t *testing.T) {
	backend := &mockBackend{err: fmt.Errorf("write failed")}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	p := New(backend, logger)
	count, err := p.Run(context.Background())
	if err != nil {
		t.Fatalf("Run should not return error on write failure, got: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 controls written, got %d", count)
	}
}

func TestProviderName(t *testing.T) {
	p := &Provider{}
	if got := p.Name(); got != "csa_ccm" {
		t.Errorf("Name() = %q, want %q", got, "csa_ccm")
	}
}

func TestEmbeddedControlsStoredCorrectly(t *testing.T) {
	backend := &mockBackend{}
	p := New(backend, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	p.Run(context.Background())

	for id, ctrl := range backend.controls {
		c, ok := ctrl.(grc.Control)
		if !ok {
			t.Errorf("expected grc.Control, got %T for id %s", ctrl, id)
			continue
		}
		if c.Framework != FrameworkID {
			t.Errorf("expected Framework %s, got %s", FrameworkID, c.Framework)
		}
		if len(c.ControlID) == 0 {
			t.Errorf("control with id %s has empty ControlID", id)
		}
	}
}
