package owasp_asvs

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/vincents-ai/enrichment-engine/pkg/storage"
)

// mockBackend is an in-memory storage.Backend for testing.
type mockBackend struct {
	controls map[string]interface{}
	err      error
}

func (m *mockBackend) WriteVulnerability(_ context.Context, _ string, _ interface{}) error {
	return nil
}
func (m *mockBackend) WriteControl(_ context.Context, id string, control interface{}) error {
	if m.err != nil {
		return m.err
	}
	if m.controls == nil {
		m.controls = make(map[string]interface{})
	}
	m.controls[id] = control
	return nil
}
func (m *mockBackend) WriteMapping(_ context.Context, _, _, _, _ string, _ float64, _ string) error {
	return nil
}
func (m *mockBackend) ReadVulnerability(_ context.Context, _ string) ([]byte, error) { return nil, nil }
func (m *mockBackend) ReadControl(_ context.Context, _ string) ([]byte, error)       { return nil, nil }
func (m *mockBackend) ListMappings(_ context.Context, _ string) ([]storage.MappingRow, error) {
	return nil, nil
}
func (m *mockBackend) Close(_ context.Context) error { return nil }
func (m *mockBackend) ListAllVulnerabilities(_ context.Context) ([]storage.VulnerabilityRow, error) {
	return nil, nil
}
func (m *mockBackend) ListAllControls(_ context.Context) ([]storage.ControlRow, error) {
	return nil, nil
}
func (m *mockBackend) ListControlsByCWE(_ context.Context, _ string) ([]storage.ControlRow, error) {
	return nil, nil
}
func (m *mockBackend) ListControlsByCPE(_ context.Context, _ string) ([]storage.ControlRow, error) {
	return nil, nil
}
func (m *mockBackend) ListControlsByFramework(_ context.Context, _ string) ([]storage.ControlRow, error) {
	return nil, nil
}
func (m *mockBackend) ListControlsByTag(_ context.Context, _ string) ([]storage.ControlRow, error) {
	return nil, nil
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// TestProvider_Run verifies the full pipeline: parse embedded CSV and write to storage.
func TestProvider_Run(t *testing.T) {
	backend := &mockBackend{}
	p := New(backend, testLogger())
	count, err := p.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() returned unexpected error: %v", err)
	}
	if count < 200 {
		t.Errorf("expected at least 200 controls, got %d", count)
	}
	if len(backend.controls) != count {
		t.Errorf("backend has %d controls but Run() returned %d", len(backend.controls), count)
	}
}

// TestProvider_Name checks the provider identifier.
func TestProvider_Name(t *testing.T) {
	p := &Provider{}
	if got := p.Name(); got != "owasp_asvs" {
		t.Errorf("Name() = %q, want %q", got, "owasp_asvs")
	}
}

// TestProvider_Parse_CWEMapping verifies that known controls have the expected CWE values.
func TestProvider_Parse_CWEMapping(t *testing.T) {
	p := &Provider{logger: testLogger()}
	controls, err := p.parse(embeddedCatalog)
	if err != nil {
		t.Fatalf("parse() failed: %v", err)
	}

	// Build a lookup map by ControlID.
	byID := make(map[string]struct{ cwes []string })
	for _, c := range controls {
		byID[c.ControlID] = struct{ cwes []string }{cwes: c.RelatedCWEs}
	}

	cases := []struct {
		id   string
		want string
	}{
		// V2.1.1 — minimum password length → CWE-521
		{"V2.1.1", "CWE-521"},
		// V2.1.5 — password change → CWE-620
		{"V2.1.5", "CWE-620"},
		// V2.1.6 — current+new password required → CWE-620
		{"V2.1.6", "CWE-620"},
	}

	for _, tc := range cases {
		entry, ok := byID[tc.id]
		if !ok {
			t.Errorf("control %s not found in parsed output", tc.id)
			continue
		}
		found := false
		for _, cwe := range entry.cwes {
			if cwe == tc.want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("control %s: expected CWE %s in %v", tc.id, tc.want, entry.cwes)
		}
	}
}

// TestProvider_Parse_NoCWEZero ensures no RelatedCWEs entry is "CWE-0".
func TestProvider_Parse_NoCWEZero(t *testing.T) {
	p := &Provider{logger: testLogger()}
	controls, err := p.parse(embeddedCatalog)
	if err != nil {
		t.Fatalf("parse() failed: %v", err)
	}
	for _, ctrl := range controls {
		for _, cwe := range ctrl.RelatedCWEs {
			if cwe == "CWE-0" {
				t.Errorf("control %s has invalid CWE-0 entry", ctrl.ControlID)
			}
		}
	}
}

// TestProvider_Parse_CWEPrefix verifies all CWE entries start with "CWE-".
func TestProvider_Parse_CWEPrefix(t *testing.T) {
	p := &Provider{logger: testLogger()}
	controls, err := p.parse(embeddedCatalog)
	if err != nil {
		t.Fatalf("parse() failed: %v", err)
	}
	for _, ctrl := range controls {
		for _, cwe := range ctrl.RelatedCWEs {
			if !strings.HasPrefix(cwe, "CWE-") {
				t.Errorf("control %s: CWE %q does not start with 'CWE-'", ctrl.ControlID, cwe)
			}
		}
	}
}

// TestProvider_Parse_RequiredFields checks all parsed controls have the mandatory fields.
func TestProvider_Parse_RequiredFields(t *testing.T) {
	p := &Provider{logger: testLogger()}
	controls, err := p.parse(embeddedCatalog)
	if err != nil {
		t.Fatalf("parse() failed: %v", err)
	}
	if len(controls) == 0 {
		t.Fatal("expected non-empty controls slice")
	}
	for _, ctrl := range controls {
		if ctrl.Framework != FrameworkID {
			t.Errorf("control %s: Framework = %q, want %q", ctrl.ControlID, ctrl.Framework, FrameworkID)
		}
		if ctrl.ControlID == "" {
			t.Errorf("found control with empty ControlID")
		}
		if ctrl.Level == "" {
			t.Errorf("control %s: Level is empty", ctrl.ControlID)
		}
		if len(ctrl.Tags) == 0 {
			t.Errorf("control %s: Tags is empty", ctrl.ControlID)
		}
		if len(ctrl.References) == 0 {
			t.Errorf("control %s: References is empty", ctrl.ControlID)
		}
	}
}

// TestProvider_Parse_LevelL1 verifies that some controls are classified as L1.
func TestProvider_Parse_LevelL1(t *testing.T) {
	p := &Provider{logger: testLogger()}
	controls, err := p.parse(embeddedCatalog)
	if err != nil {
		t.Fatalf("parse() failed: %v", err)
	}
	l1Count := 0
	for _, ctrl := range controls {
		if ctrl.Level == "L1" {
			l1Count++
		}
	}
	if l1Count == 0 {
		t.Error("expected some controls at level L1, got 0")
	}
}

// TestProvider_Run_WriteError verifies that write errors are skipped rather than fatal.
func TestProvider_Run_WriteError(t *testing.T) {
	backend := &mockBackend{err: os.ErrPermission}
	p := New(backend, testLogger())
	count, err := p.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() should not return error on individual write failures: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 controls written when all writes fail, got %d", count)
	}
}

// TestProvider_EmbeddedCatalogNotEmpty verifies the CSV was embedded at build time.
func TestProvider_EmbeddedCatalogNotEmpty(t *testing.T) {
	if len(embeddedCatalog) == 0 {
		t.Fatal("embeddedCatalog is empty — CSV was not embedded correctly")
	}
}
