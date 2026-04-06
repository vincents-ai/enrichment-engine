package mitre_attack_ics

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"testing"

	"github.com/shift/enrichment-engine/pkg/grc"
	"github.com/shift/enrichment-engine/pkg/storage"
)

// mockBackend is a full in-memory storage.Backend for testing.
type mockBackend struct {
	controls map[string]interface{}
	failAll  bool
	failSet  map[string]bool
}

func (m *mockBackend) WriteVulnerability(_ context.Context, _ string, _ interface{}) error {
	return nil
}
func (m *mockBackend) WriteControl(_ context.Context, id string, control interface{}) error {
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
func (m *mockBackend) WriteMapping(_ context.Context, _, _, _, _ string, _ float64, _ string) error {
	return nil
}
func (m *mockBackend) ReadVulnerability(_ context.Context, _ string) ([]byte, error) { return nil, nil }
func (m *mockBackend) ReadControl(_ context.Context, _ string) ([]byte, error)       { return nil, nil }
func (m *mockBackend) ListMappings(_ context.Context, _ string) ([]storage.MappingRow, error) {
	return nil, nil
}
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
func (m *mockBackend) Close(_ context.Context) error { return nil }

func TestProvider_Run(t *testing.T) {
	mock := &mockBackend{}
	logger := slog.Default()
	p := New(mock, logger)

	count, err := p.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() returned error: %v", err)
	}
	if count <= 15 {
		t.Errorf("expected more than 15 controls, got %d", count)
	}
	t.Logf("Run() returned %d controls", count)
}

func TestProvider_ICSControls(t *testing.T) {
	p := &Provider{logger: slog.Default()}
	controls, err := p.parse(embeddedCatalog)
	if err != nil {
		t.Fatalf("parse() error: %v", err)
	}

	// Build a set of ControlIDs for easy lookup.
	byID := make(map[string]bool, len(controls))
	for _, c := range controls {
		byID[c.ControlID] = true
	}

	// These mitigation IDs must be present in the parsed output.
	required := []string{
		"M0800", // Authorization Enforcement
		"M0801", // Access Management
		"M0802", // Communication Authenticity
		"M0804", // Human User Authentication
		"M0813", // Software Process and Device Authentication
		"M0814", // Static Network Configuration
		"M0930", // Network Segmentation
		"M0931", // Network Intrusion Prevention
		"M0937", // Filter Network Traffic
		"M0938", // Execution Prevention
	}
	for _, id := range required {
		if !byID[id] {
			t.Errorf("expected mitigation %s to be present, but it was not", id)
		}
	}
	t.Logf("parsed %d ICS controls", len(controls))
}

func TestProvider_Tags(t *testing.T) {
	p := &Provider{logger: slog.Default()}
	controls, err := p.parse(embeddedCatalog)
	if err != nil {
		t.Fatalf("parse() error: %v", err)
	}
	if len(controls) == 0 {
		t.Fatal("no controls parsed")
	}
	for _, c := range controls {
		if !slices.Contains(c.Tags, "ot-security") {
			t.Errorf("control %s (%s) is missing 'ot-security' tag; got %v",
				c.ControlID, c.Title, c.Tags)
		}
	}
}

func TestProvider_CWEMappings(t *testing.T) {
	// Spot-check a few well-known CWE mappings.
	cases := []struct {
		id  string
		cwe string
	}{
		{"M0930", "CWE-284"},
		{"M0930", "CWE-668"},
		{"M0802", "CWE-287"},
		{"M0804", "CWE-287"},
		{"M0810", "CWE-319"},
		{"M0950", "CWE-787"},
	}
	for _, tc := range cases {
		cwes := icsCWEs(tc.id)
		if !slices.Contains(cwes, tc.cwe) {
			t.Errorf("icsCWEs(%s) = %v; want to contain %s", tc.id, cwes, tc.cwe)
		}
	}
}

func TestProvider_FrameworkID(t *testing.T) {
	p := &Provider{logger: slog.Default()}
	controls, err := p.parse(embeddedCatalog)
	if err != nil {
		t.Fatalf("parse() error: %v", err)
	}
	for _, c := range controls {
		if c.Framework != FrameworkID {
			t.Errorf("control %s has framework %q, want %q", c.ControlID, c.Framework, FrameworkID)
		}
	}
}

func TestProvider_ControlFields(t *testing.T) {
	p := &Provider{logger: slog.Default()}
	controls, err := p.parse(embeddedCatalog)
	if err != nil {
		t.Fatalf("parse() error: %v", err)
	}
	for _, c := range controls {
		if c.ControlID == "" {
			t.Error("found control with empty ControlID")
		}
		if c.Title == "" {
			t.Errorf("control %s: empty Title", c.ControlID)
		}
		if c.Description == "" {
			t.Errorf("control %s: empty Description", c.ControlID)
		}
		if c.Family == "" {
			t.Errorf("control %s: empty Family", c.ControlID)
		}
		if len(c.References) == 0 {
			t.Errorf("control %s: empty References", c.ControlID)
		}
	}
}

func TestProvider_NoDuplicates(t *testing.T) {
	p := &Provider{logger: slog.Default()}
	controls, err := p.parse(embeddedCatalog)
	if err != nil {
		t.Fatalf("parse() error: %v", err)
	}
	ids := make(map[string]bool)
	for _, c := range controls {
		if ids[c.ControlID] {
			t.Errorf("duplicate control ID: %s", c.ControlID)
		}
		ids[c.ControlID] = true
	}
}

func TestProvider_RunStoresAllControls(t *testing.T) {
	mock := &mockBackend{}
	p := New(mock, slog.Default())
	count, err := p.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	if count != len(mock.controls) {
		t.Errorf("Run() returned count=%d but backend has %d controls", count, len(mock.controls))
	}
	// Verify stored controls have correct types.
	for id, stored := range mock.controls {
		ctrl, ok := stored.(grc.Control)
		if !ok {
			t.Errorf("control %q: not a grc.Control", id)
			continue
		}
		if ctrl.Framework != FrameworkID {
			t.Errorf("control %q: wrong framework %q", id, ctrl.Framework)
		}
	}
}
