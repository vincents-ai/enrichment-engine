package nist_sp800_53_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"testing"

	"github.com/vincents-ai/enrichment-engine/pkg/grc/nist_sp800_53"
	"github.com/vincents-ai/enrichment-engine/pkg/storage"
)

// mockBackend is an in-memory implementation of storage.Backend for tests.
type mockBackend struct {
	controls map[string]json.RawMessage
}

func newMockBackend() *mockBackend {
	return &mockBackend{controls: make(map[string]json.RawMessage)}
}

func (m *mockBackend) WriteVulnerability(_ context.Context, _ string, _ interface{}) error {
	return nil
}
func (m *mockBackend) WriteControl(_ context.Context, id string, control interface{}) error {
	data, err := json.Marshal(control)
	if err != nil {
		return err
	}
	m.controls[id] = data
	return nil
}
func (m *mockBackend) WriteMapping(_ context.Context, _, _, _, _ string, _ float64, _ string) error {
	return nil
}
func (m *mockBackend) ReadVulnerability(_ context.Context, _ string) ([]byte, error) {
	return nil, nil
}
func (m *mockBackend) ReadControl(_ context.Context, _ string) ([]byte, error) { return nil, nil }
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

// getControl deserialises a stored control by key.
func (m *mockBackend) getControl(key string) (map[string]interface{}, bool) {
	raw, ok := m.controls[key]
	if !ok {
		return nil, false
	}
	var out map[string]interface{}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, false
	}
	return out, true
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// TestProvider_Run asserts that at least 500 controls are parsed from the embedded catalog.
func TestProvider_Run(t *testing.T) {
	backend := newMockBackend()
	p := nist_sp800_53.New(backend, testLogger())

	count, err := p.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	if count < 500 {
		t.Errorf("expected at least 500 controls, got %d", count)
	}
	t.Logf("Total controls parsed: %d", count)
}

// TestProvider_SRFamily asserts SR family controls are present.
func TestProvider_SRFamily(t *testing.T) {
	backend := newMockBackend()
	p := nist_sp800_53.New(backend, testLogger())

	_, err := p.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	wantIDs := []string{"sr-3", "sr-11"}
	for _, id := range wantIDs {
		key := nist_sp800_53.FrameworkID + "/" + id
		ctrl, ok := backend.getControl(key)
		if !ok {
			t.Errorf("expected SR family control %q to be present", id)
			continue
		}
		t.Logf("Found %s: %v (family: %v)", id, ctrl["Title"], ctrl["Family"])
	}
}

// TestProvider_CWEMappings asserts sr-11 has CWE-494.
func TestProvider_CWEMappings(t *testing.T) {
	backend := newMockBackend()
	p := nist_sp800_53.New(backend, testLogger())

	_, err := p.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	key := nist_sp800_53.FrameworkID + "/sr-11"
	ctrl, ok := backend.getControl(key)
	if !ok {
		t.Fatalf("control sr-11 not found in storage")
	}

	cwesRaw, ok := ctrl["RelatedCWEs"]
	if !ok {
		t.Fatalf("sr-11 has no RelatedCWEs field")
	}

	cwes, ok := cwesRaw.([]interface{})
	if !ok {
		t.Fatalf("sr-11 RelatedCWEs is not an array, got: %T", cwesRaw)
	}

	hasCWE494 := false
	for _, v := range cwes {
		if v.(string) == "CWE-494" {
			hasCWE494 = true
			break
		}
	}
	if !hasCWE494 {
		t.Errorf("expected sr-11 to have CWE-494, got: %v", cwes)
	}
	t.Logf("sr-11 CWEs: %v", cwes)
}

// TestProvider_Name asserts the provider name.
func TestProvider_Name(t *testing.T) {
	p := nist_sp800_53.New(newMockBackend(), testLogger())
	if got := p.Name(); got != "nist_sp800_53" {
		t.Errorf("Name() = %q, want %q", got, "nist_sp800_53")
	}
}

// TestProvider_FrameworkID asserts the framework ID constant.
func TestProvider_FrameworkID(t *testing.T) {
	if nist_sp800_53.FrameworkID != "NIST_SP800_53_R5" {
		t.Errorf("FrameworkID = %q, want %q", nist_sp800_53.FrameworkID, "NIST_SP800_53_R5")
	}
}

// TestProvider_Tags asserts SR controls have supply-chain tag.
func TestProvider_Tags(t *testing.T) {
	backend := newMockBackend()
	p := nist_sp800_53.New(backend, testLogger())

	_, err := p.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	key := nist_sp800_53.FrameworkID + "/sr-3"
	ctrl, ok := backend.getControl(key)
	if !ok {
		t.Fatalf("control sr-3 not found in storage")
	}

	tagsRaw, ok := ctrl["Tags"]
	if !ok {
		t.Fatalf("sr-3 has no Tags field")
	}

	tags, ok := tagsRaw.([]interface{})
	if !ok {
		t.Fatalf("sr-3 Tags is not an array, got: %T", tagsRaw)
	}

	hasTag := false
	for _, v := range tags {
		if v.(string) == "supply-chain" {
			hasTag = true
			break
		}
	}
	if !hasTag {
		t.Errorf("expected sr-3 to have tag 'supply-chain', got: %v", tags)
	}
}
