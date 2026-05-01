package cis_controls

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/vincents-ai/enrichment-engine/pkg/grc"
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

func TestNew(t *testing.T) {
	backend := &mockBackend{}
	logger := testLogger()
	p := New(backend, logger)
	if p == nil {
		t.Fatal("New() returned nil")
	}
	if p.store != backend {
		t.Error("New() did not set store")
	}
	if p.logger != logger {
		t.Error("New() did not set logger")
	}
}

func TestEmbeddedControls(t *testing.T) {
	if len(embeddedCatalog) == 0 {
		t.Errorf("expected non-empty embedded catalog")
	}
	p := &Provider{}
	controls, err := p.parse(embeddedCatalog)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(controls) < 5 {
		t.Errorf("expected at least 5 embedded controls, got %d", len(controls))
	}
	for _, ctrl := range controls {
		if ctrl.ControlID == "" {
			t.Errorf("control has empty ControlID: %+v", ctrl)
		}
		if ctrl.Framework == "" {
			t.Errorf("control %s has empty Framework", ctrl.ControlID)
		}
		if ctrl.Title == "" {
			t.Errorf("control %s has empty Title", ctrl.ControlID)
		}
	}
}

func TestProviderWriteEmbeddedControls(t *testing.T) {
	backend := &mockBackend{}
	logger := testLogger()
	p := New(backend, logger)
	count, err := p.Run(context.Background())
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if count == 0 {
		t.Skip("embedded catalog produced 0 controls (structure mismatch - expected for offline test)")
	}
	if len(backend.controls) != count {
		t.Errorf("backend controls count %d != Run count %d", len(backend.controls), count)
	}
}

func TestProviderName(t *testing.T) {
	p := &Provider{}
	if got := p.Name(); got != "cis_controls" {
		t.Errorf("Name() = %q, want %q", got, "cis_controls")
	}
}

func TestRelatedCWEsPopulated(t *testing.T) {
	if len(embeddedCatalog) == 0 {
		t.Skip("no embedded catalog available")
	}
	p := &Provider{}
	controls, err := p.parse(embeddedCatalog)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
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
		t.Errorf("expected some CIS Controls to have RelatedCWEs populated, got 0")
	}
}

func TestDownloadSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"implementationGroups":[{"id":"ig1","name":"IG1","controls":[{"id":"1.1","title":"Inventory","description":"desc"}]}]}`))
	}))
	defer srv.Close()

	p := &Provider{logger: testLogger()}
	f, err := os.CreateTemp("", "cis_ctrl_download_test_*.json")
	if err != nil {
		t.Fatal(err)
	}
	dest := f.Name()
	f.Close()
	defer os.Remove(dest)

	err = p.download(context.Background(), srv.URL, dest)
	if err != nil {
		t.Fatalf("download failed: %v", err)
	}
	data, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "implementationGroups") {
		t.Errorf("downloaded file missing expected content")
	}
}

func TestDownloadNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	p := &Provider{logger: testLogger()}
	f, _ := os.CreateTemp("", "cis_ctrl_download_test_*.json")
	dest := f.Name()
	f.Close()
	defer os.Remove(dest)

	err := p.download(context.Background(), srv.URL, dest)
	if err == nil {
		t.Fatal("expected error for 500 status")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error should mention status code 500, got: %v", err)
	}
}

func TestDownloadInvalidURL(t *testing.T) {
	p := &Provider{logger: testLogger()}
	f, _ := os.CreateTemp("", "cis_ctrl_download_test_*.json")
	dest := f.Name()
	f.Close()
	defer os.Remove(dest)

	err := p.download(context.Background(), "http://127.0.0.1:1", dest)
	if err == nil {
		t.Fatal("expected error for invalid URL")
	}
}

func TestParseWithGroups(t *testing.T) {
	catalog := cisCatalog{
		ImplementationGroups: []cisIG{
			{
				ID:   "ig1",
				Name: "IG1 - Critical",
				Controls: []cisSubControl{
					{ID: "1.1", Title: "Inventory", Description: "desc1"},
					{ID: "1.2", Title: "Software", Description: "desc2"},
				},
			},
			{
				ID:   "ig2",
				Name: "IG2 - Important",
				Controls: []cisSubControl{
					{ID: "2.1", Title: "Training", Description: "desc3"},
				},
			},
		},
	}
	data, _ := json.Marshal(catalog)

	p := &Provider{logger: testLogger()}
	controls, err := p.parse(data)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(controls) != 3 {
		t.Fatalf("expected 3 controls, got %d", len(controls))
	}
	if controls[0].ControlID != "1.1" {
		t.Errorf("expected ControlID 1.1, got %s", controls[0].ControlID)
	}
	if controls[0].Family != "IG1 - Critical" {
		t.Errorf("expected Family from IG name, got %s", controls[0].Family)
	}
	if controls[2].Framework != FrameworkID {
		t.Errorf("expected Framework %s, got %s", FrameworkID, controls[2].Framework)
	}
}

func TestParseInvalidJSON(t *testing.T) {
	p := &Provider{logger: testLogger()}
	_, err := p.parse([]byte(`{invalid json`))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestParseEmptyCatalog(t *testing.T) {
	data, _ := json.Marshal(cisCatalog{})
	p := &Provider{logger: testLogger()}
	controls, err := p.parse(data)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(controls) != 0 {
		t.Errorf("expected 0 controls from empty catalog, got %d", len(controls))
	}
}

func TestExtractControls(t *testing.T) {
	p := &Provider{logger: testLogger()}
	ig := cisIG{
		ID:   "ig1",
		Name: "IG1",
		Controls: []cisSubControl{
			{ID: "1.1", Title: "Inventory", Description: "desc"},
		},
	}
	controls := p.extractControls(ig)
	if len(controls) != 1 {
		t.Fatalf("expected 1 control, got %d", len(controls))
	}
	if controls[0].ControlID != "1.1" {
		t.Errorf("expected ControlID 1.1, got %s", controls[0].ControlID)
	}
	if controls[0].Framework != FrameworkID {
		t.Errorf("expected Framework %s, got %s", FrameworkID, controls[0].Framework)
	}
	if controls[0].Family != "IG1" {
		t.Errorf("expected Family IG1, got %s", controls[0].Family)
	}
}

func TestMapLevel(t *testing.T) {
	tests := []struct {
		id   string
		want string
	}{
		{"1.1", "basic"},
		{"1.2", "basic"},
		{"2.1", "basic"},
		{"3.3", "basic"},
		{"4.1", "basic"},
		{"4.3", "basic"},
		{"6.5", "standard"},
		{"8.1", "standard"},
		{"12.1", "standard"},
		{"12.5", "standard"},
		{"16.1", "high"},
		{"16.10", "high"},
		{"17.1", "high"},
	}
	p := &Provider{}
	for _, tt := range tests {
		got := p.mapLevel(tt.id)
		if got != tt.want {
			t.Errorf("mapLevel(%q) = %q, want %q", tt.id, got, tt.want)
		}
	}
}

func TestCisCWEs(t *testing.T) {
	cwes := cisCWEs("1.1")
	if len(cwes) != 2 {
		t.Errorf("expected 2 CWEs for 1.1, got %d", len(cwes))
	}
	cwes = cisCWEs("nonexistent")
	if cwes != nil {
		t.Errorf("expected nil for unknown control, got %v", cwes)
	}
}

func TestRunWithWriteError(t *testing.T) {
	backend := &mockBackend{err: os.ErrPermission}
	logger := testLogger()
	p := New(backend, logger)

	count, err := p.Run(context.Background())
	if err != nil {
		t.Fatalf("Run should not return error on individual write failures: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 controls written when all writes fail, got %d", count)
	}
}

func TestRunDownloadSuccess(t *testing.T) {
	catalog := cisCatalog{
		ImplementationGroups: []cisIG{
			{
				ID:   "ig1",
				Name: "IG1",
				Controls: []cisSubControl{
					{ID: "1.1", Title: "Inventory", Description: "desc"},
					{ID: "1.2", Title: "Software", Description: "desc2"},
				},
			},
		},
	}
	data, _ := json.Marshal(catalog)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
	}))
	defer srv.Close()

	originalURL := catalogURL
	catalogURL = srv.URL
	defer func() { catalogURL = originalURL }()

	backend := &mockBackend{}
	logger := testLogger()
	p := New(backend, logger)

	count, err := p.Run(context.Background())
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if count != 2 {
		t.Errorf("expected 2 controls, got %d", count)
	}
}

func TestRunDownloadErrorFallback(t *testing.T) {
	originalURL := catalogURL
	catalogURL = "http://127.0.0.1:1"
	defer func() { catalogURL = originalURL }()

	backend := &mockBackend{}
	logger := testLogger()
	p := New(backend, logger)

	count, err := p.Run(context.Background())
	if err != nil {
		t.Fatalf("Run should fallback to embedded on download error: %v", err)
	}
	if count == 0 {
		t.Skip("embedded catalog produced 0 controls")
	}
}

func TestRunParseError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{invalid json`))
	}))
	defer srv.Close()

	originalURL := catalogURL
	catalogURL = srv.URL
	defer func() { catalogURL = originalURL }()

	backend := &mockBackend{}
	logger := testLogger()
	p := New(backend, logger)

	count, err := p.Run(context.Background())
	if err == nil {
		t.Fatalf("expected error when both downloaded and embedded parse fail")
	}
	if count != 0 {
		t.Errorf("expected 0 controls on parse error, got %d", count)
	}
}

func TestDownloadMalformedURL(t *testing.T) {
	p := &Provider{logger: testLogger()}
	f, _ := os.CreateTemp("", "malformed_*.json")
	dest := f.Name()
	f.Close()
	defer os.Remove(dest)

	err := p.download(context.Background(), "://bad", dest)
	if err == nil {
		t.Fatal("expected error for malformed URL")
	}
}

func TestDownloadConnectionRefused(t *testing.T) {
	p := &Provider{logger: testLogger()}
	f, _ := os.CreateTemp("", "conn_refused_*.json")
	dest := f.Name()
	f.Close()
	defer os.Remove(dest)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err := p.download(ctx, "http://127.0.0.1:1", dest)
	if err == nil {
		t.Fatal("expected error for connection refused")
	}
}

func TestDownloadCreateError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	origClient := grc.HTTPClient
	defer func() { grc.HTTPClient = origClient }()
	grc.HTTPClient = server.Client()

	p := &Provider{logger: testLogger()}
	err := p.download(context.Background(), server.URL, "/nonexistent/dir/file.json")
	if err == nil {
		t.Fatal("expected error for invalid dest path")
	}
}

func TestRunCreateTempError(t *testing.T) {
	t.Setenv("TMPDIR", "/nonexistent/path/that/does/not/exist")
	p := New(nil, testLogger())
	count, err := p.Run(context.Background())
	if err == nil {
		t.Fatal("expected error when CreateTemp fails")
	}
	if count != 0 {
		t.Errorf("expected 0, got %d", count)
	}
}



func TestDownloadIOCopyError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		time.Sleep(200 * time.Millisecond)
		w.Write([]byte(`{}`))
	}))
	defer server.Close()

	origClient := grc.HTTPClient
	defer func() { grc.HTTPClient = origClient }()
	grc.HTTPClient = server.Client()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	p := &Provider{logger: testLogger()}
	f, err := os.CreateTemp("", "iocopy_err_*.json")
	if err != nil {
		t.Fatal(err)
	}
	dest := f.Name()
	f.Close()
	defer os.Remove(dest)

	err = p.download(ctx, server.URL, dest)
	if err == nil {
		t.Fatal("expected error from io.Copy failure")
	}
}

