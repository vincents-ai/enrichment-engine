package cen_cenelec_cra

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
		t.Fatal("New returned nil")
	}
	if p.store != backend {
		t.Error("store not set")
	}
	if p.logger != logger {
		t.Error("logger not set")
	}
}

func TestProviderName(t *testing.T) {
	p := &Provider{}
	if got := p.Name(); got != "cen_cenelec_cra" {
		t.Errorf("Name() = %q, want %q", got, "cen_cenelec_cra")
	}
}

func TestEmbeddedControls(t *testing.T) {
	p := &Provider{}
	controls := p.generateEmbeddedControls()
	if len(controls) < 5 {
		t.Errorf("expected at least 5 embedded controls, got %d", len(controls))
	}
	for _, ctrl := range controls {
		if ctrl.ControlID == "" {
			t.Errorf("control has empty ControlID")
		}
		if ctrl.Framework == "" {
			t.Errorf("control %s has empty Framework", ctrl.ControlID)
		}
		if ctrl.Title == "" {
			t.Errorf("control %s has empty Title", ctrl.ControlID)
		}
	}
}

func TestEmbeddedControlsUniqueIDs(t *testing.T) {
	p := &Provider{}
	controls := p.generateEmbeddedControls()
	ids := make(map[string]bool)
	for _, ctrl := range controls {
		if ids[ctrl.ControlID] {
			t.Errorf("duplicate control ID: %s", ctrl.ControlID)
		}
		ids[ctrl.ControlID] = true
	}
}

func TestBuildControl(t *testing.T) {
	p := &Provider{}
	ctrl := p.buildControl(craStd{
		ID: "CC-CRA-99", Title: "Test", Family: "Test Family",
		Description: "Desc", Level: "high", StdRef: "EN 18031-1, Clause 99",
	})
	if ctrl.ControlID != "CC-CRA-99" {
		t.Errorf("expected ControlID CC-CRA-99, got %s", ctrl.ControlID)
	}
	if ctrl.Framework != FrameworkID {
		t.Errorf("expected Framework %s, got %s", FrameworkID, ctrl.Framework)
	}
	if ctrl.Family != "Test Family" {
		t.Errorf("expected Family Test Family, got %s", ctrl.Family)
	}
	if ctrl.Level != "high" {
		t.Errorf("expected Level high, got %s", ctrl.Level)
	}
	if len(ctrl.References) != 1 {
		t.Errorf("expected 1 reference, got %d", len(ctrl.References))
	}
	if ctrl.References[0].Section != "EN 18031-1, Clause 99" {
		t.Errorf("unexpected reference section: %s", ctrl.References[0].Section)
	}
}

func TestParseSuccess(t *testing.T) {
	catalog := craStdCatalog{
		Standards: []craStd{
			{ID: "CC-CRA-01", Title: "Test 1", Family: "Family 1", Description: "Desc 1", Level: "critical", StdRef: "Ref 1"},
			{ID: "CC-CRA-02", Title: "Test 2", Family: "Family 2", Description: "Desc 2", Level: "high", StdRef: "Ref 2"},
		},
	}
	data, _ := json.Marshal(catalog)

	dir := t.TempDir()
	path := filepath.Join(dir, "test.json")
	os.WriteFile(path, data, 0644)

	p := &Provider{}
	controls, err := p.parse(path)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(controls) != 2 {
		t.Fatalf("expected 2 controls, got %d", len(controls))
	}
	if controls[0].ControlID != "CC-CRA-01" {
		t.Errorf("expected ControlID CC-CRA-01, got %s", controls[0].ControlID)
	}
}

func TestParseInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	os.WriteFile(path, []byte("not json"), 0644)

	p := &Provider{}
	_, err := p.parse(path)
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
}

func TestParseFileNotFound(t *testing.T) {
	p := &Provider{}
	_, err := p.parse("/nonexistent/path/file.json")
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

func TestDownloadSuccess(t *testing.T) {
	catalog := craStdCatalog{Standards: []craStd{{ID: "01", Title: "T"}}}
	data, _ := json.Marshal(catalog)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
	}))
	defer server.Close()

	origClient := grc.HTTPClient
	defer func() { grc.HTTPClient = origClient }()
	grc.HTTPClient = server.Client()

	p := &Provider{logger: testLogger()}
	f, err := os.CreateTemp("", "cra_download_*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.Close()

	err = p.download(context.Background(), server.URL, f.Name())
	if err != nil {
		t.Fatalf("download failed: %v", err)
	}

	readData, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatalf("failed to read file: %v", err)
	}
	if len(readData) == 0 {
		t.Error("downloaded file is empty")
	}
}

func TestDownloadNon200(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	origClient := grc.HTTPClient
	defer func() { grc.HTTPClient = origClient }()
	grc.HTTPClient = server.Client()

	p := &Provider{logger: testLogger()}
	f, err := os.CreateTemp("", "cra_download_err_*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.Close()

	err = p.download(context.Background(), server.URL, f.Name())
	if err == nil {
		t.Fatal("expected error for non-200 status, got nil")
	}
}

func TestRunDownloadSuccess(t *testing.T) {
	catalog := craStdCatalog{Standards: []craStd{{ID: "01", Title: "T"}}}
	data, _ := json.Marshal(catalog)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
	}))
	defer server.Close()

	origClient := grc.HTTPClient
	origURL := CatalogURL
	defer func() { grc.HTTPClient = origClient; CatalogURL = origURL }()
	grc.HTTPClient = server.Client()
	CatalogURL = server.URL

	backend := &mockBackend{}
	p := New(backend, testLogger())
	count, err := p.Run(context.Background())
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 control, got %d", count)
	}
}

func TestRunDownloadErrorFallback(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	origClient := grc.HTTPClient
	origURL := CatalogURL
	defer func() { grc.HTTPClient = origClient; CatalogURL = origURL }()
	grc.HTTPClient = server.Client()
	CatalogURL = server.URL

	backend := &mockBackend{}
	p := New(backend, testLogger())
	count, err := p.Run(context.Background())
	if err != nil {
		t.Fatalf("Run should fall back to embedded, got: %v", err)
	}
	if count < 5 {
		t.Errorf("expected embedded controls as fallback, got %d", count)
	}
}

func TestRunParseErrorFallback(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("not json"))
	}))
	defer server.Close()

	origClient := grc.HTTPClient
	origURL := CatalogURL
	defer func() { grc.HTTPClient = origClient; CatalogURL = origURL }()
	grc.HTTPClient = server.Client()
	CatalogURL = server.URL

	backend := &mockBackend{}
	p := New(backend, testLogger())
	count, err := p.Run(context.Background())
	if err != nil {
		t.Fatalf("Run should fall back to embedded, got: %v", err)
	}
	if count < 5 {
		t.Errorf("expected embedded controls as fallback, got %d", count)
	}
}

func TestRunWriteError(t *testing.T) {
	backend := &mockBackend{err: fmt.Errorf("write failed")}
	p := New(backend, testLogger())
	count, err := p.Run(context.Background())
	if err != nil {
		t.Fatalf("Run should not return error on write failure, got: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 controls written, got %d", count)
	}
}

func TestRunControlsStoredCorrectly(t *testing.T) {
	backend := &mockBackend{}
	p := New(backend, testLogger())
	p.Run(context.Background())

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

