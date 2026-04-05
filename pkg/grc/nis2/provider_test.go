package nis2

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

	"github.com/shift/enrichment-engine/pkg/grc"
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

type failWriteBackend struct{}

func (f *failWriteBackend) WriteVulnerability(ctx context.Context, id string, record interface{}) error {
	return nil
}
func (f *failWriteBackend) WriteControl(ctx context.Context, id string, control interface{}) error {
	return os.ErrPermission
}
func (f *failWriteBackend) WriteMapping(ctx context.Context, vulnID, controlID, framework, mappingType string, confidence float64, evidence string) error {
	return nil
}
func (f *failWriteBackend) ReadVulnerability(ctx context.Context, id string) ([]byte, error) {
	return nil, nil
}
func (f *failWriteBackend) ReadControl(ctx context.Context, id string) ([]byte, error) {
	return nil, nil
}
func (f *failWriteBackend) ListMappings(ctx context.Context, vulnID string) ([]storage.MappingRow, error) {
	return nil, nil
}
func (f *failWriteBackend) Close(ctx context.Context) error { return nil }
func (f *failWriteBackend) ListAllVulnerabilities(ctx context.Context) ([]storage.VulnerabilityRow, error) {
	return nil, nil
}
func (f *failWriteBackend) ListAllControls(ctx context.Context) ([]storage.ControlRow, error) {
	return nil, nil
}
func (f *failWriteBackend) ListControlsByCWE(ctx context.Context, cwe string) ([]storage.ControlRow, error) {
	return nil, nil
}
func (f *failWriteBackend) ListControlsByCPE(ctx context.Context, cpe string) ([]storage.ControlRow, error) {
	return nil, nil
}
func (f *failWriteBackend) ListControlsByFramework(ctx context.Context, framework string) ([]storage.ControlRow, error) {
	return nil, nil
}

func (f *failWriteBackend) ListControlsByTag(_ context.Context, _ string) ([]storage.ControlRow, error) {
	return nil, nil
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestNew(t *testing.T) {
	p := New(nil, nil)
	if p == nil {
		t.Fatal("New() returned nil")
	}
	if got := p.Name(); got != "nis2" {
		t.Errorf("Name() = %q, want %q", got, "nis2")
	}
}

func TestProviderName(t *testing.T) {
	p := &Provider{}
	if got := p.Name(); got != "nis2" {
		t.Errorf("Name() = %q, want %q", got, "nis2")
	}
}

func TestEmbeddedControls(t *testing.T) {
	p := &Provider{}
	controls := p.embeddedControls()
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
	if count < 5 {
		t.Errorf("expected at least 5 controls written, got %d", count)
	}
	if len(backend.controls) < 5 {
		t.Errorf("expected at least 5 controls in backend, got %d", len(backend.controls))
	}
}

func TestRunWithWriteError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p := New(&failWriteBackend{}, testLogger())

	count, err := p.Run(ctx)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 controls on write error, got %d", count)
	}
}

func TestParse(t *testing.T) {
	catalog := nis2Catalog{
		Directive: "NIS2 Directive 2022",
		Version:   "1.0",
		Articles: []nis2Article{
			{
				Number: "21",
				Title:  "Risk management measures",
				Requirements: []nis2Requirement{
					{ID: "Art.21.1", Title: "Risk analysis", Description: "Entities shall manage risks.", Category: "Governance", Level: "high"},
					{ID: "Art.21.2", Title: "Incident handling", Description: "Implement incident measures.", Level: "standard"},
				},
			},
			{
				Number: "23",
				Title:  "Incident reporting",
				Requirements: []nis2Requirement{
					{ID: "Art.23.1", Title: "Early warning", Description: "Notify within 24 hours."},
				},
			},
		},
	}
	data, _ := json.Marshal(catalog)
	f, err := os.CreateTemp("", "nis2_test_parse_*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.Write(data)
	f.Close()

	p := &Provider{}
	controls, err := p.parse(f.Name())
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(controls) != 3 {
		t.Fatalf("expected 3 controls, got %d", len(controls))
	}
	if controls[0].ControlID != "Art.21.1" {
		t.Errorf("expected ControlID Art.21.1, got %s", controls[0].ControlID)
	}
	if controls[0].Framework != FrameworkID {
		t.Errorf("expected Framework %s, got %s", FrameworkID, controls[0].Framework)
	}
	if controls[0].Family != "Risk management measures" {
		t.Errorf("expected Family from article title, got %s", controls[0].Family)
	}
	if controls[0].Level != "high" {
		t.Errorf("expected Level 'high', got %s", controls[0].Level)
	}
	if controls[1].Level != "standard" {
		t.Errorf("expected Level 'standard', got %s", controls[1].Level)
	}
	if len(controls[0].References) != 1 {
		t.Fatalf("expected 1 reference, got %d", len(controls[0].References))
	}
	if !strings.Contains(controls[0].References[0].Section, "Article 21") {
		t.Errorf("expected reference section containing 'Article 21', got %s", controls[0].References[0].Section)
	}
}

func TestParseEmpty(t *testing.T) {
	catalog := nis2Catalog{Directive: "NIS2", Version: "1.0"}
	data, _ := json.Marshal(catalog)
	f, err := os.CreateTemp("", "nis2_test_empty_*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.Write(data)
	f.Close()

	p := &Provider{}
	controls, err := p.parse(f.Name())
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(controls) != 0 {
		t.Errorf("expected 0 controls, got %d", len(controls))
	}
}

func TestParseInvalidJSON(t *testing.T) {
	f, err := os.CreateTemp("", "nis2_test_bad_*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.Write([]byte("not valid json"))
	f.Close()

	p := &Provider{}
	_, err = p.parse(f.Name())
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
	catalog := nis2Catalog{
		Directive: "NIS2",
		Articles: []nis2Article{
			{
				Number: "21",
				Title:  "Risk management",
				Requirements: []nis2Requirement{
					{ID: "Art.21.1", Title: "Risk analysis", Description: "Manage risks."},
				},
			},
		},
	}
	body, _ := json.Marshal(catalog)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	defer server.Close()

	origClient := grc.HTTPClient
	defer func() { grc.HTTPClient = origClient }()
	grc.HTTPClient = server.Client()

	p := &Provider{logger: testLogger()}
	f, err := os.CreateTemp("", "nis2_download_*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.Close()

	err = p.download(context.Background(), server.URL, f.Name())
	if err != nil {
		t.Fatalf("download failed: %v", err)
	}

	data, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatalf("failed to read downloaded file: %v", err)
	}
	if len(data) == 0 {
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
	f, err := os.CreateTemp("", "nis2_download_err_*.json")
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
	catalog := nis2Catalog{
		Directive: "NIS2",
		Articles: []nis2Article{
			{
				Number: "21",
				Title:  "Risk management measures",
				Requirements: []nis2Requirement{
					{ID: "Art.21.1", Title: "Risk analysis", Description: "Manage risks.", Level: "high"},
					{ID: "Art.21.2", Title: "Incident handling", Description: "Handle incidents."},
				},
			},
		},
	}
	body, _ := json.Marshal(catalog)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	defer server.Close()

	origClient := grc.HTTPClient
	origURL := CatalogURL
	defer func() {
		grc.HTTPClient = origClient
		CatalogURL = origURL
	}()
	grc.HTTPClient = server.Client()
	CatalogURL = server.URL

	backend := &mockBackend{}
	p := New(backend, testLogger())
	count, err := p.Run(context.Background())
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if count != 2 {
		t.Errorf("expected 2 controls from pipeline, got %d", count)
	}
	if len(backend.controls) != 2 {
		t.Errorf("expected 2 controls in backend, got %d", len(backend.controls))
	}
}

func TestRunParseErrorFallback(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("invalid json"))
	}))
	defer server.Close()

	origClient := grc.HTTPClient
	origURL := CatalogURL
	defer func() {
		grc.HTTPClient = origClient
		CatalogURL = origURL
	}()
	grc.HTTPClient = server.Client()
	CatalogURL = server.URL

	backend := &mockBackend{}
	p := New(backend, testLogger())
	count, err := p.Run(context.Background())
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	embeddedCount := len(p.embeddedControls())
	if count != embeddedCount {
		t.Errorf("expected %d embedded fallback controls, got %d", embeddedCount, count)
	}
}

func TestEmbeddedControlsStoredCorrectly(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	backend := &mockBackend{}
	p := New(backend, testLogger())
	p.Run(ctx)

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

func TestNis2Refs(t *testing.T) {
	refs := nis2Refs("21")
	if len(refs) != 1 {
		t.Fatalf("expected 1 reference, got %d", len(refs))
	}
	if refs[0].Source != "NIS2 Directive" {
		t.Errorf("expected source 'NIS2 Directive', got %s", refs[0].Source)
	}
	if refs[0].Section != "Article 21" {
		t.Errorf("expected section 'Article 21', got %s", refs[0].Section)
	}
	if refs[0].URL != "https://eur-lex.europa.eu/eli/dir/2022/2555/oj" {
		t.Errorf("unexpected URL: %s", refs[0].URL)
	}
}

func TestEmbeddedControlsUniqueIDs(t *testing.T) {
	p := &Provider{}
	controls := p.embeddedControls()
	ids := make(map[string]bool)
	for _, ctrl := range controls {
		if ids[ctrl.ControlID] {
			t.Errorf("duplicate control ID: %s", ctrl.ControlID)
		}
		ids[ctrl.ControlID] = true
	}
}

func TestEmbeddedControlsReferences(t *testing.T) {
	p := &Provider{}
	controls := p.embeddedControls()
	for _, ctrl := range controls {
		if len(ctrl.References) == 0 {
			t.Errorf("control %s has no references", ctrl.ControlID)
			continue
		}
		if ctrl.References[0].Source != "NIS2 Directive" {
			t.Errorf("control %s: expected source 'NIS2 Directive', got %s", ctrl.ControlID, ctrl.References[0].Source)
		}
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

