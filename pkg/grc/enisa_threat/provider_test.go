package enisa_threat

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

func TestEmbeddedControls(t *testing.T) {
	p := &Provider{}
	controls := p.generateEmbeddedTaxonomy()
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

func TestEmbeddedControlsUniqueIDs(t *testing.T) {
	p := &Provider{}
	controls := p.generateEmbeddedTaxonomy()
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

func TestRunWriteError(t *testing.T) {
	backend := &mockBackend{err: fmt.Errorf("write failed")}
	logger := testLogger()
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
	if got := p.Name(); got != "enisa_threat" {
		t.Errorf("Name() = %q, want %q", got, "enisa_threat")
	}
}

func TestParse(t *testing.T) {
	catalog := enisaCatalog{
		ThreatCategories: []enisaCategory{
			{ID: "MALWARE", Name: "Malware", Title: "Malware Attacks", Family: "Technical", Description: "Malware desc", Severity: "critical"},
		},
		Categories: []enisaCategory{
			{ID: "SOCIAL", Name: "Social Engineering", Title: "Social Eng", Family: "Human", Description: "Social desc", Severity: "high"},
		},
		Threats: []enisaCategory{
			{ID: "APT", Name: "APT", Title: "Advanced Persistent Threats", Description: "APT desc", Severity: "critical"},
		},
	}
	data, _ := json.Marshal(catalog)
	dir := t.TempDir()
	path := filepath.Join(dir, "catalog.json")
	os.WriteFile(path, data, 0644)

	p := &Provider{}
	controls, err := p.parse(path)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(controls) != 3 {
		t.Fatalf("expected 3 controls, got %d", len(controls))
	}
	if controls[0].ControlID != "MALWARE" {
		t.Errorf("expected ControlID MALWARE, got %s", controls[0].ControlID)
	}
}

func TestParseWithActorsAndVectors(t *testing.T) {
	catalog := enisaCatalog{
		ThreatCategories: []enisaCategory{
			{
				ID: "RANSOMWARE", Name: "Ransomware", Title: "Ransomware Attacks",
				Description: "Ransomware desc",
				Actors:      []string{"Cybercriminals", "Nation-state"},
				Vectors:     []string{"Phishing", "RDP"},
				CVEs:        []string{"CVE-2024-1234"},
				References: []enisaReference{
					{Source: "ENISA", URL: "https://enisa.europa.eu", Section: "ETL"},
				},
			},
		},
	}
	data, _ := json.Marshal(catalog)
	dir := t.TempDir()
	path := filepath.Join(dir, "catalog.json")
	os.WriteFile(path, data, 0644)

	p := &Provider{}
	controls, err := p.parse(path)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(controls) != 1 {
		t.Fatalf("expected 1 control, got %d", len(controls))
	}
	desc := controls[0].Description
	if !strings.Contains(desc, "Cybercriminals") {
		t.Error("expected description to contain threat actors")
	}
	if !strings.Contains(desc, "Phishing") {
		t.Error("expected description to contain attack vectors")
	}
	if len(controls[0].RelatedCVEs) != 1 {
		t.Errorf("expected 1 related CVE, got %d", len(controls[0].RelatedCVEs))
	}
	if len(controls[0].References) != 1 {
		t.Errorf("expected 1 reference, got %d", len(controls[0].References))
	}
}

func TestParseWithEmptyID(t *testing.T) {
	catalog := enisaCatalog{
		ThreatCategories: []enisaCategory{
			{Name: "Test Category", Description: "Desc", Severity: "high"},
		},
	}
	data, _ := json.Marshal(catalog)
	dir := t.TempDir()
	path := filepath.Join(dir, "catalog.json")
	os.WriteFile(path, data, 0644)

	p := &Provider{}
	controls, err := p.parse(path)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(controls) != 1 {
		t.Fatalf("expected 1 control, got %d", len(controls))
	}
	if controls[0].ControlID != "TEST_CATEGORY" {
		t.Errorf("expected ControlID 'TEST_CATEGORY', got %s", controls[0].ControlID)
	}
}

func TestParseWithEmptyTitle(t *testing.T) {
	catalog := enisaCatalog{
		ThreatCategories: []enisaCategory{
			{ID: "TEST", Name: "Test Name", Description: "Desc", Severity: "high"},
		},
	}
	data, _ := json.Marshal(catalog)
	dir := t.TempDir()
	path := filepath.Join(dir, "catalog.json")
	os.WriteFile(path, data, 0644)

	p := &Provider{}
	controls, err := p.parse(path)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if controls[0].Title != "Test Name" {
		t.Errorf("expected Title 'Test Name' (fallback to Name), got %q", controls[0].Title)
	}
}

func TestParseWithEmptyFamily(t *testing.T) {
	catalog := enisaCatalog{
		ThreatCategories: []enisaCategory{
			{ID: "TEST", Name: "Test", Description: "Desc", Parent: "ParentFamily", Severity: "high"},
		},
	}
	data, _ := json.Marshal(catalog)
	dir := t.TempDir()
	path := filepath.Join(dir, "catalog.json")
	os.WriteFile(path, data, 0644)

	p := &Provider{}
	controls, err := p.parse(path)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if controls[0].Family != "ParentFamily" {
		t.Errorf("expected Family 'ParentFamily' (from Parent), got %s", controls[0].Family)
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

func TestMapLevel(t *testing.T) {
	p := &Provider{}

	tests := []struct {
		severity, level, want string
	}{
		{"critical", "", "critical"},
		{"extreme", "", "critical"},
		{"high", "", "high"},
		{"severe", "", "high"},
		{"medium", "", "standard"},
		{"moderate", "", "standard"},
		{"low", "", "basic"},
		{"minor", "", "basic"},
		{"", "critical", "critical"},
		{"", "high", "high"},
		{"", "medium", "standard"},
		{"", "low", "basic"},
		{"", "", "standard"},
		{"unknown", "", "standard"},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("sev=%s/lvl=%s", tt.severity, tt.level), func(t *testing.T) {
			got := p.mapLevel(tt.severity, tt.level)
			if got != tt.want {
				t.Errorf("mapLevel(%q, %q) = %q, want %q", tt.severity, tt.level, got, tt.want)
			}
		})
	}
}

func TestBuildControl(t *testing.T) {
	p := &Provider{}
	cat := enisaCategory{
		ID: "TEST", Name: "Test", Title: "Test Title",
		Family: "Test Family", Description: "Test Desc",
		Severity: "critical",
		References: []enisaReference{
			{Source: "ENISA", URL: "https://enisa.europa.eu", Section: "Test"},
		},
	}
	ctrl := p.buildControl(cat)
	if ctrl.ControlID != "TEST" {
		t.Errorf("expected ControlID TEST, got %s", ctrl.ControlID)
	}
	if ctrl.Framework != FrameworkID {
		t.Errorf("expected Framework %s, got %s", FrameworkID, ctrl.Framework)
	}
	if ctrl.Level != "critical" {
		t.Errorf("expected Level critical, got %s", ctrl.Level)
	}
	if len(ctrl.References) != 1 {
		t.Errorf("expected 1 reference, got %d", len(ctrl.References))
	}
}

func TestDownloadSuccess(t *testing.T) {
	body := `{"threat_categories":[{"id":"MALWARE","name":"Malware","description":"desc"}]}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(body))
	}))
	defer server.Close()

	origClient := grc.HTTPClient
	defer func() { grc.HTTPClient = origClient }()
	grc.HTTPClient = server.Client()

	p := &Provider{logger: testLogger()}
	f, err := os.CreateTemp("", "enisa_threat_download_*.json")
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
	f, err := os.CreateTemp("", "enisa_threat_download_err_*.json")
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
	catalog := enisaCatalog{
		ThreatCategories: []enisaCategory{
			{ID: "MALWARE", Name: "Malware", Title: "Malware Attacks", Description: "Desc", Severity: "high"},
			{ID: "PHISHING", Name: "Phishing", Title: "Phishing Attacks", Description: "Desc 2", Severity: "high"},
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
	embeddedCount := len(p.generateEmbeddedTaxonomy())
	if count != embeddedCount {
		t.Errorf("expected %d embedded fallback controls, got %d", embeddedCount, count)
	}
}

func TestRunDownloadErrorFallback(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
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
	embeddedCount := len(p.generateEmbeddedTaxonomy())
	if count != embeddedCount {
		t.Errorf("expected %d embedded fallback controls, got %d", embeddedCount, count)
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

