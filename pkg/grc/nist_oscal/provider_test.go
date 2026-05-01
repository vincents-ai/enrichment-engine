package nist_oscal

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/vincents-ai/enrichment-engine/pkg/grc"
	"github.com/vincents-ai/enrichment-engine/pkg/storage"
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
	if got := p.Name(); got != "nist_oscal" {
		t.Errorf("Name() = %q, want %q", got, "nist_oscal")
	}
}

func TestProviderName(t *testing.T) {
	p := &Provider{}
	if got := p.Name(); got != "nist_oscal" {
		t.Errorf("Name() = %q, want %q", got, "nist_oscal")
	}
}

func TestRunCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	backend := &mockBackend{}
	p := New(backend, testLogger())

	_, err := p.Run(ctx)
	if err == nil {
		t.Fatal("expected error for cancelled context, got nil")
	}
}

func TestRunWithWriteError(t *testing.T) {
	catalog := buildTestOSCALCatalog()
	body, _ := json.Marshal(catalog)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	defer server.Close()

	origClient := grc.HTTPClient
	origURL := NISTCatalogURL
	defer func() {
		grc.HTTPClient = origClient
		NISTCatalogURL = origURL
	}()
	grc.HTTPClient = server.Client()
	NISTCatalogURL = server.URL

	p := New(&failWriteBackend{}, testLogger())
	count, err := p.Run(context.Background())
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 controls on write error, got %d", count)
	}
}

func TestParse(t *testing.T) {
	catalog := buildTestOSCALCatalog()
	data, _ := json.Marshal(catalog)
	f, err := os.CreateTemp("", "nist_oscal_test_*.json")
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
	if len(controls) != 2 {
		t.Fatalf("expected 2 controls, got %d", len(controls))
	}
	if controls[0].ControlID != "AC-1" {
		t.Errorf("expected ControlID AC-1, got %s", controls[0].ControlID)
	}
	if controls[0].Framework != FrameworkID {
		t.Errorf("expected Framework %s, got %s", FrameworkID, controls[0].Framework)
	}
	if controls[0].Family != "Access Control" {
		t.Errorf("expected Family 'Access Control', got %s", controls[0].Family)
	}
	if controls[0].Level != "standard" {
		t.Errorf("expected Level 'standard', got %s", controls[0].Level)
	}
	if controls[1].ControlID != "AU-1" {
		t.Errorf("expected ControlID AU-1, got %s", controls[1].ControlID)
	}
}

func TestParseInvalidJSON(t *testing.T) {
	f, err := os.CreateTemp("", "nist_oscal_bad_*.json")
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

func TestParseNestedGroups(t *testing.T) {
	catalog := oscalCatalog{}
	catalog.Catalog.Metadata.Title = "NIST SP 800-53"
	catalog.Catalog.Groups = []oscalGroup{
		{
			ID:    "AC",
			Title: "Access Control",
			Controls: []oscalControl{
				{ID: "AC-1", Title: "Policy and Procedures", Class: "moderate"},
			},
			Groups: []oscalGroup{
				{
					ID:    "AC-2",
					Title: "Account Management",
					Controls: []oscalControl{
						{ID: "AC-2", Title: "Account Management Control", Class: "high"},
					},
				},
			},
		},
	}
	data, _ := json.Marshal(catalog)
	f, err := os.CreateTemp("", "nist_oscal_nested_*.json")
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
	if len(controls) != 2 {
		t.Fatalf("expected 2 controls from nested groups, got %d", len(controls))
	}
	if controls[0].Family != "Access Control" {
		t.Errorf("expected parent group title, got %s", controls[0].Family)
	}
	if controls[1].Family != "Account Management" {
		t.Errorf("expected sub-group title, got %s", controls[1].Family)
	}
}

func TestExtractControls(t *testing.T) {
	p := &Provider{}
	group := oscalGroup{
		ID:    "AC",
		Title: "Access Control",
		Controls: []oscalControl{
			{ID: "AC-1", Title: "Policy", Class: "critical"},
			{ID: "AC-2", Title: "Account Mgmt", Class: "high"},
			{ID: "AC-3", Title: "Enforcement", Class: "moderate"},
			{ID: "AC-4", Title: "Info Flow", Class: ""},
		},
	}

	controls := p.extractControls(group)
	if len(controls) != 4 {
		t.Fatalf("expected 4 controls, got %d", len(controls))
	}
	if controls[0].Level != "critical" {
		t.Errorf("expected level 'critical', got %s", controls[0].Level)
	}
	if controls[1].Level != "high" {
		t.Errorf("expected level 'high', got %s", controls[1].Level)
	}
	if controls[2].Level != "standard" {
		t.Errorf("expected level 'standard' for moderate, got %s", controls[2].Level)
	}
	if controls[3].Level != "standard" {
		t.Errorf("expected level 'standard' for empty, got %s", controls[3].Level)
	}
}

func TestExtractControlsWithProps(t *testing.T) {
	p := &Provider{}
	group := oscalGroup{
		ID:    "SC",
		Title: "System and Communications",
		Controls: []oscalControl{
			{
				ID:    "SC-7",
				Title: "Boundary Protection",
				Class: "high",
				Props: []struct {
					Name  string `json:"name"`
					Value string `json:"value"`
				}{
					{Name: "cwe", Value: "CWE-284"},
					{Name: "cwe", Value: "CWE-863"},
					{Name: "other", Value: "ignored"},
				},
			},
		},
	}

	controls := p.extractControls(group)
	if len(controls) != 1 {
		t.Fatalf("expected 1 control, got %d", len(controls))
	}
	if len(controls[0].RelatedCWEs) != 2 {
		t.Errorf("expected 2 CWEs, got %d", len(controls[0].RelatedCWEs))
	}
	if controls[0].RelatedCWEs[0] != "CWE-284" {
		t.Errorf("expected CWE-284, got %s", controls[0].RelatedCWEs[0])
	}
}

func TestExtractProse(t *testing.T) {
	p := &Provider{}

	parts := []oscalPart{
		{Name: "guidance", Prose: "Follow guidance"},
		{Name: "statement", Prose: "The organization implements AC-1."},
		{Name: "assessment-objective", Prose: "Determine if policy exists"},
	}

	result := p.extractProse(parts)
	if result != "The organization implements AC-1." {
		t.Errorf("expected statement prose, got %q", result)
	}
}

func TestExtractProseEmpty(t *testing.T) {
	p := &Provider{}
	result := p.extractProse(nil)
	if result != "" {
		t.Errorf("expected empty string, got %q", result)
	}
	parts := []oscalPart{{Name: "guidance", Prose: "some guidance"}}
	result = p.extractProse(parts)
	if result != "" {
		t.Errorf("expected empty string when no statement, got %q", result)
	}
}

func TestExtractGuidance(t *testing.T) {
	p := &Provider{}
	parts := []oscalPart{
		{Name: "statement", Prose: "Statement prose"},
		{Name: "guidance", Prose: "Implement controls properly"},
	}

	result := p.extractGuidance(parts)
	if result != "Implement controls properly" {
		t.Errorf("expected guidance prose, got %q", result)
	}
}

func TestExtractGuidanceEmpty(t *testing.T) {
	p := &Provider{}
	result := p.extractGuidance(nil)
	if result != "" {
		t.Errorf("expected empty string, got %q", result)
	}
}

func TestExtractAssessmentMethods(t *testing.T) {
	p := &Provider{}
	parts := []oscalPart{
		{Name: "assessment-objective", Prose: "Determine policy exists"},
		{Name: "assessment-objective", Prose: "Verify enforcement"},
		{Name: "statement", Prose: "The org does X"},
	}

	methods := p.extractAssessmentMethods(parts)
	if len(methods) != 2 {
		t.Fatalf("expected 2 assessment methods, got %d", len(methods))
	}
	if methods[0] != "Determine policy exists" {
		t.Errorf("unexpected method: %s", methods[0])
	}
}

func TestExtractAssessmentMethodsEmpty(t *testing.T) {
	p := &Provider{}
	methods := p.extractAssessmentMethods(nil)
	if len(methods) != 0 {
		t.Errorf("expected 0 methods, got %d", len(methods))
	}
}

func TestDownloadSuccess(t *testing.T) {
	catalog := buildTestOSCALCatalog()
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
	f, err := os.CreateTemp("", "nist_download_*.json")
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
	f, err := os.CreateTemp("", "nist_download_err_*.json")
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
	catalog := buildTestOSCALCatalog()
	body, _ := json.Marshal(catalog)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	defer server.Close()

	origClient := grc.HTTPClient
	origURL := NISTCatalogURL
	defer func() {
		grc.HTTPClient = origClient
		NISTCatalogURL = origURL
	}()
	grc.HTTPClient = server.Client()
	NISTCatalogURL = server.URL

	backend := &mockBackend{}
	p := New(backend, testLogger())
	count, err := p.Run(context.Background())
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if count != 2 {
		t.Errorf("expected 2 controls, got %d", count)
	}
	if len(backend.controls) != 2 {
		t.Errorf("expected 2 controls in backend, got %d", len(backend.controls))
	}
}

func TestRunDownloadError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	origURL := NISTCatalogURL
	defer func() { NISTCatalogURL = origURL }()
	NISTCatalogURL = "http://127.0.0.1:0/unreachable"

	backend := &mockBackend{}
	p := New(backend, testLogger())
	_, err := p.Run(ctx)
	if err == nil {
		t.Fatal("expected error for download failure, got nil")
	}
}

func TestRunParseError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("invalid json"))
	}))
	defer server.Close()

	origClient := grc.HTTPClient
	origURL := NISTCatalogURL
	defer func() {
		grc.HTTPClient = origClient
		NISTCatalogURL = origURL
	}()
	grc.HTTPClient = server.Client()
	NISTCatalogURL = server.URL

	backend := &mockBackend{}
	p := New(backend, testLogger())
	_, err := p.Run(context.Background())
	if err == nil {
		t.Fatal("expected error for parse failure, got nil")
	}
}

func buildTestOSCALCatalog() oscalCatalog {
	catalog := oscalCatalog{}
	catalog.Catalog.UUID = "test-uuid"
	catalog.Catalog.Metadata.Title = "NIST SP 800-53"
	catalog.Catalog.Groups = []oscalGroup{
		{
			ID:    "AC",
			Class: "family",
			Title: "Access Control",
			Controls: []oscalControl{
				{
					ID:    "AC-1",
					Class: "moderate",
					Title: "Policy and Procedures",
					Parts: []oscalPart{
						{Name: "statement", Prose: "The organization implements access control policy."},
					},
				},
			},
		},
		{
			ID:    "AU",
			Class: "family",
			Title: "Audit and Accountability",
			Controls: []oscalControl{
				{
					ID:    "AU-1",
					Class: "moderate",
					Title: "Audit and Accountability Policy",
					Parts: []oscalPart{
						{Name: "statement", Prose: "The organization implements audit policy."},
					},
				},
			},
		},
	}
	return catalog
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

