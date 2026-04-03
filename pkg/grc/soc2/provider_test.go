package soc2

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
func (f *failWriteBackend) Close(ctx context.Context) error { return nil }

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestNew(t *testing.T) {
	p := New(nil, nil)
	if p == nil {
		t.Fatal("New() returned nil")
	}
	if got := p.Name(); got != "soc2" {
		t.Errorf("Name() = %q, want %q", got, "soc2")
	}
}

func TestRunWithFallback(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	backend := &mockBackend{}
	p := New(backend, testLogger())

	count, err := p.Run(ctx)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if count < 5 {
		t.Errorf("expected at least 5 controls written via fallback, got %d", count)
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
		t.Errorf("expected 0 controls written on write error, got %d", count)
	}
}

func TestParseWithGroups(t *testing.T) {
	catalog := soc2Catalog{
		Groups: []soc2Group{
			{
				ID:    "security",
				Title: "Security",
				Criteria: []soc2Criterion{
					{ID: "cc6.1", ControlID: "CC6.1", Title: "Logical Access Security", Description: "Implements logical access security", Category: "Security"},
					{ID: "cc6.2", ControlID: "CC6.2", Title: "User Registration", Description: "Registers users", Category: "Security"},
				},
			},
			{
				ID:    "availability",
				Title: "Availability",
				Criteria: []soc2Criterion{
					{ID: "a1.1", ControlID: "A1.1", Title: "Capacity Planning", Description: "Maintains capacity", Category: "Availability"},
				},
			},
		},
	}
	data, _ := json.Marshal(catalog)
	f, err := os.CreateTemp("", "soc2_test_groups_*.json")
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
	if controls[0].ControlID != "CC6.1" {
		t.Errorf("expected ControlID CC6.1, got %s", controls[0].ControlID)
	}
	if controls[0].Framework != FrameworkID {
		t.Errorf("expected Framework %s, got %s", FrameworkID, controls[0].Framework)
	}
	if controls[0].Family != "Security" {
		t.Errorf("expected Family from group title, got %s", controls[0].Family)
	}
	if controls[2].Family != "Availability" {
		t.Errorf("expected Family 'Availability', got %s", controls[2].Family)
	}
}

func TestParseWithFlatControls(t *testing.T) {
	catalog := soc2Catalog{
		Criteria: []soc2Criterion{
			{ID: "a1.1", ControlID: "A1.1", Title: "Capacity Planning", Description: "Maintains capacity"},
			{ID: "pi1.1", ControlID: "PI1.1", Title: "Data Completeness", Description: "Complete data"},
			{ID: "c1.1", ControlID: "C1.1", Title: "Identify Confidential Info", Description: "Identifies"},
			{ID: "p1.1", ControlID: "P1.1", Title: "Privacy Notice", Description: "Provides notice"},
			{ID: "cc6.1", ControlID: "CC6.1", Title: "Logical Access", Description: "Access controls"},
		},
	}
	data, _ := json.Marshal(catalog)
	f, err := os.CreateTemp("", "soc2_test_flat_*.json")
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
	if len(controls) != 5 {
		t.Fatalf("expected 5 controls, got %d", len(controls))
	}

	families := map[string]string{
		"A1.1":  "Availability",
		"PI1.1": "Processing Integrity",
		"C1.1":  "Confidentiality",
		"P1.1":  "Privacy",
		"CC6.1": "Security",
	}
	for _, ctrl := range controls {
		want, ok := families[ctrl.ControlID]
		if !ok {
			continue
		}
		if ctrl.Family != want {
			t.Errorf("control %s: expected Family %q (inferred), got %q", ctrl.ControlID, want, ctrl.Family)
		}
	}
}

func TestParseInvalidJSON(t *testing.T) {
	f, err := os.CreateTemp("", "soc2_test_bad_*.json")
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

func TestInferFamily(t *testing.T) {
	p := &Provider{}
	tests := []struct {
		id   string
		want string
	}{
		{"A1.1", "Availability"},
		{"A1.2", "Availability"},
		{"PI1.1", "Processing Integrity"},
		{"PI1.2", "Processing Integrity"},
		{"C1.1", "Confidentiality"},
		{"C1.2", "Confidentiality"},
		{"P1.1", "Privacy"},
		{"P2.1", "Privacy"},
		{"CC6.1", "Security"},
		{"CC1.1", "Security"},
		{"X9.9", "Security"},
	}
	for _, tt := range tests {
		got := p.inferFamily(tt.id)
		if got != tt.want {
			t.Errorf("inferFamily(%q) = %q, want %q", tt.id, got, tt.want)
		}
	}
}

func TestToControl(t *testing.T) {
	p := &Provider{}
	ctrl := p.toControl(soc2Criterion{
		ID:          "cc6.1",
		ControlID:   "CC6.1",
		Title:       "Logical Access Security",
		Description: "  Implements logical access security  ",
	}, "Security")

	if ctrl.ControlID != "CC6.1" {
		t.Errorf("expected ControlID CC6.1, got %s", ctrl.ControlID)
	}
	if ctrl.Framework != FrameworkID {
		t.Errorf("expected Framework %s, got %s", FrameworkID, ctrl.Framework)
	}
	if ctrl.Family != "Security" {
		t.Errorf("expected Family 'Security', got %s", ctrl.Family)
	}
	if ctrl.Description != "Implements logical access security" {
		t.Errorf("expected trimmed description, got %q", ctrl.Description)
	}
	if ctrl.Level != "standard" {
		t.Errorf("expected level 'standard', got %s", ctrl.Level)
	}
}

func TestSoc2CWEs(t *testing.T) {
	cwes := soc2CWEs("CC6.1")
	if len(cwes) == 0 {
		t.Error("expected CWEs for control CC6.1")
	}
	cwes = soc2CWEs("nonexistent")
	if len(cwes) != 0 {
		t.Error("expected no CWEs for nonexistent control")
	}
}

func TestEmbeddedControls(t *testing.T) {
	controls := embeddedControls()
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

func TestEmbeddedControlsFamilies(t *testing.T) {
	controls := embeddedControls()
	families := make(map[string]int)
	for _, ctrl := range controls {
		families[ctrl.Family]++
	}
	expected := map[string]bool{
		"Security":             true,
		"Availability":         true,
		"Processing Integrity": true,
		"Confidentiality":      true,
		"Privacy":              true,
	}
	for family := range expected {
		if families[family] == 0 {
			t.Errorf("expected family %q to be present", family)
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

func TestProviderName(t *testing.T) {
	p := &Provider{}
	if got := p.Name(); got != "soc2" {
		t.Errorf("Name() = %q, want %q", got, "soc2")
	}
}

func TestRelatedCWEsPopulated(t *testing.T) {
	controls := embeddedControls()
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
		t.Errorf("expected some SOC 2 controls to have RelatedCWEs populated, got 0")
	}
}

func TestEmbeddedControlsStoredCorrectly(t *testing.T) {
	backend := &mockBackend{}
	p := New(backend, testLogger())
	p.writeEmbeddedControls(context.Background())

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

func TestDownloadSuccess(t *testing.T) {
	catalog := soc2Catalog{
		Groups: []soc2Group{
			{
				ID:    "security",
				Title: "Security",
				Criteria: []soc2Criterion{
					{ID: "cc6.1", ControlID: "CC6.1", Title: "Logical Access", Description: "Access security"},
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
	f, err := os.CreateTemp("", "soc2_download_*.json")
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
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	origClient := grc.HTTPClient
	defer func() { grc.HTTPClient = origClient }()
	grc.HTTPClient = server.Client()

	p := &Provider{logger: testLogger()}
	f, err := os.CreateTemp("", "soc2_download_err_*.json")
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

func TestDownloadAndParsePipeline(t *testing.T) {
	catalog := soc2Catalog{
		Groups: []soc2Group{
			{
				ID:    "security",
				Title: "Security",
				Criteria: []soc2Criterion{
					{ID: "cc6.1", ControlID: "CC6.1", Title: "Logical Access", Description: "Access security"},
					{ID: "cc7.1", ControlID: "CC7.1", Title: "Detection", Description: "Monitoring"},
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
	if count < 5 {
		t.Errorf("expected embedded fallback controls, got %d", count)
	}
}

func TestRunDownloadSuccessWriteError(t *testing.T) {
	catalog := soc2Catalog{
		Groups: []soc2Group{
			{
				ID:    "security",
				Title: "Security",
				Criteria: []soc2Criterion{
					{ID: "cc6.1", ControlID: "CC6.1", Title: "Logical Access", Description: "Access security"},
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

	p := New(&failWriteBackend{}, testLogger())
	count, err := p.Run(context.Background())
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 controls on write error, got %d", count)
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

