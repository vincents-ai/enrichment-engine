package iso27001

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

func (m *mockBackend) ReadControl(ctx context.Context, id string) ([]byte, error) {
	return nil, nil
}

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

func (m *mockBackend) Close(ctx context.Context) error {
	return nil
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
	if got := p.Name(); got != "iso27001" {
		t.Errorf("Name() = %q, want %q", got, "iso27001")
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
	if count != 93 {
		t.Errorf("expected 93 controls written via fallback, got %d", count)
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
	catalog := iso27001Catalog{
		Groups: []iso27001Group{
			{
				ID:    "org",
				Title: "Organizational controls",
				Controls: []iso27001Control{
					{ID: "A.5.1", Number: "A.5.1", Title: "Policies for information security", Description: "Policies defined"},
					{ID: "A.5.2", Number: "A.5.2", Title: "Information security roles", Description: "Roles defined"},
				},
			},
			{
				ID:    "tech",
				Title: "Technological controls",
				Controls: []iso27001Control{
					{ID: "A.8.1", Number: "A.8.1", Title: "User endpoint devices", Description: "Devices protected"},
				},
			},
		},
	}
	data, _ := json.Marshal(catalog)
	f, err := os.CreateTemp("", "iso_test_groups_*.json")
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
	if controls[0].ControlID != "A.5.1" {
		t.Errorf("expected ControlID A.5.1, got %s", controls[0].ControlID)
	}
	if controls[0].Framework != FrameworkID {
		t.Errorf("expected Framework %s, got %s", FrameworkID, controls[0].Framework)
	}
	if controls[0].Family != "Organizational controls" {
		t.Errorf("expected Family from group title, got %s", controls[0].Family)
	}
}

func TestParseWithFlatControls(t *testing.T) {
	catalog := iso27001Catalog{
		Controls: []iso27001Control{
			{ID: "A.5.7", Number: "A.5.7", Title: "Threat intelligence", Description: "Collected", Theme: "Organizational controls"},
			{ID: "A.8.1", Number: "A.8.1", Title: "User endpoint devices", Description: "Protected", Theme: "Technological controls"},
		},
	}
	data, _ := json.Marshal(catalog)
	f, err := os.CreateTemp("", "iso_test_flat_*.json")
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
	if controls[0].Family != "Organizational controls" {
		t.Errorf("expected Family from theme for flat controls, got %s", controls[0].Family)
	}
}

func TestParseInvalidJSON(t *testing.T) {
	f, err := os.CreateTemp("", "iso_test_bad_*.json")
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

func TestToControl(t *testing.T) {
	p := &Provider{}
	ctrl := p.toControl(iso27001Control{
		ID:          "A.5.16",
		Number:      "A.5.16",
		Title:       "Identity management",
		Description: "Full life cycle managed",
	}, "Organizational controls")

	if ctrl.ControlID != "A.5.16" {
		t.Errorf("expected ControlID A.5.16, got %s", ctrl.ControlID)
	}
	if ctrl.Framework != FrameworkID {
		t.Errorf("expected Framework %s, got %s", FrameworkID, ctrl.Framework)
	}
	if ctrl.Family != "Organizational controls" {
		t.Errorf("expected Family 'Organizational controls', got %s", ctrl.Family)
	}
	if ctrl.Level != "standard" {
		t.Errorf("expected level 'standard', got %s", ctrl.Level)
	}
	if len(ctrl.RelatedCWEs) == 0 {
		t.Errorf("expected RelatedCWEs for A.5.16")
	}
}

func TestToControlWithPurpose(t *testing.T) {
	p := &Provider{}
	ctrl := p.toControl(iso27001Control{
		ID:      "A.5.1",
		Number:  "A.5.1",
		Title:   "Policies",
		Purpose: "Policies for info sec",
	}, "Organizational controls")

	if ctrl.Description != "Policies for info sec" {
		t.Errorf("expected description from purpose when description is empty, got %s", ctrl.Description)
	}
}

func TestToControlWithGuidance(t *testing.T) {
	p := &Provider{}
	ctrl := p.toControl(iso27001Control{
		ID:          "A.8.25",
		Number:      "A.8.25",
		Title:       "Secure development",
		Description: "Rules established",
		Guidance:    "Follow OWASP guidelines",
	}, "Technological controls")

	if !strings.Contains(ctrl.Description, "Guidance: Follow OWASP guidelines") {
		t.Errorf("expected guidance appended to description, got %s", ctrl.Description)
	}
}

func TestToControlDescriptionFallback(t *testing.T) {
	p := &Provider{}
	ctrl := p.toControl(iso27001Control{
		ID:       "A.5.1",
		Number:   "A.5.1",
		Title:    "Policies",
		Purpose:  "Purpose text",
		Guidance: "Guidance text",
	}, "Org")

	if !strings.HasPrefix(ctrl.Description, "Purpose text") {
		t.Errorf("expected description to start with purpose, got %s", ctrl.Description)
	}
	if !strings.Contains(ctrl.Description, "Guidance: Guidance text") {
		t.Errorf("expected guidance in description, got %s", ctrl.Description)
	}
}

func TestIsoCWEs(t *testing.T) {
	cwes := isoCWEs("A.5.16")
	if len(cwes) == 0 {
		t.Error("expected CWEs for control A.5.16")
	}
	cwes = isoCWEs("nonexistent")
	if len(cwes) != 0 {
		t.Error("expected no CWEs for nonexistent control")
	}
}

func TestEmbeddedControls(t *testing.T) {
	controls := embeddedControls()

	if len(controls) != 93 {
		t.Errorf("expected 93 embedded controls, got %d", len(controls))
	}

	families := make(map[string]int)
	for _, ctrl := range controls {
		families[ctrl.Family]++
	}

	if families["Organizational controls"] != 37 {
		t.Errorf("expected 37 Organizational controls, got %d", families["Organizational controls"])
	}
	if families["People controls"] != 8 {
		t.Errorf("expected 8 People controls, got %d", families["People controls"])
	}
	if families["Physical controls"] != 14 {
		t.Errorf("expected 14 Physical controls, got %d", families["Physical controls"])
	}
	if families["Technological controls"] != 34 {
		t.Errorf("expected 34 Technological controls, got %d", families["Technological controls"])
	}

	if controls[0].ControlID != "A.5.1" {
		t.Errorf("expected first control A.5.1, got %s", controls[0].ControlID)
	}
	if controls[0].Framework != "ISO_27001_2022" {
		t.Errorf("expected Framework ISO_27001_2022, got %s", controls[0].Framework)
	}
	if controls[0].Level != "standard" {
		t.Errorf("expected Level standard, got %s", controls[0].Level)
	}

	last := controls[len(controls)-1]
	if last.ControlID != "A.8.34" {
		t.Errorf("expected last control A.8.34, got %s", last.ControlID)
	}
}

func TestProviderWriteEmbeddedControls(t *testing.T) {
	backend := &mockBackend{}
	p := &Provider{
		store:  backend,
		logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn})),
	}

	count, err := p.writeEmbeddedControls(context.Background())
	if err != nil {
		t.Fatalf("writeEmbeddedControls failed: %v", err)
	}

	if count != 93 {
		t.Errorf("expected 93 controls written, got %d", count)
	}

	if len(backend.controls) != 93 {
		t.Errorf("expected 93 controls in backend, got %d", len(backend.controls))
	}
}

func TestProviderName(t *testing.T) {
	p := &Provider{}
	if got := p.Name(); got != "iso27001" {
		t.Errorf("Name() = %q, want %q", got, "iso27001")
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
		t.Errorf("expected some ISO 27001 controls to have RelatedCWEs populated, got 0")
	}
}

func TestEmbeddedControlsStoredCorrectly(t *testing.T) {
	backend := &mockBackend{}
	p := &Provider{store: backend, logger: testLogger()}
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
	catalog := iso27001Catalog{
		Groups: []iso27001Group{
			{
				ID:    "org",
				Title: "Organizational controls",
				Controls: []iso27001Control{
					{ID: "A.5.1", Number: "A.5.1", Title: "Policies", Description: "Policies defined"},
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
	f, err := os.CreateTemp("", "iso_download_*.json")
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
	f, err := os.CreateTemp("", "iso_download_err_*.json")
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
	catalog := iso27001Catalog{
		Groups: []iso27001Group{
			{
				ID:    "org",
				Title: "Organizational controls",
				Controls: []iso27001Control{
					{ID: "A.5.1", Number: "A.5.1", Title: "Policies", Description: "Policies defined"},
					{ID: "A.5.7", Number: "A.5.7", Title: "Threat intel", Description: "Collected"},
				},
			},
			{
				ID:    "tech",
				Title: "Technological controls",
				Controls: []iso27001Control{
					{ID: "A.8.1", Number: "A.8.1", Title: "Endpoints", Description: "Protected"},
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
	if count != 3 {
		t.Errorf("expected 3 controls from pipeline, got %d", count)
	}
	if len(backend.controls) != 3 {
		t.Errorf("expected 3 controls in backend, got %d", len(backend.controls))
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
	if count != 93 {
		t.Errorf("expected 93 embedded fallback controls, got %d", count)
	}
}

func TestRunDownloadSuccessWriteError(t *testing.T) {
	catalog := iso27001Catalog{
		Groups: []iso27001Group{
			{
				ID:    "org",
				Title: "Organizational controls",
				Controls: []iso27001Control{
					{ID: "A.5.1", Number: "A.5.1", Title: "Policies", Description: "Policies defined"},
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

