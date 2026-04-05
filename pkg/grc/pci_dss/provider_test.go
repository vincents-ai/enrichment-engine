package pci_dss

import (
	"context"
	"encoding/json"
	"fmt"
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
func (f *failWriteBackend) Close(ctx context.Context) error { return nil }

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestNew(t *testing.T) {
	p := New(nil, nil)
	if p == nil {
		t.Fatal("New() returned nil")
	}
	if got := p.Name(); got != "pci_dss" {
		t.Errorf("Name() = %q, want %q", got, "pci_dss")
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
	catalog := pciCatalog{
		Groups: []pciGroup{
			{
				ID:          "req1",
				Requirement: "Requirement 1",
				Title:       "Install and Maintain Network Security Controls",
				Controls: []pciControl{
					{ID: "1.1", Title: "Network security controls defined", Description: "NSCs are defined", Requirement: "Req 1", Level: "STANDARD"},
					{ID: "1.2", Title: "Network segmentation", Description: "CDE isolated", Requirement: "Req 1"},
				},
			},
			{
				ID:          "req2",
				Requirement: "Requirement 2",
				Title:       "Apply Secure Configuration",
				Controls: []pciControl{
					{ID: "2.1", Title: "Vendor defaults changed", Description: "Defaults changed", Requirement: "Req 2", Level: "ADVANCED"},
				},
			},
		},
	}
	data, _ := json.Marshal(catalog)
	f, err := os.CreateTemp("", "pci_test_groups_*.json")
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

	if controls[0].ControlID != "1.1" {
		t.Errorf("expected ControlID 1.1, got %s", controls[0].ControlID)
	}
	if controls[0].Framework != FrameworkID {
		t.Errorf("expected Framework %s, got %s", FrameworkID, controls[0].Framework)
	}
	if controls[0].Family != "Install and Maintain Network Security Controls" {
		t.Errorf("expected Family from group title, got %s", controls[0].Family)
	}
	if controls[0].Level != "standard" {
		t.Errorf("expected level 'standard', got %s", controls[0].Level)
	}
	if controls[2].Level != "advanced" {
		t.Errorf("expected level 'advanced', got %s", controls[2].Level)
	}
	if len(controls[0].References) != 1 || controls[0].References[0].Source != "PCI DSS v4.0" {
		t.Errorf("expected reference source 'PCI DSS v4.0', got %v", controls[0].References)
	}
}

func TestParseWithFlatControls(t *testing.T) {
	catalog := pciCatalog{
		Controls: []pciControl{
			{ID: "1.1", Title: "Network security controls defined", Description: "NSCs defined", Requirement: "Req 1"},
			{ID: "2.1", Title: "Vendor defaults changed", Description: "Defaults changed", Requirement: "Req 2"},
		},
	}
	data, _ := json.Marshal(catalog)
	f, err := os.CreateTemp("", "pci_test_flat_*.json")
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
	if controls[0].Family != "Req 1" {
		t.Errorf("expected Family from requirement for flat controls, got %s", controls[0].Family)
	}
}

func TestParseInvalidJSON(t *testing.T) {
	f, err := os.CreateTemp("", "pci_test_bad_*.json")
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
	ctrl := p.toControl(pciControl{
		ID:          "6.4",
		Title:       "Public-facing web application protection",
		Description: "Protect against known attacks",
		Requirement: "Requirement 6",
		Level:       "STANDARD",
	}, "Develop and Maintain Secure Systems and Software", "Requirement 6")

	if ctrl.ControlID != "6.4" {
		t.Errorf("expected ControlID 6.4, got %s", ctrl.ControlID)
	}
	if ctrl.Framework != FrameworkID {
		t.Errorf("expected Framework %s, got %s", FrameworkID, ctrl.Framework)
	}
	if ctrl.Family != "Develop and Maintain Secure Systems and Software" {
		t.Errorf("expected Family from parameter, got %s", ctrl.Family)
	}
	if ctrl.Level != "standard" {
		t.Errorf("expected level 'standard', got %s", ctrl.Level)
	}
	if len(ctrl.RelatedCWEs) == 0 {
		t.Errorf("expected RelatedCWEs for 6.4")
	}
	if len(ctrl.References) != 1 || ctrl.References[0].Section != "Requirement 6" {
		t.Errorf("expected reference section 'Requirement 6', got %v", ctrl.References)
	}
}

func TestToControlNoLevel(t *testing.T) {
	p := &Provider{}
	ctrl := p.toControl(pciControl{
		ID:    "1.1",
		Title: "Network controls",
	}, "Network Security", "Req 1")

	if ctrl.Level != "standard" {
		t.Errorf("expected default level 'standard', got %s", ctrl.Level)
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
	if got := p.Name(); got != "pci_dss" {
		t.Errorf("Name() = %q, want %q", got, "pci_dss")
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
		t.Errorf("expected some PCI DSS controls to have RelatedCWEs populated, got 0")
	}
}

func TestEmbeddedControlsHaveReferences(t *testing.T) {
	controls := embeddedControls()
	for _, ctrl := range controls {
		if len(ctrl.References) == 0 {
			t.Errorf("control %s has no references", ctrl.ControlID)
			continue
		}
		if ctrl.References[0].Source != "PCI DSS v4.0" {
			t.Errorf("control %s expected reference source 'PCI DSS v4.0', got %s", ctrl.ControlID, ctrl.References[0].Source)
		}
	}
}

func TestPciCWEs(t *testing.T) {
	cwes := pciCWEs("1.1")
	if len(cwes) == 0 {
		t.Error("expected CWEs for control 1.1")
	}
	cwes = pciCWEs("nonexistent")
	if len(cwes) != 0 {
		t.Error("expected no CWEs for nonexistent control")
	}
}

func TestParseWriteToStorage(t *testing.T) {
	catalog := pciCatalog{
		Groups: []pciGroup{
			{
				ID:          "req1",
				Requirement: "Requirement 1",
				Title:       "Network Security Controls",
				Controls: []pciControl{
					{ID: "1.1", Title: "Network controls defined", Requirement: "Req 1"},
				},
			},
		},
	}
	data, _ := json.Marshal(catalog)
	f, err := os.CreateTemp("", "pci_test_write_*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.Write(data)
	f.Close()

	backend := &mockBackend{}
	p := &Provider{store: backend, logger: testLogger()}
	controls, err := p.parse(f.Name())
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	ctx := context.Background()
	count := 0
	for _, ctrl := range controls {
		id := fmt.Sprintf("%s/%s", FrameworkID, ctrl.ControlID)
		if err := p.store.WriteControl(ctx, id, ctrl); err != nil {
			t.Errorf("WriteControl failed: %v", err)
		}
		count++
	}
	if count != 1 {
		t.Errorf("expected 1 control written, got %d", count)
	}
	if len(backend.controls) != 1 {
		t.Errorf("expected 1 control in backend, got %d", len(backend.controls))
	}
}

func TestDownloadSuccess(t *testing.T) {
	catalog := pciCatalog{
		Groups: []pciGroup{
			{
				ID:          "req1",
				Requirement: "Req 1",
				Title:       "Network Controls",
				Controls: []pciControl{
					{ID: "1.1", Title: "Controls defined", Requirement: "Req 1"},
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
	f, err := os.CreateTemp("", "pci_download_*.json")
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
	f, err := os.CreateTemp("", "pci_download_err_*.json")
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
	catalog := pciCatalog{
		Groups: []pciGroup{
			{
				ID:          "req1",
				Requirement: "Req 1",
				Title:       "Network Controls",
				Controls: []pciControl{
					{ID: "1.1", Title: "Controls defined", Requirement: "Req 1"},
					{ID: "1.2", Title: "Segmentation", Requirement: "Req 1"},
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
		t.Errorf("expected 2 controls from download, got %d", count)
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
	catalog := pciCatalog{
		Groups: []pciGroup{
			{
				ID:          "req1",
				Requirement: "Req 1",
				Title:       "Network Controls",
				Controls: []pciControl{
					{ID: "1.1", Title: "Controls defined", Requirement: "Req 1"},
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

