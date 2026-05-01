package nist_csf

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
	if got := p.Name(); got != "nist_csf" {
		t.Errorf("Name() = %q, want %q", got, "nist_csf")
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

func TestParseWithFunctions(t *testing.T) {
	catalog := csfCatalog{
		Functions: []csfFunction{
			{
				ID:   "ID",
				Name: "Identify",
				Categories: []csfCategory{
					{
						ID:   "ID.RA",
						Name: "Risk Assessment",
						Subcategories: []csfSubcategory{
							{ID: "ID.RA-01", Description: "Vulnerabilities identified"},
							{ID: "ID.RA-02", Description: "Threat intelligence", Level: "TIER2"},
						},
					},
				},
			},
			{
				ID:   "PR",
				Name: "Protect",
				Categories: []csfCategory{
					{
						ID:   "PR.AA",
						Name: "Identity Management",
						Subcategories: []csfSubcategory{
							{ID: "PR.AA-01", Description: "Identities issued"},
						},
					},
				},
			},
		},
	}
	data, _ := json.Marshal(catalog)
	f, err := os.CreateTemp("", "nist_test_funcs_*.json")
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
	if controls[0].ControlID != "ID.RA-01" {
		t.Errorf("expected ControlID ID.RA-01, got %s", controls[0].ControlID)
	}
	if controls[0].Framework != FrameworkID {
		t.Errorf("expected Framework %s, got %s", FrameworkID, controls[0].Framework)
	}
	if controls[0].Family != "Identify - Risk Assessment" {
		t.Errorf("expected Family 'Identify - Risk Assessment', got %s", controls[0].Family)
	}
	if controls[1].Level != "tier2" {
		t.Errorf("expected level 'tier2', got %s", controls[1].Level)
	}
	if controls[0].Level != "standard" {
		t.Errorf("expected default level 'standard', got %s", controls[0].Level)
	}
}

func TestParseEmptyFunctions(t *testing.T) {
	catalog := csfCatalog{Functions: []csfFunction{}}
	data, _ := json.Marshal(catalog)
	f, err := os.CreateTemp("", "nist_test_empty_*.json")
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
		t.Errorf("expected 0 controls for empty catalog, got %d", len(controls))
	}
}

func TestParseInvalidJSON(t *testing.T) {
	f, err := os.CreateTemp("", "nist_test_bad_*.json")
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

func TestToSubcategory(t *testing.T) {
	p := &Provider{}
	ctrl := p.toSubcategory(csfSubcategory{
		ID:          "PR.AA-01",
		Description: "Identities and credentials issued",
		Level:       "",
	}, "Protect", "Identity Management and Access Control", "PR")

	if ctrl.ControlID != "PR.AA-01" {
		t.Errorf("expected ControlID PR.AA-01, got %s", ctrl.ControlID)
	}
	if ctrl.Framework != FrameworkID {
		t.Errorf("expected Framework %s, got %s", FrameworkID, ctrl.Framework)
	}
	if ctrl.Family != "Protect - Identity Management and Access Control" {
		t.Errorf("expected Family 'Protect - Identity Management and Access Control', got %s", ctrl.Family)
	}
	if ctrl.Title != "Identities and credentials issued" {
		t.Errorf("expected Title from description, got %s", ctrl.Title)
	}
	if ctrl.Level != "standard" {
		t.Errorf("expected default level 'standard', got %s", ctrl.Level)
	}
	if len(ctrl.RelatedCWEs) == 0 {
		t.Errorf("expected RelatedCWEs for PR.AA-01")
	}
	if len(ctrl.References) != 1 || ctrl.References[0].Source != "NIST Cybersecurity Framework 2.0" {
		t.Errorf("expected reference source 'NIST Cybersecurity Framework 2.0', got %v", ctrl.References)
	}
	if ctrl.References[0].Section != "PR.PR.AA-01" {
		t.Errorf("expected reference section 'PR.PR.AA-01', got %s", ctrl.References[0].Section)
	}
}

func TestToSubcategoryWithLevel(t *testing.T) {
	p := &Provider{}
	ctrl := p.toSubcategory(csfSubcategory{
		ID:          "DE.CM-01",
		Description: "Network monitoring",
		Level:       "TIER3",
	}, "Detect", "Security Continuous Monitoring", "DE")

	if ctrl.Level != "tier3" {
		t.Errorf("expected level 'tier3', got %s", ctrl.Level)
	}
}

func TestNistCsfCWEs(t *testing.T) {
	cwes := nistCsfCWEs("PR.AA-01")
	if len(cwes) == 0 {
		t.Error("expected CWEs for control PR.AA-01")
	}
	cwes = nistCsfCWEs("nonexistent")
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
	expected := []string{"Govern", "Identify", "Protect", "Detect", "Respond", "Recover"}
	for _, family := range expected {
		if families[family] == 0 {
			t.Errorf("expected family %q to be present", family)
		}
	}
}

func TestEmbeddedControlsReferences(t *testing.T) {
	controls := embeddedControls()
	for _, ctrl := range controls {
		if len(ctrl.References) == 0 {
			t.Errorf("control %s has no references", ctrl.ControlID)
			continue
		}
		if ctrl.References[0].Source != "NIST Cybersecurity Framework 2.0" {
			t.Errorf("control %s expected reference source 'NIST Cybersecurity Framework 2.0', got %s", ctrl.ControlID, ctrl.References[0].Source)
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
	if got := p.Name(); got != "nist_csf" {
		t.Errorf("Name() = %q, want %q", got, "nist_csf")
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
		t.Errorf("expected some NIST CSF controls to have RelatedCWEs populated, got 0")
	}

	cweMap := make(map[string][]string)
	for _, ctrl := range controls {
		if len(ctrl.RelatedCWEs) > 0 {
			cweMap[ctrl.ControlID] = ctrl.RelatedCWEs
		}
	}
	if cwes, ok := cweMap["PR.AA-03"]; !ok || len(cwes) == 0 {
		t.Errorf("expected PR.AA-03 to have RelatedCWEs")
	}
	if cwes, ok := cweMap["PR.IR-01"]; !ok || len(cwes) == 0 {
		t.Errorf("expected PR.IR-01 to have RelatedCWEs")
	}
	if cwes, ok := cweMap["DE.CM-01"]; !ok || len(cwes) == 0 {
		t.Errorf("expected DE.CM-01 to have RelatedCWEs")
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
	catalog := csfCatalog{
		Functions: []csfFunction{
			{
				ID:   "ID",
				Name: "Identify",
				Categories: []csfCategory{
					{
						ID:   "ID.RA",
						Name: "Risk Assessment",
						Subcategories: []csfSubcategory{
							{ID: "ID.RA-01", Description: "Vulnerabilities identified"},
						},
					},
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
		w.WriteHeader(http.StatusBadGateway)
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

func TestDownloadAndParsePipeline(t *testing.T) {
	catalog := csfCatalog{
		Functions: []csfFunction{
			{
				ID:   "PR",
				Name: "Protect",
				Categories: []csfCategory{
					{
						ID:   "PR.AA",
						Name: "Identity Management",
						Subcategories: []csfSubcategory{
							{ID: "PR.AA-01", Description: "Identities issued"},
							{ID: "PR.AA-05", Description: "Access permissions managed"},
						},
					},
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
	catalog := csfCatalog{
		Functions: []csfFunction{
			{
				ID:   "ID",
				Name: "Identify",
				Categories: []csfCategory{
					{
						ID:   "ID.RA",
						Name: "Risk Assessment",
						Subcategories: []csfSubcategory{
							{ID: "ID.RA-01", Description: "Vulnerabilities identified"},
						},
					},
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

