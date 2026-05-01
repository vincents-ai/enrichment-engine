package cmmc

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
	if got := p.Name(); got != "cmmc" {
		t.Errorf("Name() = %q, want %q", got, "cmmc")
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
		t.Errorf("expected some CMMC controls to have RelatedCWEs populated, got 0")
	}
}

func TestRunWithWriteError(t *testing.T) {
	backend := &mockBackend{err: os.ErrPermission}
	logger := testLogger()
	p := New(backend, logger)

	count, err := p.writeEmbeddedControls(context.Background())
	if err != nil {
		t.Fatalf("writeEmbeddedControls should not return error on individual write failures: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 controls written when all writes fail, got %d", count)
	}
}

func TestDownloadSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"controls":[{"id":"AC.L1-3.1.1","title":"Test","domain":"Access Control","level":"1"}]}`))
	}))
	defer srv.Close()

	p := &Provider{logger: testLogger()}
	f, err := os.CreateTemp("", "cmmc_download_test_*.json")
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
	if !strings.Contains(string(data), "AC.L1-3.1.1") {
		t.Errorf("downloaded file missing expected content: %s", string(data))
	}
}

func TestDownloadNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	p := &Provider{logger: testLogger()}
	f, _ := os.CreateTemp("", "cmmc_download_test_*.json")
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
	f, _ := os.CreateTemp("", "cmmc_download_test_*.json")
	dest := f.Name()
	f.Close()
	defer os.Remove(dest)

	err := p.download(context.Background(), "http://127.0.0.1:1", dest)
	if err == nil {
		t.Fatal("expected error for invalid URL")
	}
}

func TestParseWithFlatControls(t *testing.T) {
	catalog := cmmcCatalog{
		Controls: []cmmcControl{
			{ID: "AC.L1-3.1.1", Title: "Limit access", Description: "desc", Domain: "Access Control", Level: "1", NISTRef: "3.1.1"},
			{ID: "AC.L1-3.1.2", Title: "Limit transactions", Description: "desc2", Domain: "Access Control", Level: "1"},
		},
	}
	data, _ := json.Marshal(catalog)
	f, err := os.CreateTemp("", "cmmc_parse_test_*.json")
	if err != nil {
		t.Fatal(err)
	}
	f.Write(data)
	f.Close()
	defer os.Remove(f.Name())

	p := &Provider{logger: testLogger()}
	controls, err := p.parse(f.Name())
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(controls) != 2 {
		t.Fatalf("expected 2 controls, got %d", len(controls))
	}
	if controls[0].ControlID != "AC.L1-3.1.1" {
		t.Errorf("expected ControlID AC.L1-3.1.1, got %s", controls[0].ControlID)
	}
	if controls[0].Family != "Access Control" {
		t.Errorf("expected Family Access Control, got %s", controls[0].Family)
	}
	if controls[0].Level != "1" {
		t.Errorf("expected Level 1, got %s", controls[0].Level)
	}
	if len(controls[0].References) < 1 {
		t.Errorf("expected at least 1 reference, got %d", len(controls[0].References))
	}
	if controls[0].References[0].Source != "CMMC v2" {
		t.Errorf("expected reference source CMMC v2, got %s", controls[0].References[0].Source)
	}
	if len(controls[0].RelatedCWEs) != 3 {
		t.Errorf("expected 3 CWEs for AC.L1-3.1.1, got %d", len(controls[0].RelatedCWEs))
	}
	if controls[1].Framework != FrameworkID {
		t.Errorf("expected Framework %s, got %s", FrameworkID, controls[1].Framework)
	}
}

func TestParseWithGroups(t *testing.T) {
	catalog := cmmcCatalog{
		Groups: []cmmcGroup{
			{
				ID:     "AC",
				Domain: "Access Control",
				Level:  "2",
				Controls: []cmmcControl{
					{ID: "AC.L2-3.1.3", Title: "Control flow", Description: "desc", NISTRef: "3.1.3"},
					{ID: "AC.L2-3.1.5", Title: "Least privilege", Level: "3"},
				},
			},
		},
	}
	data, _ := json.Marshal(catalog)
	f, err := os.CreateTemp("", "cmmc_parse_test_*.json")
	if err != nil {
		t.Fatal(err)
	}
	f.Write(data)
	f.Close()
	defer os.Remove(f.Name())

	p := &Provider{logger: testLogger()}
	controls, err := p.parse(f.Name())
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(controls) != 2 {
		t.Fatalf("expected 2 controls from groups, got %d", len(controls))
	}
	if controls[0].Family != "Access Control" {
		t.Errorf("expected Family from group, got %s", controls[0].Family)
	}
	if controls[0].Level != "2" {
		t.Errorf("expected Level 2 from group, got %s", controls[0].Level)
	}
	if controls[1].Level != "3" {
		t.Errorf("expected Level 3 from control override, got %s", controls[1].Level)
	}
}

func TestParseInvalidJSON(t *testing.T) {
	f, err := os.CreateTemp("", "cmmc_parse_test_*.json")
	if err != nil {
		t.Fatal(err)
	}
	f.Write([]byte(`{invalid json`))
	f.Close()
	defer os.Remove(f.Name())

	p := &Provider{logger: testLogger()}
	_, err = p.parse(f.Name())
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestParseFileNotFound(t *testing.T) {
	p := &Provider{logger: testLogger()}
	_, err := p.parse("/nonexistent/file.json")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestParseEmptyCatalog(t *testing.T) {
	catalog := cmmcCatalog{}
	data, _ := json.Marshal(catalog)
	f, _ := os.CreateTemp("", "cmmc_parse_test_*.json")
	f.Write(data)
	f.Close()
	defer os.Remove(f.Name())

	p := &Provider{logger: testLogger()}
	controls, err := p.parse(f.Name())
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(controls) != 0 {
		t.Errorf("expected 0 controls from empty catalog, got %d", len(controls))
	}
}

func TestToControl(t *testing.T) {
	p := &Provider{logger: testLogger()}
	ctrl := p.toControl(cmmcControl{
		ID:          "AC.L1-3.1.1",
		Title:       "Test",
		Description: "desc",
		NISTRef:     "3.1.1",
	}, "Access Control", "1")

	if ctrl.Framework != FrameworkID {
		t.Errorf("expected Framework %s, got %s", FrameworkID, ctrl.Framework)
	}
	if ctrl.ControlID != "AC.L1-3.1.1" {
		t.Errorf("expected ControlID AC.L1-3.1.1, got %s", ctrl.ControlID)
	}
	if ctrl.Level != "1" {
		t.Errorf("expected Level 1, got %s", ctrl.Level)
	}
	if len(ctrl.References) != 2 {
		t.Errorf("expected 2 references (CMMC v2 + NIST), got %d", len(ctrl.References))
	}
	if ctrl.References[1].Source != "NIST SP 800-171" {
		t.Errorf("expected NIST ref source, got %s", ctrl.References[1].Source)
	}
}

func TestToControlNoNISTRef(t *testing.T) {
	p := &Provider{logger: testLogger()}
	ctrl := p.toControl(cmmcControl{
		ID:    "XX.1",
		Title: "Test",
	}, "Domain", "2")

	if len(ctrl.References) != 1 {
		t.Errorf("expected 1 reference (CMMC v2 only), got %d", len(ctrl.References))
	}
}

func TestToControlLevelOverride(t *testing.T) {
	p := &Provider{logger: testLogger()}
	ctrl := p.toControl(cmmcControl{
		ID:    "AC.L2-3.1.5",
		Title: "Test",
		Level: "3",
	}, "Access Control", "2")

	if ctrl.Level != "3" {
		t.Errorf("expected control-level override 3, got %s", ctrl.Level)
	}
}

func TestCmmcCWEs(t *testing.T) {
	cwes := cmmcCWEs("AC.L1-3.1.1")
	if len(cwes) != 3 {
		t.Errorf("expected 3 CWEs for AC.L1-3.1.1, got %d", len(cwes))
	}
	cwes = cmmcCWEs("nonexistent")
	if cwes != nil {
		t.Errorf("expected nil for unknown control, got %v", cwes)
	}
}

func TestRunDownloadSuccess(t *testing.T) {
	catalog := cmmcCatalog{
		Controls: []cmmcControl{
			{ID: "AC.L1-3.1.1", Title: "Limit access", Domain: "Access Control", Level: "1"},
			{ID: "AC.L1-3.1.2", Title: "Limit transactions", Domain: "Access Control", Level: "1"},
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
	if len(backend.controls) != 2 {
		t.Errorf("expected 2 controls in backend, got %d", len(backend.controls))
	}
}

func TestRunParseErrorFallback(t *testing.T) {
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
	if err != nil {
		t.Fatalf("Run should fallback to embedded on parse error: %v", err)
	}
	if count < 5 {
		t.Errorf("expected at least 5 embedded controls on fallback, got %d", count)
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
	if count < 5 {
		t.Errorf("expected at least 5 embedded controls on fallback, got %d", count)
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

func TestRunDownloadSuccessWithWriteError(t *testing.T) {
	catalog := cmmcCatalog{
		Controls: []cmmcControl{
			{ID: "AC.L1-3.1.1", Title: "Limit access", Domain: "Access Control", Level: "1"},
			{ID: "AC.L1-3.1.2", Title: "Limit transactions", Domain: "Access Control", Level: "1"},
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

	backend := &mockBackend{err: os.ErrPermission}
	logger := testLogger()
	p := New(backend, logger)

	count, err := p.Run(context.Background())
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 controls written with error backend, got %d", count)
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

func TestDownloadCreateError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{}`))
	}))
	defer server.Close()

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

