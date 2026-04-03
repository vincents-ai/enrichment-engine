package anssi_ebios

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
	if got := p.Name(); got != "anssi_ebios" {
		t.Errorf("Name() = %q, want %q", got, "anssi_ebios")
	}
}

func TestNormalizeSeverity(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"critical", "critical"},
		{"critique", "critical"},
		{"CRITICAL", "critical"},
		{"high", "high"},
		{"élevé", "high"},
		{"eleve", "high"},
		{"HIGH", "high"},
		{"medium", "standard"},
		{"moyen", "standard"},
		{"MEDIUM", "standard"},
		{"low", "low"},
		{"faible", "low"},
		{"LOW", "low"},
		{"", "standard"},
		{"unknown", "standard"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := normalizeSeverity(tt.input)
			if got != tt.expected {
				t.Errorf("normalizeSeverity(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestEmbeddedControls(t *testing.T) {
	p := &Provider{}
	controls := p.parseEmbedded()
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
	controls := p.parseEmbedded()
	ids := make(map[string]bool)
	for _, ctrl := range controls {
		if ids[ctrl.ControlID] {
			t.Errorf("duplicate control ID: %s", ctrl.ControlID)
		}
		ids[ctrl.ControlID] = true
	}
}

func TestPhaseToControl(t *testing.T) {
	p := &Provider{}
	ctrl := p.phaseToControl(ebiosPhase{
		ID:          "1",
		Name:        "Test Phase",
		Description: "Test description",
	})
	if ctrl.ControlID != "P.1" {
		t.Errorf("expected ControlID P.1, got %s", ctrl.ControlID)
	}
	if ctrl.Family != "Phases" {
		t.Errorf("expected Family Phases, got %s", ctrl.Family)
	}
	if ctrl.Framework != FrameworkID {
		t.Errorf("expected Framework %s, got %s", FrameworkID, ctrl.Framework)
	}
}

func TestStepToControl(t *testing.T) {
	p := &Provider{}
	ctrl := p.stepToControl(ebiosStep{ID: "1", Name: "Step", Description: "Desc"}, ebiosPhase{ID: "1", Name: "Phase"})
	if ctrl.ControlID != "P.1.S.1" {
		t.Errorf("expected ControlID P.1.S.1, got %s", ctrl.ControlID)
	}
	if ctrl.Family != "Phases/Phase" {
		t.Errorf("expected Family Phases/Phase, got %s", ctrl.Family)
	}
}

func TestOutputToControl(t *testing.T) {
	p := &Provider{}
	ctrl := p.outputToControl(ebiosOutput{ID: "1", Name: "Output", Description: "Desc"}, ebiosPhase{ID: "1", Name: "Phase"})
	if ctrl.ControlID != "P.1.O.1" {
		t.Errorf("expected ControlID P.1.O.1, got %s", ctrl.ControlID)
	}
	if ctrl.Family != "Livrables/Phase" {
		t.Errorf("expected Family Livrables/Phase, got %s", ctrl.Family)
	}
}

func TestThreatToControl(t *testing.T) {
	p := &Provider{}
	ctrl := p.threatToControl(ebiosThreat{ID: "1", Name: "Threat", Category: "Techniques", Description: "Desc", Severity: "critical"})
	if ctrl.ControlID != "T.1" {
		t.Errorf("expected ControlID T.1, got %s", ctrl.ControlID)
	}
	if ctrl.Level != "critical" {
		t.Errorf("expected Level critical, got %s", ctrl.Level)
	}
	if ctrl.Family != "Menaces/Techniques" {
		t.Errorf("expected Family Menaces/Techniques, got %s", ctrl.Family)
	}
}

func TestRiskToControl(t *testing.T) {
	p := &Provider{}
	ctrl := p.riskToControl(ebiosRisk{ID: "1", Name: "Risk", Category: "Opérationnels", Description: "Desc", Severity: "high"})
	if ctrl.ControlID != "R.1" {
		t.Errorf("expected ControlID R.1, got %s", ctrl.ControlID)
	}
	if ctrl.Level != "high" {
		t.Errorf("expected Level high, got %s", ctrl.Level)
	}
	if ctrl.Family != "Risques/Opérationnels" {
		t.Errorf("expected Family Risques/Opérationnels, got %s", ctrl.Family)
	}
}

func TestScenarioToControl(t *testing.T) {
	p := &Provider{}
	ctrl := p.scenarioToControl(ebiosScenario{ID: "1", Name: "Scenario", Category: "Stratégiques", Description: "Desc", Severity: "low"})
	if ctrl.ControlID != "S.1" {
		t.Errorf("expected ControlID S.1, got %s", ctrl.ControlID)
	}
	if ctrl.Level != "low" {
		t.Errorf("expected Level low, got %s", ctrl.Level)
	}
	if ctrl.Family != "Scénarios/Stratégiques" {
		t.Errorf("expected Family Scénarios/Stratégiques, got %s", ctrl.Family)
	}
}

func TestParseSuccess(t *testing.T) {
	kb := ebiosKnowledgeBase{
		Phases: []ebiosPhase{
			{
				ID: "1", Name: "Phase 1", Description: "Desc",
				Steps:   []ebiosStep{{ID: "1", Name: "Step 1", Description: "Step desc", Order: 1}},
				Outputs: []ebiosOutput{{ID: "1", Name: "Output 1", Description: "Output desc"}},
			},
		},
		Threats: []ebiosThreat{
			{ID: "1", Name: "Threat 1", Category: "Techniques", Description: "TDesc", Severity: "high"},
		},
		Risks: []ebiosRisk{
			{ID: "1", Name: "Risk 1", Category: "Opérationnels", Description: "RDesc", Severity: "critical"},
		},
		Scenarios: []ebiosScenario{
			{ID: "1", Name: "Scenario 1", Category: "Stratégiques", Description: "SDesc", Severity: "low"},
		},
	}

	data, err := json.Marshal(kb)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "test.json")
	os.WriteFile(path, data, 0644)

	p := &Provider{}
	controls, err := p.parse(path)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	expected := 6
	if len(controls) != expected {
		t.Errorf("expected %d controls, got %d", expected, len(controls))
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
	kb := ebiosKnowledgeBase{
		Phases: []ebiosPhase{{ID: "1", Name: "Phase 1", Description: "Desc"}},
	}
	data, _ := json.Marshal(kb)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
	}))
	defer server.Close()

	origClient := grc.HTTPClient
	defer func() { grc.HTTPClient = origClient }()
	grc.HTTPClient = server.Client()

	p := &Provider{logger: testLogger()}
	f, err := os.CreateTemp("", "ebios_download_*.json")
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
		t.Fatalf("failed to read downloaded file: %v", err)
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
	f, err := os.CreateTemp("", "ebios_download_err_*.json")
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
	kb := ebiosKnowledgeBase{
		Phases: []ebiosPhase{{ID: "1", Name: "Phase 1", Description: "Desc"}},
	}
	data, _ := json.Marshal(kb)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
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
	if count < 1 {
		t.Errorf("expected at least 1 control from pipeline, got %d", count)
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
		t.Fatalf("Run should fall back to embedded on download error, got: %v", err)
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
		t.Fatalf("Run should fall back to embedded on parse error, got: %v", err)
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

func TestWriteControlsSuccess(t *testing.T) {
	backend := &mockBackend{}
	p := New(backend, testLogger())
	controls := []grc.Control{
		{Framework: FrameworkID, ControlID: "P.1", Title: "Test"},
		{Framework: FrameworkID, ControlID: "P.2", Title: "Test 2"},
	}
	count, err := p.writeControls(context.Background(), controls)
	if err != nil {
		t.Fatalf("writeControls failed: %v", err)
	}
	if count != 2 {
		t.Errorf("expected 2 controls written, got %d", count)
	}
}

func TestWriteControlsError(t *testing.T) {
	backend := &mockBackend{err: fmt.Errorf("write failed")}
	p := New(backend, testLogger())
	controls := []grc.Control{
		{Framework: FrameworkID, ControlID: "P.1", Title: "Test"},
	}
	count, err := p.writeControls(context.Background(), controls)
	if err != nil {
		t.Fatalf("writeControls should not return error, got: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 controls written, got %d", count)
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

