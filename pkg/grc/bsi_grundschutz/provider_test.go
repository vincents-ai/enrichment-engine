package bsi_grundschutz

import (
	"context"
	"encoding/xml"
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
	if got := p.Name(); got != "bsi_grundschutz" {
		t.Errorf("Name() = %q, want %q", got, "bsi_grundschutz")
	}
}

func TestProviderParse(t *testing.T) {
	fixture := `<?xml version="1.0" encoding="UTF-8"?>
<book xmlns="http://docbook.org/ns/docbook" version="5.0">
<chapter>
<section>
<section>
<title>CON.1 Kryptokonzept</title>
<title>CON.1.A1 Auswahl geeigneter kryptografischer Verfahren (B) [Fachverantwortliche]</title>
<title>CON.1.A2 Datensicherung beim Einsatz kryptografischer Verfahren (B) [IT-Betrieb]</title>
<title>CON.1.A3 Test (S)</title>
<title>CON.1.A4 Hoch sicher (H) [Admin]</title>
</section>
</section>
</chapter>
</book>`

	dir := t.TempDir()
	path := filepath.Join(dir, "test.xml")
	if err := os.WriteFile(path, []byte(fixture), 0644); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}

	p := &Provider{}
	controls, err := p.parse(path)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	if len(controls) != 4 {
		t.Fatalf("expected 4 controls, got %d", len(controls))
	}

	if controls[0].ControlID != "CON.1.A1" {
		t.Errorf("expected ControlID CON.1.A1, got %s", controls[0].ControlID)
	}
	if controls[0].Title != "Auswahl geeigneter kryptografischer Verfahren" {
		t.Errorf("unexpected title: %s", controls[0].Title)
	}
	if controls[0].Family != "Kryptokonzept" {
		t.Errorf("expected Family Kryptokonzept, got %s", controls[0].Family)
	}
	if controls[0].Level != "basic" {
		t.Errorf("expected Level basic, got %s", controls[0].Level)
	}

	if controls[2].Level != "standard" {
		t.Errorf("expected Level standard, got %s", controls[2].Level)
	}

	if controls[3].Level != "high" {
		t.Errorf("expected Level high, got %s", controls[3].Level)
	}
}

func TestParseMultipleChapters(t *testing.T) {
	fixture := `<?xml version="1.0" encoding="UTF-8"?>
<book xmlns="http://docbook.org/ns/docbook" version="5.0">
<chapter>
<section>
<section>
<title>CON.1 Kryptokonzept</title>
<title>CON.1.A1 Test (B)</title>
</section>
</section>
</chapter>
<chapter>
<section>
<section>
<title>NET.1 Netzwerk</title>
<title>NET.1.A1 Network test (H)</title>
</section>
</section>
</chapter>
</book>`

	dir := t.TempDir()
	path := filepath.Join(dir, "test.xml")
	os.WriteFile(path, []byte(fixture), 0644)

	p := &Provider{}
	controls, err := p.parse(path)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(controls) != 2 {
		t.Fatalf("expected 2 controls, got %d", len(controls))
	}
	if controls[0].Family != "Kryptokonzept" {
		t.Errorf("expected Family Kryptokonzept, got %s", controls[0].Family)
	}
	if controls[1].Family != "Netzwerk" {
		t.Errorf("expected Family Netzwerk, got %s", controls[1].Family)
	}
	if controls[1].Level != "high" {
		t.Errorf("expected Level high, got %s", controls[1].Level)
	}
}

func TestParseNoMatchingTitles(t *testing.T) {
	fixture := `<?xml version="1.0" encoding="UTF-8"?>
<book xmlns="http://docbook.org/ns/docbook" version="5.0">
<chapter>
<section>
<section>
<title>Some random title</title>
<title>Another title</title>
</section>
</section>
</chapter>
</book>`

	dir := t.TempDir()
	path := filepath.Join(dir, "test.xml")
	os.WriteFile(path, []byte(fixture), 0644)

	p := &Provider{}
	controls, err := p.parse(path)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(controls) != 0 {
		t.Errorf("expected 0 controls for non-matching titles, got %d", len(controls))
	}
}

func TestParseInvalidXML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.xml")
	os.WriteFile(path, []byte("not xml"), 0644)

	p := &Provider{}
	_, err := p.parse(path)
	if err == nil {
		t.Fatal("expected error for invalid XML, got nil")
	}
}

func TestParseFileNotFound(t *testing.T) {
	p := &Provider{}
	_, err := p.parse("/nonexistent/path/file.xml")
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

func TestParseModulePattern(t *testing.T) {
	tests := []struct {
		title string
		want  bool
	}{
		{"CON.1 Kryptokonzept", true},
		{"ORP.4.2 Sicherheitsmanagement", true},
		{"Not a module", false},
		{"Random text", false},
	}
	for _, tt := range tests {
		t.Run(tt.title, func(t *testing.T) {
			match := modulePattern.FindStringSubmatch(tt.title)
			if tt.want && match == nil {
				t.Errorf("expected match for %q", tt.title)
			}
			if !tt.want && match != nil {
				t.Errorf("expected no match for %q", tt.title)
			}
		})
	}
}

func TestParseControlPattern(t *testing.T) {
	tests := []struct {
		title string
		want  bool
	}{
		{"CON.1.A1 Auswahl geeigneter kryptografischer Verfahren (B) [Fachverantwortliche]", true},
		{"CON.1.A4 Hoch sicher (H) [Admin]", true},
		{"ORP.4.2.A1 Some control (S)", true},
		{"Not a control pattern", false},
	}
	for _, tt := range tests {
		t.Run(tt.title, func(t *testing.T) {
			match := controlPattern.FindStringSubmatch(tt.title)
			if tt.want && match == nil {
				t.Errorf("expected match for %q", tt.title)
			}
			if !tt.want && match != nil {
				t.Errorf("expected no match for %q", tt.title)
			}
		})
	}
}

func TestProviderMapLevel(t *testing.T) {
	p := &Provider{}

	tests := []struct {
		input    string
		expected string
	}{
		{"B", "basic"},
		{"S", "standard"},
		{"H", "high"},
		{"b", "basic"},
		{"s", "standard"},
		{"h", "high"},
		{"X", "standard"},
		{"", "standard"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := p.mapLevel(tt.input)
			if got != tt.expected {
				t.Errorf("mapLevel(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestDocBookXMLUnmarshal(t *testing.T) {
	fixture := `<?xml version="1.0" encoding="UTF-8"?>
<book xmlns="http://docbook.org/ns/docbook" version="5.0">
<chapter>
<section>
<section>
<title>CON.1 Kryptokonzept</title>
<title>CON.1.A1 Test (B)</title>
</section>
</section>
</chapter>
</book>`

	var book docbookBook
	if err := xml.Unmarshal([]byte(fixture), &book); err != nil {
		t.Fatalf("failed to unmarshal DocBook XML: %v", err)
	}

	if len(book.Chapters) != 1 {
		t.Fatalf("expected 1 chapter, got %d", len(book.Chapters))
	}

	if len(book.Chapters[0].Sections) != 1 {
		t.Fatalf("expected 1 section in chapter, got %d", len(book.Chapters[0].Sections))
	}

	if len(book.Chapters[0].Sections[0].Sections) != 1 {
		t.Fatalf("expected 1 subsection, got %d", len(book.Chapters[0].Sections[0].Sections))
	}

	if len(book.Chapters[0].Sections[0].Sections[0].Titles) != 2 {
		t.Fatalf("expected 2 titles, got %d", len(book.Chapters[0].Sections[0].Sections[0].Titles))
	}

	if book.Chapters[0].Sections[0].Sections[0].Titles[0] != "CON.1 Kryptokonzept" {
		t.Errorf("unexpected title: %s", book.Chapters[0].Sections[0].Sections[0].Titles[0])
	}
}

func TestDownloadSuccess(t *testing.T) {
	fixture := `<?xml version="1.0" encoding="UTF-8"?>
<book xmlns="http://docbook.org/ns/docbook" version="5.0">
<chapter>
<section>
<section>
<title>CON.1 Kryptokonzept</title>
<title>CON.1.A1 Test (B)</title>
</section>
</section>
</chapter>
</book>`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.Write([]byte(fixture))
	}))
	defer server.Close()

	origClient := grc.HTTPClient
	defer func() { grc.HTTPClient = origClient }()
	grc.HTTPClient = server.Client()

	p := &Provider{logger: testLogger()}
	f, err := os.CreateTemp("", "bsi_download_*.xml")
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
	f, err := os.CreateTemp("", "bsi_download_err_*.xml")
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
	fixture := `<?xml version="1.0" encoding="UTF-8"?>
<book xmlns="http://docbook.org/ns/docbook" version="5.0">
<chapter>
<section>
<section>
<title>CON.1 Kryptokonzept</title>
<title>CON.1.A1 Krypto (B)</title>
<title>CON.1.A2 Krypto 2 (H)</title>
</section>
</section>
</chapter>
</book>`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.Write([]byte(fixture))
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

func TestRunDownloadError(t *testing.T) {
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
	_, err := p.Run(context.Background())
	if err == nil {
		t.Fatal("expected error for download failure, got nil")
	}
}

func TestRunParseError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.Write([]byte("not xml"))
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
	_, err := p.Run(context.Background())
	if err == nil {
		t.Fatal("expected error for parse failure, got nil")
	}
}

func TestRunWriteError(t *testing.T) {
	fixture := `<?xml version="1.0" encoding="UTF-8"?>
<book xmlns="http://docbook.org/ns/docbook" version="5.0">
<chapter>
<section>
<section>
<title>CON.1 Kryptokonzept</title>
<title>CON.1.A1 Test (B)</title>
</section>
</section>
</chapter>
</book>`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.Write([]byte(fixture))
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
	fixture := `<?xml version="1.0" encoding="UTF-8"?>
<book xmlns="http://docbook.org/ns/docbook" version="5.0">
<chapter>
<section>
<section>
<title>CON.1 Kryptokonzept</title>
<title>CON.1.A1 Test (B)</title>
</section>
</section>
</chapter>
</book>`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.Write([]byte(fixture))
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

