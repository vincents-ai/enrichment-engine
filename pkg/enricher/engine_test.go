package enricher

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"testing"

	"github.com/shift/enrichment-engine/pkg/grc"
	"github.com/shift/enrichment-engine/pkg/storage"
)

type mockBackend struct {
	vulns    []storage.VulnerabilityRow
	controls []storage.ControlRow
	mappings []storage.MappingRow
}

func (m *mockBackend) WriteVulnerability(_ context.Context, _ string, _ interface{}) error {
	return nil
}

func (m *mockBackend) WriteControl(_ context.Context, _ string, _ interface{}) error {
	return nil
}

func (m *mockBackend) WriteMapping(_ context.Context, vulnID, controlID, framework, mappingType string, confidence float64, evidence string) error {
	m.mappings = append(m.mappings, storage.MappingRow{
		VulnerabilityID: vulnID,
		ControlID:       controlID,
		Framework:       framework,
		MappingType:     mappingType,
		Confidence:      confidence,
		Evidence:        evidence,
	})
	return nil
}

func (m *mockBackend) ReadVulnerability(_ context.Context, _ string) ([]byte, error) {
	return nil, nil
}

func (m *mockBackend) ReadControl(_ context.Context, _ string) ([]byte, error) {
	return nil, nil
}

func (m *mockBackend) ListMappings(_ context.Context, _ string) ([]storage.MappingRow, error) {
	return m.mappings, nil
}

func (m *mockBackend) Close(_ context.Context) error {
	return nil
}

func (m *mockBackend) ListAllVulnerabilities(_ context.Context) ([]storage.VulnerabilityRow, error) {
	return m.vulns, nil
}

func (m *mockBackend) ListAllControls(_ context.Context) ([]storage.ControlRow, error) {
	return m.controls, nil
}

func (m *mockBackend) ListControlsByCWE(_ context.Context, cwe string) ([]storage.ControlRow, error) {
	var result []storage.ControlRow
	for _, ctrl := range m.controls {
		for _, c := range ctrl.RelatedCWEs {
			if c == cwe {
				result = append(result, ctrl)
				break
			}
		}
	}
	return result, nil
}

func (m *mockBackend) ListControlsByCPE(_ context.Context, cpe string) ([]storage.ControlRow, error) {
	return m.controls, nil
}

func (m *mockBackend) ListControlsByFramework(_ context.Context, framework string) ([]storage.ControlRow, error) {
	var result []storage.ControlRow
	for _, ctrl := range m.controls {
		if ctrl.Framework == framework {
			result = append(result, ctrl)
		}
	}
	return result, nil
}

type cweLookupErrMock struct {
	mockBackend
}

func (m *cweLookupErrMock) ListControlsByCWE(_ context.Context, _ string) ([]storage.ControlRow, error) {
	return nil, fmt.Errorf("simulated db error")
}

type mappingWriteErrMock struct {
	mockBackend
}

func (m *mappingWriteErrMock) WriteMapping(_ context.Context, _, _, _, _ string, _ float64, _ string) error {
	return fmt.Errorf("simulated write error")
}

type cpeLookupErrMock struct {
	mockBackend
}

func (m *cpeLookupErrMock) ListControlsByCPE(_ context.Context, _ string) ([]storage.ControlRow, error) {
	return nil, fmt.Errorf("simulated cpe lookup error")
}

type vulnListErrMock struct {
	mockBackend
}

func (m *vulnListErrMock) ListAllVulnerabilities(_ context.Context) ([]storage.VulnerabilityRow, error) {
	return nil, fmt.Errorf("simulated list error")
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(&discardWriter{}, &slog.HandlerOptions{Level: slog.LevelInfo}))
}

type discardWriter struct{}

func (d *discardWriter) Write(p []byte) (n int, err error) {
	return len(p), nil
}

func TestNewDefaults(t *testing.T) {
	e := New(Config{})
	if e.maxParallel != 1 {
		t.Errorf("expected maxParallel=1, got %d", e.maxParallel)
	}
}

func TestRunAllProviders(t *testing.T) {
	backend, err := storage.NewSQLiteBackend(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close(context.Background())

	vulnData := json.RawMessage(`{
		"id": "CVE-2024-RUNALL",
		"cve": {
			"id": "CVE-2024-RUNALL",
			"weaknesses": [{"description": [{"lang": "en", "value": "CWE-287"}]}],
			"configurations": [{"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:apache:log4j:2.14.0:*:*:*:*:*:*:*"}]}]}]
		}
	}`)
	if err := backend.WriteVulnerability(context.Background(), "CVE-2024-RUNALL", vulnData); err != nil {
		t.Fatal(err)
	}

	e := New(Config{
		Store:         backend,
		Logger:        testLogger(),
		ProviderNames: []string{"hipaa"},
	})

	result, err := e.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.ProviderCount != 1 {
		t.Errorf("expected 1 provider, got %d", result.ProviderCount)
	}
	if result.ControlCount == 0 {
		t.Error("expected controls to be loaded")
	}
	if result.MappingCount == 0 {
		t.Error("expected mappings from CWE-287")
	}
	if result.Duration <= 0 {
		t.Error("expected positive duration")
	}
}

func TestRunWithProviderNames(t *testing.T) {
	backend, err := storage.NewSQLiteBackend(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close(context.Background())

	e := New(Config{
		Store:         backend,
		Logger:        testLogger(),
		ProviderNames: []string{"hipaa"},
	})

	result, err := e.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.ProviderCount != 1 {
		t.Errorf("expected 1 provider, got %d", result.ProviderCount)
	}
	if result.ControlCount == 0 {
		t.Error("expected hipaa controls")
	}
}

func TestRunSkipMapping(t *testing.T) {
	backend, err := storage.NewSQLiteBackend(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close(context.Background())

	e := New(Config{
		Store:         backend,
		Logger:        testLogger(),
		ProviderNames: []string{"hipaa"},
		SkipMapping:   true,
	})

	result, err := e.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.ProviderCount != 1 {
		t.Errorf("expected 1 provider, got %d", result.ProviderCount)
	}
	if result.MappingCount != 0 {
		t.Errorf("expected 0 mappings, got %d", result.MappingCount)
	}
	if result.VulnCount != 0 {
		t.Errorf("expected 0 vuln count, got %d", result.VulnCount)
	}
}

func TestRunNoVulns(t *testing.T) {
	backend, err := storage.NewSQLiteBackend(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close(context.Background())

	e := New(Config{
		Store:         backend,
		Logger:        testLogger(),
		SkipProviders: true,
	})

	result, err := e.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.ProviderCount != 0 {
		t.Errorf("expected 0 providers, got %d", result.ProviderCount)
	}
	if result.ControlCount != 0 {
		t.Errorf("expected 0 controls, got %d", result.ControlCount)
	}
	if result.MappingCount != 0 {
		t.Errorf("expected 0 mappings, got %d", result.MappingCount)
	}
	if result.VulnCount != 0 {
		t.Errorf("expected 0 vulns, got %d", result.VulnCount)
	}
}

func TestRunListVulnsError(t *testing.T) {
	mock := &vulnListErrMock{}

	e := New(Config{
		Store:         mock,
		Logger:        testLogger(),
		SkipProviders: true,
	})

	_, err := e.Run(context.Background())
	if err == nil {
		t.Fatal("expected error from Run when ListAllVulnerabilities fails")
	}
}

func TestRunAllProviders_EmptyNames(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	mock := &mockBackend{}
	e := New(Config{
		Store:  mock,
		Logger: testLogger(),
	})

	result, err := e.Run(ctx)
	if err != nil {
		t.Logf("Run returned error with cancelled context: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.ProviderCount == 0 {
		t.Error("expected providers to run (providerCount should be len(registry.List()))")
	}
}

type failingProvider struct{}

func (f *failingProvider) Name() string { return "failing" }

func (f *failingProvider) Run(_ context.Context) (int, error) {
	return 0, fmt.Errorf("simulated provider failure")
}

func TestRun_ProviderError(t *testing.T) {
	reg := grc.NewRegistry()
	reg.Register("failing", func(s storage.Backend, l *slog.Logger) grc.GRCProvider {
		return &failingProvider{}
	})

	mock := &mockBackend{}
	e := New(Config{
		Store:       mock,
		Logger:      testLogger(),
		MaxParallel: 2,
		Registry:    reg,
	})

	_, err := e.Run(context.Background())
	if err == nil {
		t.Fatal("expected error from Run when provider fails")
	}
}

func TestRun_ProviderErrorSequential(t *testing.T) {
	reg := grc.NewRegistry()
	reg.Register("failing", func(s storage.Backend, l *slog.Logger) grc.GRCProvider {
		return &failingProvider{}
	})

	mock := &mockBackend{}
	e := New(Config{
		Store:       mock,
		Logger:      testLogger(),
		MaxParallel: 1,
		Registry:    reg,
	})

	result, err := e.Run(context.Background())
	if err != nil {
		t.Fatalf("Run should not return error in sequential mode (errors are logged): %v", err)
	}
	if result.ProviderCount != 1 {
		t.Errorf("expected 1 provider, got %d", result.ProviderCount)
	}
}

func TestExtractCWEs(t *testing.T) {
	record := json.RawMessage(`{
		"id": "CVE-2024-12345",
		"cve": {
			"id": "CVE-2024-12345",
			"weaknesses": [
				{"description": [{"lang": "en", "value": "CWE-79"}]},
				{"description": [{"lang": "en", "value": "CWE-79"}]}
			],
			"configurations": []
		}
	}`)

	cwes := extractCWEs(record)
	if len(cwes) != 1 {
		t.Fatalf("expected 1 CWE, got %d: %v", len(cwes), cwes)
	}
	if cwes[0] != "CWE-79" {
		t.Errorf("expected CWE-79, got %s", cwes[0])
	}
}

func TestExtractCWEs_Multiple(t *testing.T) {
	record := json.RawMessage(`{
		"id": "CVE-2024-99999",
		"cve": {
			"id": "CVE-2024-99999",
			"weaknesses": [
				{"description": [{"lang": "en", "value": "CWE-79"}, {"lang": "fr", "value": "CWE-79"}]},
				{"description": [{"lang": "en", "value": "CWE-89"}]}
			],
			"configurations": []
		}
	}`)

	cwes := extractCWEs(record)
	if len(cwes) != 2 {
		t.Fatalf("expected 2 CWEs, got %d: %v", len(cwes), cwes)
	}
	found79, found89 := false, false
	for _, c := range cwes {
		if c == "CWE-79" {
			found79 = true
		}
		if c == "CWE-89" {
			found89 = true
		}
	}
	if !found79 {
		t.Error("missing CWE-79")
	}
	if !found89 {
		t.Error("missing CWE-89")
	}
}

func TestExtractCWEs_NoWeaknesses(t *testing.T) {
	record := json.RawMessage(`{
		"id": "CVE-2024-00000",
		"cve": {
			"id": "CVE-2024-00000",
			"weaknesses": [],
			"configurations": []
		}
	}`)

	cwes := extractCWEs(record)
	if len(cwes) != 0 {
		t.Fatalf("expected 0 CWEs, got %d: %v", len(cwes), cwes)
	}
}

func TestExtractCWEs_Malformed(t *testing.T) {
	cwes := extractCWEs(json.RawMessage(`not json at all`))
	if cwes != nil {
		t.Fatalf("expected nil for malformed JSON, got %v", cwes)
	}
}

func TestExtractCWEs_NonCWEPrefix(t *testing.T) {
	record := json.RawMessage(`{
		"id": "CVE-2024-NOPE",
		"cve": {
			"id": "CVE-2024-NOPE",
			"weaknesses": [
				{"description": [{"lang": "en", "value": "NVD-CWE-noinfo"}]}
			],
			"configurations": []
		}
	}`)

	cwes := extractCWEs(record)
	if len(cwes) != 0 {
		t.Fatalf("expected 0 CWEs for non-CWE prefix, got %d: %v", len(cwes), cwes)
	}
}

func TestExtractCPEs(t *testing.T) {
	record := json.RawMessage(`{
		"id": "CVE-2024-12345",
		"cve": {
			"id": "CVE-2024-12345",
			"weaknesses": [],
			"configurations": [
				{
					"nodes": [
						{
							"cpeMatch": [
								{"criteria": "cpe:2.3:a:apache:log4j:2.14.0:*:*:*:*:*:*:*"},
								{"criteria": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"}
							]
						}
					]
				}
			]
		}
	}`)

	cpes := extractCPEs(record)
	if len(cpes) != 2 {
		t.Fatalf("expected 2 CPEs, got %d: %v", len(cpes), cpes)
	}
	if cpes[0] != "cpe:2.3:a:apache:log4j:2.14.0:*:*:*:*:*:*:*" {
		t.Errorf("unexpected CPE[0]: %s", cpes[0])
	}
	if cpes[1] != "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*" {
		t.Errorf("unexpected CPE[1]: %s", cpes[1])
	}
}

func TestExtractCPEs_NoConfigs(t *testing.T) {
	record := json.RawMessage(`{
		"id": "CVE-2024-00000",
		"cve": {
			"id": "CVE-2024-00000",
			"weaknesses": [],
			"configurations": []
		}
	}`)

	cpes := extractCPEs(record)
	if len(cpes) != 0 {
		t.Fatalf("expected 0 CPEs, got %d: %v", len(cpes), cpes)
	}
}

func TestExtractCPEs_Malformed(t *testing.T) {
	cpes := extractCPEs(json.RawMessage(`{invalid json`))
	if cpes != nil {
		t.Fatalf("expected nil for malformed JSON, got %v", cpes)
	}
}

func TestExtractCPEs_Dedup(t *testing.T) {
	record := json.RawMessage(`{
		"id": "CVE-2024-DUP",
		"cve": {
			"id": "CVE-2024-DUP",
			"weaknesses": [],
			"configurations": [
				{"nodes": [{"cpeMatch": [
					{"criteria": "cpe:2.3:a:apache:log4j:2.14.0:*:*:*:*:*:*:*"},
					{"criteria": "cpe:2.3:a:apache:log4j:2.14.0:*:*:*:*:*:*:*"}
				]}]},
				{"nodes": [{"cpeMatch": [
					{"criteria": "cpe:2.3:a:apache:log4j:2.14.0:*:*:*:*:*:*:*"}
				]}]}
			]
		}
	}`)

	cpes := extractCPEs(record)
	if len(cpes) != 1 {
		t.Fatalf("expected 1 deduplicated CPE, got %d: %v", len(cpes), cpes)
	}
}

func TestMapByCWE(t *testing.T) {
	vulnRecord := json.RawMessage(`{
		"id": "CVE-2024-12345",
		"cve": {
			"id": "CVE-2024-12345",
			"weaknesses": [
				{"description": [{"lang": "en", "value": "CWE-79"}]}
			],
			"configurations": [
				{
					"nodes": [
						{"cpeMatch": [{"criteria": "cpe:2.3:a:apache:log4j:2.14.0:*:*:*:*:*:*:*"}]}
					]
				}
			]
		}
	}`)

	mock := &mockBackend{
		vulns: []storage.VulnerabilityRow{
			{ID: "CVE-2024-12345", Record: vulnRecord},
		},
		controls: []storage.ControlRow{
			{
				ID:          "NIST_CSF_2_0/PR.IR-05",
				Framework:   "NIST_CSF_2_0",
				ControlID:   "PR.IR-05",
				Title:       "Secure development",
				RelatedCWEs: []string{"CWE-79"},
			},
		},
	}

	e := New(Config{
		Store:  mock,
		Logger: testLogger(),
	})

	count, err := e.mapByCWE(context.Background())
	if err != nil {
		t.Fatalf("mapByCWE error: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 CWE mapping, got %d", count)
	}
	if len(mock.mappings) != 1 {
		t.Fatalf("expected 1 mapping written, got %d", len(mock.mappings))
	}
	m := mock.mappings[0]
	if m.VulnerabilityID != "CVE-2024-12345" {
		t.Errorf("expected vuln CVE-2024-12345, got %s", m.VulnerabilityID)
	}
	if m.MappingType != "cwe" {
		t.Errorf("expected mapping type cwe, got %s", m.MappingType)
	}
	if m.Confidence != 0.8 {
		t.Errorf("expected confidence 0.8, got %f", m.Confidence)
	}
}

func TestMapByCWE_NoMatch(t *testing.T) {
	vulnRecord := json.RawMessage(`{
		"id": "CVE-2024-99999",
		"cve": {
			"id": "CVE-2024-99999",
			"weaknesses": [
				{"description": [{"lang": "en", "value": "CWE-123"}]}
			],
			"configurations": []
		}
	}`)

	mock := &mockBackend{
		vulns: []storage.VulnerabilityRow{
			{ID: "CVE-2024-99999", Record: vulnRecord},
		},
		controls: []storage.ControlRow{
			{
				ID:          "NIST_CSF_2_0/PR.IR-05",
				Framework:   "NIST_CSF_2_0",
				ControlID:   "PR.IR-05",
				Title:       "Secure development",
				RelatedCWEs: []string{"CWE-79"},
			},
		},
	}

	e := New(Config{
		Store:  mock,
		Logger: testLogger(),
	})

	count, err := e.mapByCWE(context.Background())
	if err != nil {
		t.Fatalf("mapByCWE error: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected 0 mappings, got %d", count)
	}
}

func TestMapByCWE_NoWeaknesses(t *testing.T) {
	vulnRecord := json.RawMessage(`{
		"id": "CVE-2024-NOVULN",
		"cve": {
			"id": "CVE-2024-NOVULN",
			"weaknesses": [],
			"configurations": []
		}
	}`)

	mock := &mockBackend{
		vulns: []storage.VulnerabilityRow{
			{ID: "CVE-2024-NOVULN", Record: vulnRecord},
		},
		controls: []storage.ControlRow{
			{
				ID:          "FW/C-1",
				Framework:   "FW",
				ControlID:   "C-1",
				Title:       "Test",
				RelatedCWEs: []string{"CWE-79"},
			},
		},
	}

	e := New(Config{Store: mock, Logger: testLogger()})
	count, err := e.mapByCWE(context.Background())
	if err != nil {
		t.Fatalf("mapByCWE error: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected 0 mappings, got %d", count)
	}
}

func TestMapByCWE_CWELookupError(t *testing.T) {
	vulnRecord := json.RawMessage(`{
		"id": "CVE-2024-CWEERR",
		"cve": {
			"id": "CVE-2024-CWEERR",
			"weaknesses": [{"description": [{"lang": "en", "value": "CWE-79"}]}],
			"configurations": []
		}
	}`)

	mock := &cweLookupErrMock{
		mockBackend: mockBackend{
			vulns: []storage.VulnerabilityRow{
				{ID: "CVE-2024-CWEERR", Record: vulnRecord},
			},
		},
	}

	e := New(Config{Store: mock, Logger: testLogger()})
	count, err := e.mapByCWE(context.Background())
	if err != nil {
		t.Fatalf("mapByCWE error: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected 0 mappings on CWE lookup error, got %d", count)
	}
}

func TestMapByCWE_WriteMappingError(t *testing.T) {
	vulnRecord := json.RawMessage(`{
		"id": "CVE-2024-WMERR",
		"cve": {
			"id": "CVE-2024-WMERR",
			"weaknesses": [{"description": [{"lang": "en", "value": "CWE-79"}]}],
			"configurations": []
		}
	}`)

	mock := &mappingWriteErrMock{
		mockBackend: mockBackend{
			vulns: []storage.VulnerabilityRow{
				{ID: "CVE-2024-WMERR", Record: vulnRecord},
			},
			controls: []storage.ControlRow{
				{
					ID:          "FW/C-1",
					Framework:   "FW",
					ControlID:   "C-1",
					Title:       "Test",
					RelatedCWEs: []string{"CWE-79"},
				},
			},
		},
	}

	e := New(Config{Store: mock, Logger: testLogger()})
	count, err := e.mapByCWE(context.Background())
	if err != nil {
		t.Fatalf("mapByCWE error: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected 0 mappings on write error, got %d", count)
	}
}

func TestMapByCWE_ListVulnsError(t *testing.T) {
	mock := &vulnListErrMock{}

	e := New(Config{Store: mock, Logger: testLogger()})
	_, err := e.mapByCWE(context.Background())
	if err == nil {
		t.Fatal("expected error when ListAllVulnerabilities fails")
	}
}

func TestMapByCPE(t *testing.T) {
	vulnRecord := json.RawMessage(`{
		"id": "CVE-2024-CPE",
		"cve": {
			"id": "CVE-2024-CPE",
			"weaknesses": [{"description": [{"lang": "en", "value": "CWE-79"}]}],
			"configurations": [{"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:apache:log4j:2.14.0:*:*:*:*:*:*:*"}]}]}]
		}
	}`)

	mock := &mockBackend{
		vulns: []storage.VulnerabilityRow{
			{ID: "CVE-2024-CPE", Record: vulnRecord},
		},
		controls: []storage.ControlRow{
			{
				ID:          "NIST_CSF_2_0/PR.IR-05",
				Framework:   "NIST_CSF_2_0",
				ControlID:   "PR.IR-05",
				Title:       "Secure development",
				RelatedCWEs: []string{"CWE-79"},
			},
		},
	}

	e := New(Config{Store: mock, Logger: testLogger()})
	count, err := e.mapByCPE(context.Background())
	if err != nil {
		t.Fatalf("mapByCPE error: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 CPE mapping, got %d", count)
	}
	if len(mock.mappings) != 1 {
		t.Fatalf("expected 1 mapping written, got %d", len(mock.mappings))
	}
	m := mock.mappings[0]
	if m.MappingType != "cpe" {
		t.Errorf("expected cpe, got %s", m.MappingType)
	}
	if m.Confidence != 0.6 {
		t.Errorf("expected 0.6, got %f", m.Confidence)
	}
	if m.VulnerabilityID != "CVE-2024-CPE" {
		t.Errorf("expected CVE-2024-CPE, got %s", m.VulnerabilityID)
	}
}

func TestMapByCPE_NoMatch(t *testing.T) {
	vulnRecord := json.RawMessage(`{
		"id": "CVE-2024-NOCPE",
		"cve": {
			"id": "CVE-2024-NOCPE",
			"weaknesses": [{"description": [{"lang": "en", "value": "CWE-999"}]}],
			"configurations": [{"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:apache:log4j:2.14.0:*:*:*:*:*:*:*"}]}]}]
		}
	}`)

	mock := &mockBackend{
		vulns: []storage.VulnerabilityRow{
			{ID: "CVE-2024-NOCPE", Record: vulnRecord},
		},
		controls: []storage.ControlRow{
			{
				ID:          "FW/C-1",
				Framework:   "FW",
				ControlID:   "C-1",
				Title:       "Test",
				RelatedCWEs: []string{"CWE-79"},
			},
		},
	}

	e := New(Config{Store: mock, Logger: testLogger()})
	count, err := e.mapByCPE(context.Background())
	if err != nil {
		t.Fatalf("mapByCPE error: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected 0 CPE mappings, got %d", count)
	}
}

func TestMapByCPE_NoCPEs(t *testing.T) {
	vulnRecord := json.RawMessage(`{
		"id": "CVE-2024-NOCPE2",
		"cve": {
			"id": "CVE-2024-NOCPE2",
			"weaknesses": [{"description": [{"lang": "en", "value": "CWE-79"}]}],
			"configurations": []
		}
	}`)

	mock := &mockBackend{
		vulns: []storage.VulnerabilityRow{
			{ID: "CVE-2024-NOCPE2", Record: vulnRecord},
		},
		controls: []storage.ControlRow{
			{
				ID:          "FW/C-1",
				Framework:   "FW",
				ControlID:   "C-1",
				Title:       "Test",
				RelatedCWEs: []string{"CWE-79"},
			},
		},
	}

	e := New(Config{Store: mock, Logger: testLogger()})
	count, err := e.mapByCPE(context.Background())
	if err != nil {
		t.Fatalf("mapByCPE error: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected 0 CPE mappings, got %d", count)
	}
}

func TestMapByCPE_NoCWEsInVuln(t *testing.T) {
	vulnRecord := json.RawMessage(`{
		"id": "CVE-2024-NOVULNCWE",
		"cve": {
			"id": "CVE-2024-NOVULNCWE",
			"weaknesses": [],
			"configurations": [{"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:apache:log4j:2.14.0:*:*:*:*:*:*:*"}]}]}]
		}
	}`)

	mock := &mockBackend{
		vulns: []storage.VulnerabilityRow{
			{ID: "CVE-2024-NOVULNCWE", Record: vulnRecord},
		},
		controls: []storage.ControlRow{
			{
				ID:          "FW/C-1",
				Framework:   "FW",
				ControlID:   "C-1",
				Title:       "Test",
				RelatedCWEs: []string{"CWE-79"},
			},
		},
	}

	e := New(Config{Store: mock, Logger: testLogger()})
	count, err := e.mapByCPE(context.Background())
	if err != nil {
		t.Fatalf("mapByCPE error: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected 0 CPE mappings, got %d", count)
	}
}

func TestMapByCPE_ControlNoCWEs(t *testing.T) {
	vulnRecord := json.RawMessage(`{
		"id": "CVE-2024-CTRLNOCWE",
		"cve": {
			"id": "CVE-2024-CTRLNOCWE",
			"weaknesses": [{"description": [{"lang": "en", "value": "CWE-79"}]}],
			"configurations": [{"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:apache:log4j:2.14.0:*:*:*:*:*:*:*"}]}]}]
		}
	}`)

	mock := &mockBackend{
		vulns: []storage.VulnerabilityRow{
			{ID: "CVE-2024-CTRLNOCWE", Record: vulnRecord},
		},
		controls: []storage.ControlRow{
			{
				ID:        "FW/C-1",
				Framework: "FW",
				ControlID: "C-1",
				Title:     "Test",
			},
		},
	}

	e := New(Config{Store: mock, Logger: testLogger()})
	count, err := e.mapByCPE(context.Background())
	if err != nil {
		t.Fatalf("mapByCPE error: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected 0 CPE mappings, got %d", count)
	}
}

func TestMapByCPE_WriteMappingError(t *testing.T) {
	vulnRecord := json.RawMessage(`{
		"id": "CVE-2024-CPEERR",
		"cve": {
			"id": "CVE-2024-CPEERR",
			"weaknesses": [{"description": [{"lang": "en", "value": "CWE-79"}]}],
			"configurations": [{"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:apache:log4j:2.14.0:*:*:*:*:*:*:*"}]}]}]
		}
	}`)

	mock := &mappingWriteErrMock{
		mockBackend: mockBackend{
			vulns: []storage.VulnerabilityRow{
				{ID: "CVE-2024-CPEERR", Record: vulnRecord},
			},
			controls: []storage.ControlRow{
				{
					ID:          "FW/C-1",
					Framework:   "FW",
					ControlID:   "C-1",
					Title:       "Test",
					RelatedCWEs: []string{"CWE-79"},
				},
			},
		},
	}

	e := New(Config{Store: mock, Logger: testLogger()})
	count, err := e.mapByCPE(context.Background())
	if err != nil {
		t.Fatalf("mapByCPE error: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected 0 mappings on write error, got %d", count)
	}
}

func TestMapByCPE_ListVulnsError(t *testing.T) {
	mock := &vulnListErrMock{}

	e := New(Config{Store: mock, Logger: testLogger()})
	_, err := e.mapByCPE(context.Background())
	if err == nil {
		t.Fatal("expected error when ListAllVulnerabilities fails")
	}
}

func TestMapByCPE_ListControlsError(t *testing.T) {
	type listCtrlErrMock struct {
		mockBackend
	}

	mock := &listCtrlErrMock{
		mockBackend: mockBackend{
			vulns: []storage.VulnerabilityRow{
				{ID: "CVE-2024-LCERR", Record: json.RawMessage(`{
					"id": "CVE-2024-LCERR",
					"cve": {
						"id": "CVE-2024-LCERR",
						"weaknesses": [{"description": [{"lang": "en", "value": "CWE-79"}]}],
						"configurations": [{"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:apache:log4j:2.14.0:*:*:*:*:*:*:*"}]}]}]
					}
				}`)},
			},
		},
	}

	e := New(Config{Store: mock, Logger: testLogger()})
	count, err := e.mapByCPE(context.Background())
	if err != nil {
		t.Fatalf("mapByCPE error: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected 0 mappings with empty controls, got %d", count)
	}
}

func TestEnrichSBOM(t *testing.T) {
	mock := &mockBackend{
		controls: []storage.ControlRow{
			{
				ID:        "NIST_CSF_2_0/PR.IR-05",
				Framework: "NIST_CSF_2_0",
				ControlID: "PR.IR-05",
				Title:     "Secure development",
			},
			{
				ID:        "CIS_CONTROLS/v8/1.1",
				Framework: "CIS_CONTROLS",
				ControlID: "v8/1.1",
				Title:     "Inventory of Enterprise Assets",
			},
		},
	}

	e := New(Config{
		Store:  mock,
		Logger: testLogger(),
	})

	components := []grc.SBOMComponent{
		{
			Name:    "log4j-core",
			Version: "2.14.0",
			Type:    "library",
			CPEs:    []string{"cpe:2.3:a:apache:log4j:2.14.0:*:*:*:*:*:*:*"},
		},
		{
			Name:    "openssl",
			Version: "1.1.1k",
			Type:    "library",
			CPEs:    []string{},
		},
	}

	enriched, err := e.EnrichSBOM(context.Background(), components)
	if err != nil {
		t.Fatalf("EnrichSBOM error: %v", err)
	}
	if len(enriched) != 2 {
		t.Fatalf("expected 2 enriched components, got %d", len(enriched))
	}

	if enriched[0].ComplianceRisk != "needs-review" {
		t.Errorf("expected compliance risk 'needs-review', got %s", enriched[0].ComplianceRisk)
	}
	if len(enriched[0].Controls) != 2 {
		t.Errorf("expected 2 controls for log4j, got %d: %v", len(enriched[0].Controls), enriched[0].Controls)
	}

	if enriched[1].ComplianceRisk != "" {
		t.Errorf("expected empty compliance risk for openssl, got %s", enriched[1].ComplianceRisk)
	}
	if len(enriched[1].Controls) != 0 {
		t.Errorf("expected 0 controls for openssl, got %d", len(enriched[1].Controls))
	}
}

func TestEnrichSBOM_Empty(t *testing.T) {
	mock := &mockBackend{}

	e := New(Config{
		Store:  mock,
		Logger: testLogger(),
	})

	enriched, err := e.EnrichSBOM(context.Background(), nil)
	if err != nil {
		t.Fatalf("EnrichSBOM error: %v", err)
	}
	if len(enriched) != 0 {
		t.Fatalf("expected 0 enriched components, got %d", len(enriched))
	}
}

func TestEnrichSBOM_CPELookupError(t *testing.T) {
	mock := &cpeLookupErrMock{
		mockBackend: mockBackend{},
	}

	e := New(Config{Store: mock, Logger: testLogger()})

	components := []grc.SBOMComponent{
		{
			Name:    "log4j-core",
			Version: "2.14.0",
			Type:    "library",
			CPEs:    []string{"cpe:2.3:a:apache:log4j:2.14.0:*:*:*:*:*:*:*"},
		},
	}

	enriched, err := e.EnrichSBOM(context.Background(), components)
	if err != nil {
		t.Fatalf("EnrichSBOM error: %v", err)
	}
	if len(enriched) != 1 {
		t.Fatalf("expected 1 enriched component, got %d", len(enriched))
	}
	if enriched[0].ComplianceRisk != "" {
		t.Errorf("expected empty compliance risk on error, got %s", enriched[0].ComplianceRisk)
	}
}

func TestEnrichSBOM_WithRealDB(t *testing.T) {
	backend, err := storage.NewSQLiteBackend(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close(context.Background())

	vulnData := json.RawMessage(`{
		"id": "CVE-2024-SBOM",
		"cve": {
			"id": "CVE-2024-SBOM",
			"weaknesses": [{"description": [{"lang": "en", "value": "CWE-79"}]}],
			"configurations": [{"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:apache:log4j:2.14.0:*:*:*:*:*:*:*"}]}]}]
		}
	}`)
	if err := backend.WriteVulnerability(context.Background(), "CVE-2024-SBOM", vulnData); err != nil {
		t.Fatal(err)
	}

	ctrl := map[string]interface{}{
		"Framework":   "NIST_CSF_2_0",
		"ControlID":   "PR.IR-05",
		"Title":       "Secure development",
		"RelatedCWEs": []string{"CWE-79"},
	}
	if err := backend.WriteControl(context.Background(), "NIST_CSF_2_0/PR.IR-05", ctrl); err != nil {
		t.Fatal(err)
	}

	e := New(Config{Store: backend, Logger: testLogger()})

	components := []grc.SBOMComponent{
		{
			Name:    "log4j-core",
			Version: "2.14.0",
			Type:    "library",
			CPEs:    []string{"cpe:2.3:a:apache:log4j:2.14.0:*:*:*:*:*:*:*"},
		},
		{
			Name:    "no-match-lib",
			Version: "1.0.0",
			Type:    "library",
		},
	}

	enriched, err := e.EnrichSBOM(context.Background(), components)
	if err != nil {
		t.Fatalf("EnrichSBOM error: %v", err)
	}
	if len(enriched) != 2 {
		t.Fatalf("expected 2 enriched components, got %d", len(enriched))
	}
	if enriched[0].ComplianceRisk != "needs-review" {
		t.Errorf("expected 'needs-review', got %s", enriched[0].ComplianceRisk)
	}
	if len(enriched[0].Controls) == 0 {
		t.Error("expected controls for log4j component")
	}
	if enriched[1].ComplianceRisk != "" {
		t.Errorf("expected empty risk for no-match-lib, got %s", enriched[1].ComplianceRisk)
	}
}

type listAllControlsErrMock struct {
	mockBackend
}

func (m *listAllControlsErrMock) ListAllControls(_ context.Context) ([]storage.ControlRow, error) {
	return nil, fmt.Errorf("simulated list controls error")
}

func TestMapByCPEListControlsError(t *testing.T) {
	backend := &listAllControlsErrMock{
		mockBackend{
			vulns: []storage.VulnerabilityRow{
				{ID: "CVE-2024-0001", Record: json.RawMessage(`{"cpe": "cpe:2.3:a:test:1.0"}`)},
			},
		},
	}
	e := New(Config{Store: backend, Logger: testLogger()})
	_, err := e.mapByCPE(context.Background())
	if err == nil {
		t.Fatal("expected error from ListAllControls failure")
	}
}
