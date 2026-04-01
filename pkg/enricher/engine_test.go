package enricher

import (
	"context"
	"encoding/json"
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

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(&discardWriter{}, &slog.HandlerOptions{Level: slog.LevelInfo}))
}

type discardWriter struct{}

func (d *discardWriter) Write(p []byte) (n int, err error) {
	return len(p), nil
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
