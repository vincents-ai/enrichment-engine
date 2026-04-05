package cyclonedx

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/shift/enrichment-engine/test"
)

func TestIntegration_MultipleVulnsMultipleFrameworks(t *testing.T) {
	store := test.SetupTestDB(t)
	ctx := context.Background()

	vulnIDs := []string{"CVE-2021-44228", "CVE-2024-3094", "CVE-2023-44487"}
	for _, id := range vulnIDs {
		err := store.WriteVulnerability(ctx, id, map[string]interface{}{
			"id": id,
			"cve": map[string]interface{}{
				"id":        id,
				"published": "2021-12-10T00:00:00.000Z",
			},
		})
		if err != nil {
			t.Fatalf("WriteVulnerability(%s): %v", id, err)
		}
	}

	controls := []struct {
		id, framework, title string
	}{
		{"HIPAA_SECURITY_RULE_2013/164.308(a)(1)(ii)(A)", "HIPAA_SECURITY_RULE_2013", "Risk Assessment"},
		{"PCI_DSS_v4/6.2.4", "PCI_DSS_v4", "Apply Security Patches"},
		{"PCI_DSS_v4/6.3.1", "PCI_DSS_v4", "Remove Unnecessary Services"},
		{"ISO_27001_2022/A.8.9", "ISO_27001_2022", "Configuration Management"},
		{"ISO_27001_2022/A.8.8", "ISO_27001_2022", "Management of Technical Vulnerabilities"},
	}
	for _, c := range controls {
		err := store.WriteControl(ctx, c.id, map[string]interface{}{
			"Framework":   c.framework,
			"ControlID":   strings.TrimPrefix(c.id, c.framework+"/"),
			"Title":       c.title,
			"RelatedCWEs": []string{"CWE-502"},
		})
		if err != nil {
			t.Fatalf("WriteControl(%s): %v", c.id, err)
		}
	}

	mappings := []struct {
		vuln, control, framework, mappingType string
		confidence                            float64
		evidence                              string
	}{
		{"CVE-2021-44228", "HIPAA_SECURITY_RULE_2013/164.308(a)(1)(ii)(A)", "HIPAA_SECURITY_RULE_2013", "cwe", 0.8, "CWE-502 direct match"},
		{"CVE-2021-44228", "PCI_DSS_v4/6.2.4", "PCI_DSS_v4", "cwe", 0.7, "CWE-502 shared"},
		{"CVE-2024-3094", "ISO_27001_2022/A.8.8", "ISO_27001_2022", "cwe", 0.9, "CWE-502 direct"},
		{"CVE-2023-44487", "PCI_DSS_v4/6.3.1", "PCI_DSS_v4", "cpe", 0.6, "HTTP/2 rapid reset"},
		{"CVE-2024-3094", "ISO_27001_2022/A.8.9", "ISO_27001_2022", "cwe", 0.75, "supply chain risk"},
	}
	for _, m := range mappings {
		err := store.WriteMapping(ctx, m.vuln, m.control, m.framework, m.mappingType, m.confidence, m.evidence)
		if err != nil {
			t.Fatalf("WriteMapping(%s->%s): %v", m.vuln, m.control, err)
		}
	}

	ser := NewSerializer(store)
	bom, err := ser.Serialize(ctx)
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}

	if bom.BOMFormat != "CycloneDX" {
		t.Errorf("BOMFormat = %q, want %q", bom.BOMFormat, "CycloneDX")
	}
	if bom.SpecVersion != "1.5" {
		t.Errorf("SpecVersion = %q, want %q", bom.SpecVersion, "1.5")
	}
	if !strings.HasPrefix(bom.SerialNumber, "urn:uuid:") {
		t.Errorf("SerialNumber = %q, want urn:uuid: prefix", bom.SerialNumber)
	}
	if len(bom.Metadata.Tools) == 0 || bom.Metadata.Tools[0].Name != "enrichment-engine" {
		t.Errorf("Metadata.Tools[0].Name = %v, want enrichment-engine", bom.Metadata.Tools)
	}
	if len(bom.Vulnerabilities) < 2 {
		t.Fatalf("Vulnerabilities len = %d, want >= 2", len(bom.Vulnerabilities))
	}

	for i, v := range bom.Vulnerabilities {
		if len(v.Affects) == 0 {
			t.Errorf("Vulnerabilities[%d] (%s) has no Affects entries", i, v.ID)
		}
		if len(v.Properties) == 0 {
			t.Errorf("Vulnerabilities[%d] (%s) has no Properties", i, v.ID)
		}
	}

	jsonData, err := ser.SerializeJSON(ctx)
	if err != nil {
		t.Fatalf("SerializeJSON: %v", err)
	}
	if !json.Valid(jsonData) {
		t.Error("SerializeJSON output is not valid JSON")
	}
	s := string(jsonData)
	if !strings.Contains(s, `"bomFormat"`) {
		t.Error("JSON missing bomFormat")
	}
	if !strings.Contains(s, `"specVersion"`) {
		t.Error("JSON missing specVersion")
	}
}

func TestIntegration_EmptyVulnsWithControls(t *testing.T) {
	store := test.SetupTestDB(t)
	ctx := context.Background()

	controls := []struct {
		id, framework, title string
	}{
		{"HIPAA_SECURITY_RULE_2013/164.308(a)(1)(ii)(A)", "HIPAA_SECURITY_RULE_2013", "Risk Assessment"},
		{"PCI_DSS_v4/6.2.4", "PCI_DSS_v4", "Apply Security Patches"},
		{"ISO_27001_2022/A.8.8", "ISO_27001_2022", "Management of Technical Vulnerabilities"},
	}
	for _, c := range controls {
		err := store.WriteControl(ctx, c.id, map[string]interface{}{
			"Framework":   c.framework,
			"ControlID":   strings.TrimPrefix(c.id, c.framework+"/"),
			"Title":       c.title,
			"RelatedCWEs": []string{"CWE-502"},
		})
		if err != nil {
			t.Fatalf("WriteControl(%s): %v", c.id, err)
		}
	}

	ser := NewSerializer(store)
	bom, err := ser.Serialize(ctx)
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}

	if len(bom.Vulnerabilities) != 0 {
		t.Errorf("Vulnerabilities len = %d, want 0", len(bom.Vulnerabilities))
	}

	if len(bom.Components) == 0 {
		t.Fatal("Components is empty")
	}

	found := false
	for _, p := range bom.Components[0].Properties {
		if p.Name == "total_controls" {
			if p.Value == "0" {
				t.Errorf("total_controls = %q, want > 0", p.Value)
			}
			found = true
			break
		}
	}
	if !found {
		t.Error("missing total_controls property")
	}
}

func TestIntegration_WithOptions(t *testing.T) {
	store := test.SetupTestDB(t)
	ctx := context.Background()

	err := store.WriteVulnerability(ctx, "CVE-2021-44228", map[string]interface{}{
		"id":  "CVE-2021-44228",
		"cve": map[string]interface{}{"id": "CVE-2021-44228"},
	})
	if err != nil {
		t.Fatalf("WriteVulnerability: %v", err)
	}

	err = store.WriteControl(ctx, "ctrl-1", map[string]interface{}{
		"Framework":   "HIPAA",
		"ControlID":   "164.308(a)(1)",
		"Title":       "Security Management Process",
		"RelatedCWEs": []string{"CWE-502"},
	})
	if err != nil {
		t.Fatalf("WriteControl: %v", err)
	}

	err = store.WriteMapping(ctx, "CVE-2021-44228", "ctrl-1", "HIPAA", "cwe", 0.8, "CWE-502 shared")
	if err != nil {
		t.Fatalf("WriteMapping: %v", err)
	}

	ser := NewSerializer(store, WithToolName("custom-tool"), WithToolVersion("1.2.3"))
	bom, err := ser.Serialize(ctx)
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}

	if len(bom.Metadata.Tools) == 0 || bom.Metadata.Tools[0].Name != "custom-tool" {
		t.Errorf("Tools[0].Name = %v, want custom-tool", bom.Metadata.Tools)
	}
	if bom.Metadata.Tools[0].Version != "1.2.3" {
		t.Errorf("Tools[0].Version = %q, want %q", bom.Metadata.Tools[0].Version, "1.2.3")
	}
}

func TestIntegration_MultipleMappingsPerVuln(t *testing.T) {
	store := test.SetupTestDB(t)
	ctx := context.Background()

	err := store.WriteVulnerability(ctx, "CVE-2021-44228", map[string]interface{}{
		"id":  "CVE-2021-44228",
		"cve": map[string]interface{}{"id": "CVE-2021-44228"},
	})
	if err != nil {
		t.Fatalf("WriteVulnerability: %v", err)
	}

	controls := []struct {
		id, framework, title string
	}{
		{"HIPAA_SECURITY_RULE_2013/164.308(a)(1)(ii)(A)", "HIPAA_SECURITY_RULE_2013", "Risk Assessment"},
		{"PCI_DSS_v4/6.2.4", "PCI_DSS_v4", "Apply Security Patches"},
		{"PCI_DSS_v4/6.3.1", "PCI_DSS_v4", "Remove Unnecessary Services"},
		{"ISO_27001_2022/A.8.8", "ISO_27001_2022", "Management of Technical Vulnerabilities"},
		{"ISO_27001_2022/A.8.9", "ISO_27001_2022", "Configuration Management"},
	}
	for _, c := range controls {
		err := store.WriteControl(ctx, c.id, map[string]interface{}{
			"Framework":   c.framework,
			"ControlID":   strings.TrimPrefix(c.id, c.framework+"/"),
			"Title":       c.title,
			"RelatedCWEs": []string{"CWE-502"},
		})
		if err != nil {
			t.Fatalf("WriteControl(%s): %v", c.id, err)
		}
	}

	for _, c := range controls {
		err := store.WriteMapping(ctx, "CVE-2021-44228", c.id, c.framework, "cwe", 0.8, "CWE-502 direct match")
		if err != nil {
			t.Fatalf("WriteMapping(%s->%s): %v", "CVE-2021-44228", c.id, err)
		}
	}

	ser := NewSerializer(store)
	bom, err := ser.Serialize(ctx)
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}

	if len(bom.Vulnerabilities) != 1 {
		t.Fatalf("Vulnerabilities len = %d, want 1", len(bom.Vulnerabilities))
	}

	vuln := bom.Vulnerabilities[0]
	if vuln.ID != "CVE-2021-44228" {
		t.Errorf("Vulnerability ID = %q, want CVE-2021-44228", vuln.ID)
	}

	if len(vuln.Affects) != 5 {
		t.Errorf("Affects len = %d, want 5", len(vuln.Affects))
	}

	mappingCount := 0
	for _, p := range vuln.Properties {
		if strings.HasPrefix(p.Name, "mapping:") {
			mappingCount++
		}
	}
	if mappingCount != 5 {
		t.Errorf("found %d mapping properties, want 5", mappingCount)
	}
}
