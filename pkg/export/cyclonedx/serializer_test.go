package cyclonedx

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/vincents-ai/enrichment-engine/test"
)

func TestSerialize_Empty(t *testing.T) {
	store := test.SetupTestDB(t)
	ctx := context.Background()

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
	if bom.Version != 1 {
		t.Errorf("Version = %d, want 1", bom.Version)
	}
	if bom.Metadata == nil {
		t.Fatal("Metadata is nil")
	}
	if len(bom.Metadata.Tools) != 1 || bom.Metadata.Tools[0].Name != "enrichment-engine" {
		t.Errorf("Tools = %v, want [{enrichment-engine dev}]", bom.Metadata.Tools)
	}
	if len(bom.Components) != 1 {
		t.Fatalf("Components len = %d, want 1", len(bom.Components))
	}
	if bom.Components[0].Type != "application" {
		t.Errorf("Component type = %q, want %q", bom.Components[0].Type, "application")
	}
	if len(bom.Vulnerabilities) != 0 {
		t.Errorf("Vulnerabilities len = %d, want 0", len(bom.Vulnerabilities))
	}

	props := bom.Components[0].Properties
	foundTotalVulns := false
	foundTotalCtrls := false
	for _, p := range props {
		if p.Name == "total_vulnerabilities" && p.Value == "0" {
			foundTotalVulns = true
		}
		if p.Name == "total_controls" && p.Value == "0" {
			foundTotalCtrls = true
		}
	}
	if !foundTotalVulns {
		t.Error("missing total_vulnerabilities=0 property")
	}
	if !foundTotalCtrls {
		t.Error("missing total_controls=0 property")
	}
}

func TestSerialize_WithVulnAndMappings(t *testing.T) {
	store := test.SetupTestDB(t)
	ctx := context.Background()

	store.WriteVulnerability(ctx, "CVE-2021-44228", map[string]interface{}{
		"id":  "CVE-2021-44228",
		"cve": map[string]interface{}{"id": "CVE-2021-44228"},
	})
	store.WriteControl(ctx, "ctrl-1", map[string]interface{}{
		"Framework":   "HIPAA",
		"ControlID":   "§164.308(a)(1)",
		"Title":       "Security Management Process",
		"RelatedCWEs": []string{"CWE-502"},
	})
	store.WriteMapping(ctx, "CVE-2021-44228", "ctrl-1", "HIPAA", "cwe", 0.8, "CWE-502 shared")

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
		t.Errorf("Vulnerability ID = %q, want %q", vuln.ID, "CVE-2021-44228")
	}
	if vuln.Source == nil || vuln.Source.Name != "NVD" {
		t.Errorf("Source.Name = %v, want NVD", vuln.Source)
	}
	if len(vuln.Affects) != 1 {
		t.Fatalf("Affects len = %d, want 1", len(vuln.Affects))
	}
	if vuln.Affects[0].Ref != "ctrl-1" {
		t.Errorf("Affects[0].Ref = %q, want %q", vuln.Affects[0].Ref, "ctrl-1")
	}

	foundMappingProp := false
	foundCtrlTitle := false
	for _, p := range vuln.Properties {
		if p.Name == "mapping:ctrl-1:cwe" && strings.Contains(p.Value, "framework=HIPAA") && strings.Contains(p.Value, "confidence=0.80") {
			foundMappingProp = true
		}
		if p.Name == "control:ctrl-1:title" && p.Value == "Security Management Process" {
			foundCtrlTitle = true
		}
	}
	if !foundMappingProp {
		t.Error("missing mapping:ctrl-1:cwe property")
	}
	if !foundCtrlTitle {
		t.Error("missing control:ctrl-1:title property")
	}

	props := bom.Components[0].Properties
	foundFrameworks := false
	for _, p := range props {
		if p.Name == "frameworks" {
			var list []string
			if err := json.Unmarshal([]byte(p.Value), &list); err != nil {
				t.Fatalf("unmarshal frameworks: %v", err)
			}
			if len(list) != 1 || list[0] != "HIPAA" {
				t.Errorf("frameworks = %v, want [HIPAA]", list)
			}
			foundFrameworks = true
		}
	}
	if !foundFrameworks {
		t.Error("missing frameworks property")
	}
}

func TestSerializeJSON(t *testing.T) {
	store := test.SetupTestDB(t)
	ctx := context.Background()

	store.WriteVulnerability(ctx, "CVE-2021-44228", map[string]interface{}{
		"id":  "CVE-2021-44228",
		"cve": map[string]interface{}{"id": "CVE-2021-44228"},
	})
	store.WriteControl(ctx, "ctrl-1", map[string]interface{}{
		"Framework": "HIPAA",
		"ControlID": "§164.308(a)(1)",
		"Title":     "Security Management Process",
	})
	store.WriteMapping(ctx, "CVE-2021-44228", "ctrl-1", "HIPAA", "cwe", 0.8, "CWE-502 shared")

	ser := NewSerializer(store)
	data, err := ser.SerializeJSON(ctx)
	if err != nil {
		t.Fatalf("SerializeJSON: %v", err)
	}

	if !json.Valid(data) {
		t.Error("output is not valid JSON")
	}
	if !strings.Contains(string(data), `"bomFormat": "CycloneDX"`) {
		t.Error("missing bomFormat in JSON output")
	}
	if !strings.Contains(string(data), `"specVersion": "1.5"`) {
		t.Error("missing specVersion in JSON output")
	}
}

func TestNewSerializer_Defaults(t *testing.T) {
	store := test.SetupTestDB(t)

	ser := NewSerializer(store)
	if ser.toolName != "enrichment-engine" {
		t.Errorf("toolName = %q, want %q", ser.toolName, "enrichment-engine")
	}
	if ser.toolVer != "dev" {
		t.Errorf("toolVer = %q, want %q", ser.toolVer, "dev")
	}
}

func TestNewSerializer_Options(t *testing.T) {
	store := test.SetupTestDB(t)

	ser := NewSerializer(store, WithToolName("custom-tool"), WithToolVersion("1.2.3"))
	if ser.toolName != "custom-tool" {
		t.Errorf("toolName = %q, want %q", ser.toolName, "custom-tool")
	}
	if ser.toolVer != "1.2.3" {
		t.Errorf("toolVer = %q, want %q", ser.toolVer, "1.2.3")
	}
}
