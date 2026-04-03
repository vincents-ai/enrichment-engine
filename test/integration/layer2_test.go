package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"

	"github.com/shift/enrichment-engine/pkg/enricher"
	"github.com/shift/enrichment-engine/pkg/grc"
	grcbuiltin "github.com/shift/enrichment-engine/pkg/grc/builtin"
)

func TestLayer2_FullPipelineMultipleProviders(t *testing.T) {
	backend := setupTestDB(t)
	ctx := context.Background()
	logger := testLogger()

	providerNames := []string{"hipaa", "gdpr", "iso27001"}
	registry := grcbuiltin.DefaultRegistry()

	for _, name := range providerNames {
		p, err := registry.Get(name, backend, logger)
		if err != nil {
			t.Fatalf("get provider %s: %v", name, err)
		}
		count, err := p.Run(ctx)
		if err != nil {
			t.Fatalf("run provider %s: %v", name, err)
		}
		if count <= 0 {
			t.Fatalf("provider %s wrote 0 controls", name)
		}
	}

	vulnRecord := map[string]interface{}{
		"id": "CVE-2024-L2-PIPE",
		"cve": map[string]interface{}{
			"id": "CVE-2024-L2-PIPE",
			"weaknesses": []map[string]interface{}{
				{"description": []map[string]string{{"lang": "en", "value": "CWE-79"}}},
			},
			"configurations": []interface{}{},
		},
	}
	if err := backend.WriteVulnerability(ctx, "CVE-2024-L2-PIPE", vulnRecord); err != nil {
		t.Fatalf("write vulnerability: %v", err)
	}

	engine := enricher.New(enricher.Config{
		Store:         backend,
		Logger:        logger,
		SkipProviders: true,
	})
	result, err := engine.Run(ctx)
	if err != nil {
		t.Fatalf("engine run: %v", err)
	}

	if result.MappingCount < 1 {
		t.Fatalf("expected at least 1 mapping from CWE-79 vuln, got %d", result.MappingCount)
	}

	mappings, err := backend.ListMappings(ctx, "CVE-2024-L2-PIPE")
	if err != nil {
		t.Fatalf("list mappings: %v", err)
	}
	if len(mappings) == 0 {
		t.Fatal("no mappings in DB for CVE-2024-L2-PIPE")
	}

	frameworks := make(map[string]bool)
	for _, m := range mappings {
		frameworks[m.Framework] = true
		if m.Confidence != 0.8 {
			t.Errorf("mapping to %s has confidence %f, expected 0.8", m.ControlID, m.Confidence)
		}
		if m.MappingType != "cwe" {
			t.Errorf("mapping to %s has type %q, expected cwe", m.ControlID, m.MappingType)
		}
	}

	for _, fw := range []string{"HIPAA_SECURITY_RULE_2013", "GDPR_2016_679", "ISO_27001_2022"} {
		if frameworks[fw] {
			t.Logf("CWE-79 mapping found in framework %s", fw)
		}
	}
}

func TestLayer2_CWEMappingCorrectness(t *testing.T) {
	backend := setupTestDB(t)
	ctx := context.Background()

	cweVulns := []struct {
		id   string
		cwe  string
		desc string
	}{
		{"CVE-2024-L2-CWE1", "CWE-79", "XSS"},
		{"CVE-2024-L2-CWE2", "CWE-89", "SQLi"},
		{"CVE-2024-L2-CWE3", "CWE-120", "Buffer Overflow"},
		{"CVE-2024-L2-CWE4", "CWE-287", "Auth Bypass"},
	}

	for _, v := range cweVulns {
		rec := map[string]interface{}{
			"id": v.id,
			"cve": map[string]interface{}{
				"id": v.id,
				"weaknesses": []map[string]interface{}{
					{"description": []map[string]string{{"lang": "en", "value": v.cwe}}},
				},
				"configurations": []interface{}{},
			},
		}
		if err := backend.WriteVulnerability(ctx, v.id, rec); err != nil {
			t.Fatalf("write vuln %s: %v", v.id, err)
		}
	}

	testControls := []struct {
		framework string
		controlID string
		title     string
		cwes      []string
	}{
		{"FW_A", "CTRL-1", "Input Validation", []string{"CWE-79", "CWE-89"}},
		{"FW_A", "CTRL-2", "Memory Safety", []string{"CWE-120"}},
		{"FW_B", "CTRL-1", "Access Control", []string{"CWE-287", "CWE-862"}},
		{"FW_B", "CTRL-3", "Unrelated Control", []string{"CWE-200"}},
	}

	for _, tc := range testControls {
		ctrl := grc.Control{
			Framework:   tc.framework,
			ControlID:   tc.controlID,
			Title:       tc.title,
			Description: tc.title + " description",
			RelatedCWEs: tc.cwes,
		}
		id := fmt.Sprintf("%s/%s", tc.framework, tc.controlID)
		if err := backend.WriteControl(ctx, id, ctrl); err != nil {
			t.Fatalf("write control %s: %v", id, err)
		}
	}

	engine := enricher.New(enricher.Config{
		Store:         backend,
		Logger:        testLogger(),
		SkipProviders: true,
	})
	result, err := engine.Run(ctx)
	if err != nil {
		t.Fatalf("engine run: %v", err)
	}

	expectedMappings := map[string][]string{
		"CVE-2024-L2-CWE1": {"FW_A/CTRL-1"},
		"CVE-2024-L2-CWE2": {"FW_A/CTRL-1"},
		"CVE-2024-L2-CWE3": {"FW_A/CTRL-2"},
		"CVE-2024-L2-CWE4": {"FW_B/CTRL-1"},
	}

	for vulnID, expectedCtrls := range expectedMappings {
		mappings, err := backend.ListMappings(ctx, vulnID)
		if err != nil {
			t.Fatalf("list mappings for %s: %v", vulnID, err)
		}

		found := make(map[string]bool)
		for _, m := range mappings {
			if m.Confidence != 0.8 {
				t.Errorf("mapping %s -> %s: confidence %f, expected 0.8", vulnID, m.ControlID, m.Confidence)
			}
			if m.MappingType != "cwe" {
				t.Errorf("mapping %s -> %s: type %q, expected cwe", vulnID, m.ControlID, m.MappingType)
			}
			found[m.ControlID] = true
		}

		for _, ec := range expectedCtrls {
			if !found[ec] {
				t.Errorf("missing mapping %s -> %s", vulnID, ec)
			}
		}
	}

	mappings, _ := backend.ListMappings(ctx, "CVE-2024-L2-CWE4")
	for _, m := range mappings {
		if m.ControlID == "FW_B/CTRL-3" {
			t.Errorf("CWE-287 should not map to unrelated control FW_B/CTRL-3 (CWE-200)")
		}
	}

	if result.MappingCount < 4 {
		t.Errorf("expected at least 4 CWE mappings, got %d", result.MappingCount)
	}
}

func TestLayer2_CPEIndirectMapping(t *testing.T) {
	backend := setupTestDB(t)
	ctx := context.Background()

	vulnWithCPE := map[string]interface{}{
		"id": "CVE-2024-L2-CPE",
		"cve": map[string]interface{}{
			"id": "CVE-2024-L2-CPE",
			"weaknesses": []map[string]interface{}{
				{"description": []map[string]string{{"lang": "en", "value": "CWE-79"}}},
			},
			"configurations": []map[string]interface{}{
				{"nodes": []map[string]interface{}{
					{"cpeMatch": []map[string]string{
						{"criteria": "cpe:2.3:a:apache:log4j:2.14.0:*:*:*:*:*:*:*"},
					}},
				}},
			},
		},
	}
	if err := backend.WriteVulnerability(ctx, "CVE-2024-L2-CPE", vulnWithCPE); err != nil {
		t.Fatalf("write vuln: %v", err)
	}

	ctrl := grc.Control{
		Framework:   "TEST_CPE_FW",
		ControlID:   "CPE-CTRL-1",
		Title:       "XSS Prevention",
		Description: "Prevent cross-site scripting",
		RelatedCWEs: []string{"CWE-79"},
	}
	if err := backend.WriteControl(ctx, "TEST_CPE_FW/CPE-CTRL-1", ctrl); err != nil {
		t.Fatalf("write control: %v", err)
	}

	engine := enricher.New(enricher.Config{
		Store:         backend,
		Logger:        testLogger(),
		SkipProviders: true,
	})
	result, err := engine.Run(ctx)
	if err != nil {
		t.Fatalf("engine run: %v", err)
	}

	mappings, err := backend.ListMappings(ctx, "CVE-2024-L2-CPE")
	if err != nil {
		t.Fatalf("list mappings: %v", err)
	}
	if len(mappings) == 0 {
		t.Fatalf("expected mappings for CPE vuln, got 0")
	}

	for _, m := range mappings {
		if m.ControlID == "TEST_CPE_FW/CPE-CTRL-1" {
			if m.Confidence != 0.6 {
				t.Errorf("CPE indirect mapping confidence: got %f, expected 0.6", m.Confidence)
			}
			if m.MappingType != "cpe" {
				t.Errorf("CPE indirect mapping type: got %q, expected cpe", m.MappingType)
			}
		}
	}

	t.Logf("CPE indirect mapping: %d total mappings (engine reported %d)", len(mappings), result.MappingCount)
}

func TestLayer2_CPEOnlyMapping_NoOverwrite(t *testing.T) {
	backend := setupTestDB(t)
	ctx := context.Background()

	vulnNoCPE := map[string]interface{}{
		"id": "CVE-2024-L2-NOCPE",
		"cve": map[string]interface{}{
			"id": "CVE-2024-L2-NOCPE",
			"weaknesses": []map[string]interface{}{
				{"description": []map[string]string{{"lang": "en", "value": "CWE-89"}}},
			},
			"configurations": []interface{}{},
		},
	}
	if err := backend.WriteVulnerability(ctx, "CVE-2024-L2-NOCPE", vulnNoCPE); err != nil {
		t.Fatalf("write vuln: %v", err)
	}

	ctrl := grc.Control{
		Framework:   "TEST_NOCPE_FW",
		ControlID:   "NOCPE-CTRL-1",
		Title:       "SQL Injection Prevention",
		Description: "Prevent SQL injection",
		RelatedCWEs: []string{"CWE-89"},
	}
	if err := backend.WriteControl(ctx, "TEST_NOCPE_FW/NOCPE-CTRL-1", ctrl); err != nil {
		t.Fatalf("write control: %v", err)
	}

	engine := enricher.New(enricher.Config{
		Store:         backend,
		Logger:        testLogger(),
		SkipProviders: true,
	})
	_, err := engine.Run(ctx)
	if err != nil {
		t.Fatalf("engine run: %v", err)
	}

	mappings, err := backend.ListMappings(ctx, "CVE-2024-L2-NOCPE")
	if err != nil {
		t.Fatalf("list mappings: %v", err)
	}
	if len(mappings) == 0 {
		t.Fatal("expected mapping for vuln without CPE")
	}

	for _, m := range mappings {
		if m.ControlID == "TEST_NOCPE_FW/NOCPE-CTRL-1" {
			if m.Confidence != 0.8 {
				t.Errorf("no-CPE vuln mapping confidence: got %f, expected 0.8", m.Confidence)
			}
			if m.MappingType != "cwe" {
				t.Errorf("no-CPE vuln mapping type: got %q, expected cwe", m.MappingType)
			}
		}
	}
}

func TestLayer2_ProviderIsolation(t *testing.T) {
	backend := setupTestDB(t)
	ctx := context.Background()
	logger := testLogger()
	registry := grcbuiltin.DefaultRegistry()

	p1, err := registry.Get("hipaa", backend, logger)
	if err != nil {
		t.Fatalf("get hipaa: %v", err)
	}
	count1, err := p1.Run(ctx)
	if err != nil {
		t.Fatalf("run hipaa: %v", err)
	}

	hipaaCtrls, err := backend.ListControlsByFramework(ctx, "HIPAA_SECURITY_RULE_2013")
	if err != nil {
		t.Fatalf("list hipaa controls: %v", err)
	}
	if len(hipaaCtrls) == 0 {
		t.Fatal("no hipaa controls after hipaa provider run")
	}

	gdprCtrlsBefore, _ := backend.ListControlsByFramework(ctx, "GDPR_2016_679")

	p2, err := registry.Get("gdpr", backend, logger)
	if err != nil {
		t.Fatalf("get gdpr: %v", err)
	}
	count2, err := p2.Run(ctx)
	if err != nil {
		t.Fatalf("run gdpr: %v", err)
	}

	hipaaCtrlsAfter, err := backend.ListControlsByFramework(ctx, "HIPAA_SECURITY_RULE_2013")
	if err != nil {
		t.Fatalf("list hipaa controls after gdpr: %v", err)
	}
	if len(hipaaCtrlsAfter) != len(hipaaCtrls) {
		t.Errorf("HIPAA controls changed after GDPR run: before=%d, after=%d",
			len(hipaaCtrls), len(hipaaCtrlsAfter))
	}

	gdprCtrlsAfter, err := backend.ListControlsByFramework(ctx, "GDPR_2016_679")
	if err != nil {
		t.Fatalf("list gdpr controls: %v", err)
	}
	if len(gdprCtrlsAfter) <= len(gdprCtrlsBefore) {
		t.Errorf("GDPR controls did not increase: before=%d, after=%d",
			len(gdprCtrlsBefore), len(gdprCtrlsAfter))
	}

	allCtrls, err := backend.ListAllControls(ctx)
	if err != nil {
		t.Fatalf("list all controls: %v", err)
	}
	if len(allCtrls) != count1+count2 {
		t.Errorf("total controls %d != hipaa(%d) + gdpr(%d)", len(allCtrls), count1, count2)
	}
}

func TestLayer2_ReadAfterWriteFieldPreservation(t *testing.T) {
	backend := setupTestDB(t)
	ctx := context.Background()

	original := grc.Control{
		Framework:   "FIELD_TEST_FW",
		ControlID:   "FIELD-001",
		Title:       "Field Preservation Test",
		Family:      "Security Family",
		Description: "This is a detailed description for field preservation testing.",
		Level:       "high",
		RelatedCWEs: []string{"CWE-79", "CWE-89", "CWE-120"},
		RelatedCVEs: []string{"CVE-2024-0001", "CVE-2024-0002"},
		References: []grc.Reference{
			{Source: "NIST", URL: "https://example.com/ref1", Section: "3.1"},
			{Source: "ISO", URL: "https://example.com/ref2", Section: "5.2"},
		},
		ImplementationGuidance: "Implement input validation and parameterized queries.",
		AssessmentMethods:      []string{"interview", "observation", "testing"},
	}

	id := "FIELD_TEST_FW/FIELD-001"
	if err := backend.WriteControl(ctx, id, original); err != nil {
		t.Fatalf("write control: %v", err)
	}

	data, err := backend.ReadControl(ctx, id)
	if err != nil {
		t.Fatalf("read control: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("empty record read back")
	}

	var readBack grc.Control
	if err := json.Unmarshal(data, &readBack); err != nil {
		t.Fatalf("unmarshal control: %v", err)
	}

	if readBack.Framework != original.Framework {
		t.Errorf("Framework: got %q, want %q", readBack.Framework, original.Framework)
	}
	if readBack.ControlID != original.ControlID {
		t.Errorf("ControlID: got %q, want %q", readBack.ControlID, original.ControlID)
	}
	if readBack.Title != original.Title {
		t.Errorf("Title: got %q, want %q", readBack.Title, original.Title)
	}
	if readBack.Family != original.Family {
		t.Errorf("Family: got %q, want %q", readBack.Family, original.Family)
	}
	if readBack.Description != original.Description {
		t.Errorf("Description: got %q, want %q", readBack.Description, original.Description)
	}
	if readBack.Level != original.Level {
		t.Errorf("Level: got %q, want %q", readBack.Level, original.Level)
	}
	if len(readBack.RelatedCWEs) != len(original.RelatedCWEs) {
		t.Errorf("RelatedCWEs count: got %d, want %d", len(readBack.RelatedCWEs), len(original.RelatedCWEs))
	}
	for i, cwe := range readBack.RelatedCWEs {
		if cwe != original.RelatedCWEs[i] {
			t.Errorf("RelatedCWEs[%d]: got %q, want %q", i, cwe, original.RelatedCWEs[i])
		}
	}
	if len(readBack.RelatedCVEs) != len(original.RelatedCVEs) {
		t.Errorf("RelatedCVEs count: got %d, want %d", len(readBack.RelatedCVEs), len(original.RelatedCVEs))
	}
	if len(readBack.References) != len(original.References) {
		t.Errorf("References count: got %d, want %d", len(readBack.References), len(original.References))
	}
	if readBack.ImplementationGuidance != original.ImplementationGuidance {
		t.Errorf("ImplementationGuidance: got %q, want %q", readBack.ImplementationGuidance, original.ImplementationGuidance)
	}
	if len(readBack.AssessmentMethods) != len(original.AssessmentMethods) {
		t.Errorf("AssessmentMethods count: got %d, want %d", len(readBack.AssessmentMethods), len(original.AssessmentMethods))
	}

	ctrlRow, err := backend.ReadControl(ctx, id)
	if err != nil {
		t.Fatalf("read control raw: %v", err)
	}
	if !json.Valid(ctrlRow) {
		t.Error("raw control record is not valid JSON")
	}
}

func TestLayer2_FrameworkFiltering(t *testing.T) {
	backend := setupTestDB(t)
	ctx := context.Background()
	logger := testLogger()
	registry := grcbuiltin.DefaultRegistry()

	targetProviders := []string{"hipaa", "gdpr", "iso27001", "nist_csf", "pci_dss"}
	for _, name := range targetProviders {
		p, err := registry.Get(name, backend, logger)
		if err != nil {
			t.Fatalf("get provider %s: %v", name, err)
		}
		if _, err := p.Run(ctx); err != nil {
			t.Fatalf("run provider %s: %v", name, err)
		}
	}

	frameworkTests := []struct {
		framework string
		checkID   string
	}{
		{"HIPAA_SECURITY_RULE_2013", "164.312(a)(1)"},
		{"GDPR_2016_679", ""},
		{"ISO_27001_2022", ""},
		{"NIST_CSF_2_0", ""},
		{"PCI_DSS_v4", ""},
	}

	for _, ft := range frameworkTests {
		ctrls, err := backend.ListControlsByFramework(ctx, ft.framework)
		if err != nil {
			t.Fatalf("list controls for %s: %v", ft.framework, err)
		}
		if len(ctrls) == 0 {
			t.Errorf("no controls returned for framework %s", ft.framework)
			continue
		}

		for _, c := range ctrls {
			if c.Framework != ft.framework {
				t.Errorf("framework filtering leak: control %s has framework %q, expected %q",
					c.ID, c.Framework, ft.framework)
			}
		}

		if ft.checkID != "" {
			found := false
			for _, c := range ctrls {
				if c.ControlID == ft.checkID {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected control %s in framework %s, not found", ft.checkID, ft.framework)
			}
		}

		t.Logf("framework %s: %d controls", ft.framework, len(ctrls))
	}

	nonExistent, err := backend.ListControlsByFramework(ctx, "NONEXISTENT_FRAMEWORK")
	if err != nil {
		t.Fatalf("list nonexistent framework: %v", err)
	}
	if len(nonExistent) != 0 {
		t.Errorf("expected 0 controls for nonexistent framework, got %d", len(nonExistent))
	}
}

func TestLayer2_ConcurrentProviderExecution(t *testing.T) {
	backend := setupTestDB(t)
	ctx := context.Background()
	logger := testLogger()
	registry := grcbuiltin.DefaultRegistry()

	providerNames := []string{"hipaa", "gdpr", "iso27001", "nist_csf", "soc2", "pci_dss"}
	results := make(map[string]int)
	var mu sync.Mutex
	var wg sync.WaitGroup
	errors := make([]error, 0)

	for _, name := range providerNames {
		wg.Add(1)
		go func(pName string) {
			defer wg.Done()
			p, err := registry.Get(pName, backend, logger)
			if err != nil {
				mu.Lock()
				errors = append(errors, fmt.Errorf("get %s: %w", pName, err))
				mu.Unlock()
				return
			}
			count, err := p.Run(ctx)
			if err != nil {
				mu.Lock()
				errors = append(errors, fmt.Errorf("run %s: %w", pName, err))
				mu.Unlock()
				return
			}
			mu.Lock()
			results[pName] = count
			mu.Unlock()
		}(name)
	}

	wg.Wait()

	if len(errors) > 0 {
		for _, e := range errors {
			t.Errorf("concurrent provider error: %v", e)
		}
	}

	totalFromResults := 0
	for name, count := range results {
		if count <= 0 {
			t.Errorf("provider %s wrote 0 controls concurrently", name)
		}
		totalFromResults += count
	}

	allCtrls, err := backend.ListAllControls(ctx)
	if err != nil {
		t.Fatalf("list all controls: %v", err)
	}

	frameworks := make(map[string]bool)
	for _, c := range allCtrls {
		frameworks[c.Framework] = true
	}

	expectedFrameworks := map[string]bool{
		"HIPAA_SECURITY_RULE_2013": true,
		"GDPR_2016_679":            true,
		"ISO_27001_2022":           true,
		"NIST_CSF_2_0":             true,
		"SOC2_TSC_2017":            true,
		"PCI_DSS_v4":               true,
	}
	for fw := range expectedFrameworks {
		if !frameworks[fw] {
			t.Errorf("missing framework %s after concurrent execution", fw)
		}
	}

	t.Logf("concurrent providers: %d providers, %d total controls from results, %d controls in DB",
		len(providerNames), totalFromResults, len(allCtrls))
}

func TestLayer2_EnrichSBOMWithRealData(t *testing.T) {
	backend := setupTestDB(t)
	ctx := context.Background()
	logger := testLogger()
	registry := grcbuiltin.DefaultRegistry()

	p, err := registry.Get("hipaa", backend, logger)
	if err != nil {
		t.Fatalf("get hipaa: %v", err)
	}
	if _, err := p.Run(ctx); err != nil {
		t.Fatalf("run hipaa: %v", err)
	}

	ctrl := grc.Control{
		Framework:   "SBOM_TEST_FW",
		ControlID:   "SBOM-CTRL-1",
		Title:       "Third-Party Component Security",
		Description: "Validate third-party components",
		RelatedCWEs: []string{"CWE-79"},
	}
	if err := backend.WriteControl(ctx, "SBOM_TEST_FW/SBOM-CTRL-1", ctrl); err != nil {
		t.Fatalf("write control: %v", err)
	}

	vulnForCPE := map[string]interface{}{
		"id": "CVE-2024-SBOM-TEST",
		"cve": map[string]interface{}{
			"id": "CVE-2024-SBOM-TEST",
			"weaknesses": []map[string]interface{}{
				{"description": []map[string]string{{"lang": "en", "value": "CWE-79"}}},
			},
			"configurations": []map[string]interface{}{
				{"nodes": []map[string]interface{}{
					{"cpeMatch": []map[string]string{
						{"criteria": "cpe:2.3:a:apache:log4j:2.14.0:*:*:*:*:*:*:*"},
					}},
				}},
			},
		},
	}
	if err := backend.WriteVulnerability(ctx, "CVE-2024-SBOM-TEST", vulnForCPE); err != nil {
		t.Fatalf("write vuln: %v", err)
	}

	vulnForNginx := map[string]interface{}{
		"id": "CVE-2024-NGINX-TEST",
		"cve": map[string]interface{}{
			"id": "CVE-2024-NGINX-TEST",
			"weaknesses": []map[string]interface{}{
				{"description": []map[string]string{{"lang": "en", "value": "CWE-79"}}},
			},
			"configurations": []map[string]interface{}{
				{"nodes": []map[string]interface{}{
					{"cpeMatch": []map[string]string{
						{"criteria": "cpe:2.3:a:f5:nginx:1.24.0:*:*:*:*:*:*:*"},
					}},
				}},
			},
		},
	}
	if err := backend.WriteVulnerability(ctx, "CVE-2024-NGINX-TEST", vulnForNginx); err != nil {
		t.Fatalf("write nginx vuln: %v", err)
	}

	engine := enricher.New(enricher.Config{
		Store:         backend,
		Logger:        logger,
		SkipProviders: true,
	})
	if _, err := engine.Run(ctx); err != nil {
		t.Fatalf("engine run: %v", err)
	}

	components := []grc.SBOMComponent{
		{
			Name:    "log4j-core",
			Version: "2.14.0",
			Type:    "library",
			CPEs:    []string{"cpe:2.3:a:apache:log4j:2.14.0:*:*:*:*:*:*:*"},
		},
		{
			Name:    "nginx",
			Version: "1.24.0",
			Type:    "library",
			CPEs:    []string{"cpe:2.3:a:f5:nginx:1.24.0:*:*:*:*:*:*:*"},
		},
		{
			Name:    "safe-utils",
			Version: "3.0.0",
			Type:    "library",
			CPEs:    []string{},
		},
		{
			Name:    "multi-cpe-lib",
			Version: "1.0.0",
			Type:    "framework",
			CPEs: []string{
				"cpe:2.3:a:apache:log4j:2.14.0:*:*:*:*:*:*:*",
				"cpe:2.3:a:f5:nginx:1.24.0:*:*:*:*:*:*:*",
			},
		},
	}

	enriched, err := engine.EnrichSBOM(ctx, components)
	if err != nil {
		t.Fatalf("EnrichSBOM: %v", err)
	}

	if len(enriched) != 4 {
		t.Fatalf("expected 4 enriched components, got %d", len(enriched))
	}

	if enriched[0].ComplianceRisk != "needs-review" {
		t.Errorf("log4j compliance risk: got %q, want needs-review", enriched[0].ComplianceRisk)
	}
	if len(enriched[0].Controls) == 0 {
		t.Error("log4j should have controls (ListControlsByCPE returns all)")
	}

	if enriched[1].ComplianceRisk != "needs-review" {
		t.Errorf("nginx compliance risk: got %q, want needs-review", enriched[1].ComplianceRisk)
	}

	if enriched[2].ComplianceRisk != "" {
		t.Errorf("safe-utils compliance risk: got %q, want empty", enriched[2].ComplianceRisk)
	}
	if len(enriched[2].Controls) != 0 {
		t.Errorf("safe-utils controls: got %d, want 0", len(enriched[2].Controls))
	}

	if enriched[3].ComplianceRisk != "needs-review" {
		t.Errorf("multi-cpe-lib compliance risk: got %q, want needs-review", enriched[3].ComplianceRisk)
	}

	for i, ec := range enriched {
		if ec.Name != components[i].Name {
			t.Errorf("component[%d] name: got %q, want %q", i, ec.Name, components[i].Name)
		}
		if ec.Version != components[i].Version {
			t.Errorf("component[%d] version: got %q, want %q", i, ec.Version, components[i].Version)
		}
		if ec.Type != components[i].Type {
			t.Errorf("component[%d] type: got %q, want %q", i, ec.Type, components[i].Type)
		}
	}
}

func TestLayer2_LargeDatasetRoundtrip(t *testing.T) {
	backend := setupTestDB(t)
	ctx := context.Background()

	const numControls = 150
	frameworks := []string{"FW_LARGE_A", "FW_LARGE_B", "FW_LARGE_C"}

	for i := 0; i < numControls; i++ {
		fw := frameworks[i%len(frameworks)]
		ctrl := grc.Control{
			Framework:   fw,
			ControlID:   fmt.Sprintf("CTRL-%04d", i),
			Title:       fmt.Sprintf("Control %d Title", i),
			Family:      fmt.Sprintf("Family %d", i%10),
			Description: fmt.Sprintf("Description for control %d with sufficient detail", i),
			Level:       []string{"low", "medium", "high"}[i%3],
			RelatedCWEs: []string{fmt.Sprintf("CWE-%d", 79+(i%50))},
			RelatedCVEs: []string{fmt.Sprintf("CVE-2024-%05d", i)},
		}
		id := fmt.Sprintf("%s/%s", fw, ctrl.ControlID)
		if err := backend.WriteControl(ctx, id, ctrl); err != nil {
			t.Fatalf("write control %d: %v", i, err)
		}
	}

	allCtrls, err := backend.ListAllControls(ctx)
	if err != nil {
		t.Fatalf("list all controls: %v", err)
	}
	if len(allCtrls) != numControls {
		t.Fatalf("expected %d controls, got %d", numControls, len(allCtrls))
	}

	for _, fw := range frameworks {
		fwCtrls, err := backend.ListControlsByFramework(ctx, fw)
		if err != nil {
			t.Fatalf("list controls for %s: %v", fw, err)
		}
		expected := numControls / len(frameworks)
		if len(fwCtrls) != expected {
			t.Errorf("framework %s: expected %d controls, got %d", fw, expected, len(fwCtrls))
		}
		for _, c := range fwCtrls {
			if c.Framework != fw {
				t.Errorf("control %s has wrong framework %q", c.ID, c.Framework)
			}
		}
	}

	testCWE := "CWE-79"
	cweCtrls, err := backend.ListControlsByCWE(ctx, testCWE)
	if err != nil {
		t.Fatalf("list controls by CWE: %v", err)
	}
	if len(cweCtrls) == 0 {
		t.Error("expected controls matching CWE-79")
	}
	for _, c := range cweCtrls {
		found := false
		for _, cwe := range c.RelatedCWEs {
			if cwe == testCWE {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("control %s returned for CWE-79 but does not have it in RelatedCWEs: %v", c.ID, c.RelatedCWEs)
		}
	}

	sampleIDs := []string{"FW_LARGE_A/CTRL-0000", "FW_LARGE_C/CTRL-0050", "FW_LARGE_B/CTRL-0100"}
	for _, id := range sampleIDs {
		data, err := backend.ReadControl(ctx, id)
		if err != nil {
			t.Errorf("read control %s: %v", id, err)
			continue
		}
		if len(data) == 0 {
			t.Errorf("empty record for control %s", id)
		}
		if !json.Valid(data) {
			t.Errorf("invalid JSON for control %s", id)
		}

		var ctrl grc.Control
		if err := json.Unmarshal(data, &ctrl); err != nil {
			t.Errorf("unmarshal control %s: %v", id, err)
			continue
		}
		if ctrl.Framework == "" || ctrl.ControlID == "" || ctrl.Title == "" {
			t.Errorf("control %s has empty required fields: fw=%q id=%q title=%q",
				id, ctrl.Framework, ctrl.ControlID, ctrl.Title)
		}
	}

	nonexistent, err := backend.ReadControl(ctx, "FW_LARGE_A/CTRL-9999")
	if err == nil {
		t.Error("expected error reading nonexistent control, got nil")
	}
	if nonexistent != nil {
		t.Errorf("expected nil data for nonexistent control, got %q", string(nonexistent))
	}
}
