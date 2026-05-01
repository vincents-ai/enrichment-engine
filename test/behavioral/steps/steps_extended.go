package steps

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/cucumber/godog"
	"github.com/vincents-ai/enrichment-engine/internal/cli"
	"github.com/vincents-ai/enrichment-engine/pkg/grc"
)

func (s *testState) theProviderNamesShouldBeUnique() error {
	names := s.registry.List()
	seen := make(map[string]bool)
	for _, name := range names {
		if seen[name] {
			return fmt.Errorf("duplicate provider name: %s", name)
		}
		seen[name] = true
	}
	return nil
}

func (s *testState) eachProviderNameShouldMatchTheValidNameFormat() error {
	names := s.registry.List()
	for _, name := range names {
		if !isValidProviderName(name) {
			return fmt.Errorf("invalid provider name format: %q", name)
		}
	}
	return nil
}

func isValidProviderName(name string) bool {
	if len(name) == 0 || len(name) > 50 {
		return false
	}
	for _, c := range name {
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_') {
			return false
		}
	}
	return true
}

func (s *testState) noControlsInStorage() error {
	controls, err := s.backend.ListAllControls(context.Background())
	if err != nil {
		return err
	}
	if len(controls) != 0 {
		return fmt.Errorf("expected no controls, got %d", len(controls))
	}
	return nil
}

func (s *testState) theResultShouldReportAtLeastMappings(min int) error {
	if s.result == nil {
		return fmt.Errorf("no result")
	}
	if s.result.MappingCount < min {
		return fmt.Errorf("expected result to report at least %d mappings, got %d", min, s.result.MappingCount)
	}
	return nil
}

func (s *testState) aVulnerabilityWithCWEAndCPE(vulnID, cwe, cpe string) error {
	s.vulnID = vulnID
	record := map[string]interface{}{
		"id": vulnID,
		"cve": map[string]interface{}{
			"id": vulnID,
			"weaknesses": []map[string]interface{}{
				{"description": []map[string]string{{"lang": "en", "value": cwe}}},
			},
			"configurations": []map[string]interface{}{
				{
					"nodes": []map[string]interface{}{
						{
							"cpeMatch": []map[string]string{
								{"criteria": cpe},
							},
						},
					},
				},
			},
		},
	}
	return s.backend.WriteVulnerability(context.Background(), vulnID, record)
}

func (s *testState) iRecordTheMappingCount() error {
	if s.result == nil {
		return fmt.Errorf("no result to record")
	}
	s.firstMappingCount = s.result.MappingCount
	return nil
}

func (s *testState) iRunTheFullEnrichmentPipelineAgain() error {
	var err error
	s.result, err = s.engine.Run(context.Background())
	if err != nil {
		return err
	}
	s.mappingCount = s.result.MappingCount
	return nil
}

func (s *testState) theMappingCountShouldRemainTheSame() error {
	if s.result.MappingCount != s.firstMappingCount {
		return fmt.Errorf("expected mapping count to remain %d, got %d", s.firstMappingCount, s.result.MappingCount)
	}
	return nil
}

func (s *testState) iWriteAControlWithCompositeIDFrameworkAndTitle(compositeID, framework, title string) error {
	ctrl := grc.Control{
		Framework:   framework,
		ControlID:   compositeID,
		Title:       title,
		Description: "Test control for storage layer",
	}
	return s.backend.WriteControl(context.Background(), compositeID, ctrl)
}

func (s *testState) iReadTheControlWithCompositeID(compositeID string) error {
	data, err := s.backend.ReadControl(context.Background(), compositeID)
	if err != nil {
		return fmt.Errorf("read control: %w", err)
	}
	s.readControlData = data
	return nil
}

func (s *testState) theControlDataShouldBeValidJSONWithFramework(framework string) error {
	var ctrl struct {
		Framework string `json:"Framework"`
	}
	if err := json.Unmarshal(s.readControlData, &ctrl); err != nil {
		return fmt.Errorf("unmarshal control: %w", err)
	}
	if ctrl.Framework != framework {
		return fmt.Errorf("expected framework %q, got %q", framework, ctrl.Framework)
	}
	return nil
}

func (s *testState) theControlDataShouldHaveTitle(title string) error {
	var ctrl struct {
		Title string `json:"Title"`
	}
	if err := json.Unmarshal(s.readControlData, &ctrl); err != nil {
		return fmt.Errorf("unmarshal control: %w", err)
	}
	if ctrl.Title != title {
		return fmt.Errorf("expected title %q, got %q", title, ctrl.Title)
	}
	return nil
}

func (s *testState) iWriteAMappingFromVulnerabilityToControlWithTypeConfidenceAndEvidence(vulnID, ctrlID, mappingType string, confidence float64, evidence string) error {
	return s.backend.WriteMapping(context.Background(), vulnID, ctrlID, "TEST_FW", mappingType, confidence, evidence)
}

func (s *testState) iListMappingsForVulnerability(vulnID string) error {
	mappings, err := s.backend.ListMappings(context.Background(), vulnID)
	if err != nil {
		return fmt.Errorf("list mappings: %w", err)
	}
	s.mappings = mappings
	return nil
}

func (s *testState) theMappingShouldHaveControl(ctrlID string) error {
	for _, m := range s.mappings {
		if m.ControlID == ctrlID {
			return nil
		}
	}
	return fmt.Errorf("no mapping with control %q found in %v", ctrlID, s.mappings)
}

func (s *testState) theMappingShouldHaveType(mappingType string) error {
	for _, m := range s.mappings {
		if m.MappingType == mappingType {
			return nil
		}
	}
	return fmt.Errorf("no mapping with type %q found in %v", mappingType, s.mappings)
}

func (s *testState) theMappingShouldHaveConfidence(confidence float64) error {
	for _, m := range s.mappings {
		if m.Confidence == confidence {
			return nil
		}
	}
	return fmt.Errorf("no mapping with confidence %f found in %v", confidence, s.mappings)
}

func (s *testState) theMappingShouldHaveEvidenceContaining(substring string) error {
	for _, m := range s.mappings {
		if strings.Contains(m.Evidence, substring) {
			return nil
		}
	}
	return fmt.Errorf("no mapping with evidence containing %q found in %v", substring, s.mappings)
}

func (s *testState) allReturnedControlsShouldHaveFramework(framework string) error {
	for _, ctrl := range s.controls {
		if ctrl.Framework != framework {
			return fmt.Errorf("control %s has framework %q, expected %q", ctrl.ID, ctrl.Framework, framework)
		}
	}
	return nil
}

func (s *testState) iRunTheCLICommand(argsStr string) error {
	cmd := cli.New()
	args := strings.Fields(argsStr)

	fullArgs := []string{"--workspace", s.tempDir, "--log-level", "error"}
	fullArgs = append(fullArgs, args...)

	oldStdout := os.Stdout
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stdout = w
	os.Stderr = w

	cmd.SetArgs(fullArgs)
	s.cliError = cmd.Execute()

	w.Close()
	os.Stdout = oldStdout
	os.Stderr = oldStderr

	var buf bytes.Buffer
	buf.ReadFrom(r)
	s.cliOutput = buf.String()
	return nil
}

func (s *testState) theOutputShouldContain(substring string) error {
	if !strings.Contains(s.cliOutput, substring) {
		return fmt.Errorf("expected output to contain %q, got:\n%s", substring, s.cliOutput)
	}
	return nil
}

func (s *testState) theOutputShouldMatch(pattern string) error {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return fmt.Errorf("invalid regex pattern %q: %w", pattern, err)
	}
	if !re.MatchString(s.cliOutput) {
		return fmt.Errorf("expected output to match %q, got:\n%s", pattern, s.cliOutput)
	}
	return nil
}

func (s *testState) theCommandShouldExitWithoutError() error {
	if s.cliError != nil {
		return fmt.Errorf("expected no error, got: %v", s.cliError)
	}
	return nil
}

func RegisterExtendedSteps(ctx *godog.ScenarioContext, state *testState) {
	ctx.Step(`^the provider names should be unique$`, state.theProviderNamesShouldBeUnique)
	ctx.Step(`^each provider name should match the valid name format$`, state.eachProviderNameShouldMatchTheValidNameFormat)
	ctx.Step(`^no controls in storage$`, state.noControlsInStorage)
	ctx.Step(`^the result should report at least (\d+) mappings$`, state.theResultShouldReportAtLeastMappings)
	ctx.Step(`^a vulnerability "([^"]*)" with CWE "([^"]*)" and CPE "([^"]*)"$`, state.aVulnerabilityWithCWEAndCPE)
	ctx.Step(`^I record the mapping count$`, state.iRecordTheMappingCount)
	ctx.Step(`^I run the full enrichment pipeline again$`, state.iRunTheFullEnrichmentPipelineAgain)
	ctx.Step(`^the mapping count should remain the same$`, state.theMappingCountShouldRemainTheSame)
	ctx.Step(`^I write a control with composite ID "([^"]*)", framework "([^"]*)", title "([^"]*)"$`, state.iWriteAControlWithCompositeIDFrameworkAndTitle)
	ctx.Step(`^I read the control with composite ID "([^"]*)"$`, state.iReadTheControlWithCompositeID)
	ctx.Step(`^the control data should be valid JSON with framework "([^"]*)"$`, state.theControlDataShouldBeValidJSONWithFramework)
	ctx.Step(`^the control data should have title "([^"]*)"$`, state.theControlDataShouldHaveTitle)
	ctx.Step(`^I write a mapping from vulnerability "([^"]*)" to control "([^"]*)" with type "([^"]*)", confidence ([\d.]+), and evidence "([^"]*)"$`, state.iWriteAMappingFromVulnerabilityToControlWithTypeConfidenceAndEvidence)
	ctx.Step(`^I list mappings for vulnerability "([^"]*)"$`, state.iListMappingsForVulnerability)
	ctx.Step(`^the mapping should have control "([^"]*)"$`, state.theMappingShouldHaveControl)
	ctx.Step(`^the mapping should have type "([^"]*)"$`, state.theMappingShouldHaveType)
	ctx.Step(`^the mapping should have confidence ([\d.]+)$`, state.theMappingShouldHaveConfidence)
	ctx.Step(`^the mapping should have evidence containing "([^"]*)"$`, state.theMappingShouldHaveEvidenceContaining)
	ctx.Step(`^all returned controls should have framework "([^"]*)"$`, state.allReturnedControlsShouldHaveFramework)
	ctx.Step(`^I run the CLI command "([^"]*)"$`, state.iRunTheCLICommand)
	ctx.Step(`^the output should contain "([^"]*)"$`, state.theOutputShouldContain)
	ctx.Step(`^the output should match "([^"]*)"$`, state.theOutputShouldMatch)
	ctx.Step(`^the command should exit without error$`, state.theCommandShouldExitWithoutError)
}
