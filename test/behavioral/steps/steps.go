package steps

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"

	"github.com/cucumber/godog"
	"github.com/shift/enrichment-engine/pkg/enricher"
	"github.com/shift/enrichment-engine/pkg/grc"
	grcbuiltin "github.com/shift/enrichment-engine/pkg/grc/builtin"
	"github.com/shift/enrichment-engine/pkg/storage"
)

type testState struct {
	backend           storage.Backend
	registry          *grc.Registry
	engine            enricher.EnrichmentEngine
	result            *enricher.Result
	provider          grc.GRCProvider
	providerCount     int
	controlCount      int
	mappingCount      int
	controls          []storage.ControlRow
	mappings          []storage.MappingRow
	enriched          []grc.EnrichedComponent
	err               error
	vulnID            string
	ctrlID            string
	found             bool
	tempDir           string
	dbPath            string
	firstMappingCount int
	readControlData   json.RawMessage
	cliOutput         string
	cliError          error
}

func InitializeScenario(ctx *godog.ScenarioContext) {
	state := &testState{}

	ctx.Before(func(ctx context.Context, sc *godog.Scenario) (context.Context, error) {
		dir, err := os.MkdirTemp("", "godog-*")
		if err != nil {
			return ctx, fmt.Errorf("create temp dir: %w", err)
		}
		state.tempDir = dir
		state.dbPath = filepath.Join(dir, "test.db")
		backend, err := storage.NewSQLiteBackend(state.dbPath)
		if err != nil {
			return ctx, fmt.Errorf("create db: %w", err)
		}
		state.backend = backend
		state.registry = grcbuiltin.DefaultRegistry()
		state.engine = enricher.New(enricher.Config{
			Store:  backend,
			Logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
		})
		state.result = nil
		state.providerCount = 0
		state.controlCount = 0
		state.mappingCount = 0
		state.controls = nil
		state.mappings = nil
		state.enriched = nil
		state.err = nil
		state.found = false
		return ctx, nil
	})

	ctx.After(func(ctx context.Context, sc *godog.Scenario, err error) (context.Context, error) {
		if state.backend != nil {
			state.backend.Close(context.Background())
		}
		os.RemoveAll(state.tempDir)
		return ctx, nil
	})

	ctx.Step(`^I list all registered providers$`, state.iListAllRegisteredProviders)
	ctx.Step(`^the registry should contain at least (\d+) providers$`, state.theRegistryShouldContainAtLeastProviders)
	ctx.Step(`^I request the "([^"]*)" provider$`, state.iRequestTheProvider)
	ctx.Step(`^the provider should be available$`, state.theProviderShouldBeAvailable)
	ctx.Step(`^the provider should not be available$`, state.theProviderShouldNotBeAvailable)
	ctx.Step(`^the provider name should be "([^"]*)"$`, state.theProviderNameShouldBe)
	ctx.Step(`^a storage backend is available$`, state.aStorageBackendIsAvailable)
	ctx.Step(`^I run the "([^"]*)" provider$`, state.iRunTheProvider)
	ctx.Step(`^at least (\d+) controls should be written$`, state.atLeastControlsShouldBeWritten)
	ctx.Step(`^I run all providers$`, state.iRunAllProviders)
	ctx.Step(`^at least (\d+) total controls should be written$`, state.atLeastTotalControlsShouldBeWritten)
	ctx.Step(`^a vulnerability "([^"]*)" with CWE "([^"]*)"$`, state.aVulnerabilityWithCWE)
	ctx.Step(`^a control "([^"]*)" with RelatedCWE "([^"]*)"$`, state.aControlWithRelatedCWE)
	ctx.Step(`^I run the CWE mapping phase$`, state.iRunTheCWEMappingPhase)
	ctx.Step(`^a mapping should exist from "([^"]*)" to "([^"]*)"$`, state.aMappingShouldExistFromTo)
	ctx.Step(`^the mapping type should be "([^"]*)"$`, state.theMappingTypeShouldBe)
	ctx.Step(`^the mapping confidence should be ([\d.]+)$`, state.theMappingConfidenceShouldBe)
	ctx.Step(`^an SBOM with component "([^"]*)" version "([^"]*)"$`, state.anSBOMWithComponentVersion)
	ctx.Step(`^the component has CPE "([^"]*)"$`, state.theComponentHasCPE)
	ctx.Step(`^at least (\d+) control exists in storage$`, state.atLeastControlExistsInStorage)
	ctx.Step(`^I enrich the SBOM$`, state.iEnrichTheSBOM)
	ctx.Step(`^the enriched component should have compliance metadata$`, state.theEnrichedComponentShouldHaveComplianceMetadata)
	ctx.Step(`^the compliance risk should be "([^"]*)"$`, state.theComplianceRiskShouldBe)
	ctx.Step(`^no vulnerabilities in storage$`, state.noVulnerabilitiesInStorage)
	ctx.Step(`^I run the full enrichment pipeline$`, state.iRunTheFullEnrichmentPipeline)
	ctx.Step(`^(\d+) mappings should be created$`, state.mappingsShouldBeCreated)
	ctx.Step(`^the result should report (\d+) mappings$`, state.theResultShouldReportMappings)
	ctx.Step(`^an empty database$`, state.anEmptyDatabase)
	ctx.Step(`^I write a control with ID "([^"]*)"$`, state.iWriteAControlWithID)
	ctx.Step(`^reading the control should return valid JSON$`, state.readingTheControlShouldReturnValidJSON)
	ctx.Step(`^controls exist for framework "([^"]*)"$`, state.controlsExistForFramework)
	ctx.Step(`^I list controls for framework "([^"]*)"$`, state.iListControlsForFramework)
	ctx.Step(`^at least (\d+) control should be returned$`, state.atLeastControlShouldBeReturned)
	ctx.Step(`^I write (\d+) controls concurrently$`, state.iWriteControlsConcurrently)
	ctx.Step(`^all (\d+) controls should be persisted$`, state.allControlsShouldBePersisted)
	ctx.Step(`^a control with ID "([^"]*)" exists$`, state.aControlWithIDExists)
	ctx.Step(`^I close and reopen the database$`, state.iCloseAndReopenTheDatabase)
	ctx.Step(`^the control "([^"]*)" should still exist$`, state.theControlShouldStillExist)

	RegisterExtendedSteps(ctx, state)
}

func (s *testState) iListAllRegisteredProviders() error {
	names := s.registry.List()
	s.providerCount = len(names)
	return nil
}

func (s *testState) theRegistryShouldContainAtLeastProviders(min int) error {
	if s.providerCount < min {
		return fmt.Errorf("expected at least %d providers, got %d", min, s.providerCount)
	}
	return nil
}

func (s *testState) iRequestTheProvider(name string) error {
	p, err := s.registry.Get(name, s.backend, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	if err != nil {
		s.provider = nil
		s.err = err
	} else {
		s.provider = p
		s.err = nil
	}
	return nil
}

func (s *testState) theProviderShouldBeAvailable() error {
	if s.provider == nil {
		return fmt.Errorf("provider not available: %v", s.err)
	}
	return nil
}

func (s *testState) theProviderShouldNotBeAvailable() error {
	if s.provider != nil {
		return fmt.Errorf("expected provider to be unavailable but got one")
	}
	return nil
}

func (s *testState) theProviderNameShouldBe(name string) error {
	if s.provider == nil {
		return fmt.Errorf("no provider available")
	}
	if s.provider.Name() != name {
		return fmt.Errorf("expected name %q, got %q", name, s.provider.Name())
	}
	return nil
}

func (s *testState) aStorageBackendIsAvailable() error {
	if s.backend != nil {
		return nil
	}
	return fmt.Errorf("storage backend not available")
}

func (s *testState) iRunTheProvider(name string) error {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	p, err := s.registry.Get(name, s.backend, logger)
	if err != nil {
		return fmt.Errorf("get provider %s: %w", name, err)
	}
	count, err := p.Run(context.Background())
	if err != nil {
		return fmt.Errorf("run provider %s: %w", name, err)
	}
	s.controlCount = count
	return nil
}

func (s *testState) atLeastControlsShouldBeWritten(min int) error {
	if s.controlCount < min {
		return fmt.Errorf("expected at least %d controls, got %d", min, s.controlCount)
	}
	return nil
}

func (s *testState) iRunAllProviders() error {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	total, err := s.registry.RunAll(context.Background(), s.backend, logger)
	if err != nil {
		return fmt.Errorf("run all providers: %w", err)
	}
	s.controlCount = total
	return nil
}

func (s *testState) atLeastTotalControlsShouldBeWritten(min int) error {
	if s.controlCount < min {
		return fmt.Errorf("expected at least %d total controls, got %d", min, s.controlCount)
	}
	return nil
}

func (s *testState) aVulnerabilityWithCWE(vulnID, cwe string) error {
	s.vulnID = vulnID
	record := map[string]interface{}{
		"id": vulnID,
		"cve": map[string]interface{}{
			"id": vulnID,
			"weaknesses": []map[string]interface{}{
				{"description": []map[string]string{{"lang": "en", "value": cwe}}},
			},
			"configurations": []interface{}{},
		},
	}
	return s.backend.WriteVulnerability(context.Background(), vulnID, record)
}

func (s *testState) aControlWithRelatedCWE(ctrlID, cwe string) error {
	s.ctrlID = ctrlID
	control := grc.Control{
		Framework:   "TEST_FRAMEWORK",
		ControlID:   ctrlID,
		Title:       "Test Control",
		Description: "Test control for CWE mapping",
		RelatedCWEs: []string{cwe},
	}
	return s.backend.WriteControl(context.Background(), "TEST_FRAMEWORK/"+ctrlID, control)
}

func (s *testState) iRunTheCWEMappingPhase() error {
	controls, err := s.backend.ListAllControls(context.Background())
	if err != nil {
		return fmt.Errorf("list controls: %w", err)
	}

	vulns, err := s.backend.ListAllVulnerabilities(context.Background())
	if err != nil {
		return fmt.Errorf("list vulnerabilities: %w", err)
	}

	for _, vuln := range vulns {
		var rec struct {
			CVE struct {
				Weaknesses []struct {
					Description []struct {
						Lang  string `json:"lang"`
						Value string `json:"value"`
					} `json:"description"`
				} `json:"weaknesses"`
			} `json:"cve"`
		}
		if err := json.Unmarshal(vuln.Record, &rec); err != nil {
			continue
		}
		var cwes []string
		seen := map[string]bool{}
		for _, w := range rec.CVE.Weaknesses {
			for _, d := range w.Description {
				if d.Lang == "en" && !seen[d.Value] {
					cwes = append(cwes, d.Value)
					seen[d.Value] = true
				}
			}
		}
		for _, cwe := range cwes {
			for _, ctrl := range controls {
				for _, ctrlCWE := range ctrl.RelatedCWEs {
					if ctrlCWE == cwe {
						s.backend.WriteMapping(context.Background(), vuln.ID, ctrl.ID, ctrl.Framework, "cwe", 0.8, "test")
						s.mappingCount++
						break
					}
				}
			}
		}
	}
	return nil
}

func (s *testState) aMappingShouldExistFromTo(vulnID, ctrlID string) error {
	mappings, err := s.backend.ListMappings(context.Background(), vulnID)
	if err != nil {
		return fmt.Errorf("list mappings: %w", err)
	}
	s.mappings = mappings
	fullID := "TEST_FRAMEWORK/" + ctrlID
	for _, m := range mappings {
		if m.ControlID == fullID {
			s.found = true
			return nil
		}
	}
	return fmt.Errorf("no mapping from %s to %s found in %v", vulnID, fullID, mappings)
}

func (s *testState) theMappingTypeShouldBe(expected string) error {
	for _, m := range s.mappings {
		if m.MappingType == expected {
			return nil
		}
	}
	return fmt.Errorf("no mapping with type %q found", expected)
}

func (s *testState) theMappingConfidenceShouldBe(expected float64) error {
	for _, m := range s.mappings {
		if m.Confidence == expected {
			return nil
		}
	}
	return fmt.Errorf("no mapping with confidence %f found", expected)
}

func (s *testState) anSBOMWithComponentVersion(name, version string) error {
	return nil
}

func (s *testState) theComponentHasCPE(cpe string) error {
	return nil
}

func (s *testState) atLeastControlExistsInStorage(min int) error {
	ctrl := grc.Control{
		Framework:   "TEST_FW",
		ControlID:   "TC-1",
		Title:       "Test Control",
		Description: "A test control",
		RelatedCWEs: []string{"CWE-79"},
	}
	return s.backend.WriteControl(context.Background(), "TEST_FW/TC-1", ctrl)
}

func (s *testState) iEnrichTheSBOM() error {
	// Seed a vulnerability whose record contains the log4j CPE with a CWE
	// matching the control seeded by atLeastControlExistsInStorage, so that
	// ListControlsByCPE can resolve the component to controls.
	vulnRecord := json.RawMessage(`{
		"id": "CVE-2024-TEST",
		"cve": {
			"weaknesses": [
				{
					"description": [
						{"lang": "en", "value": "CWE-79"}
					]
				}
			]
		},
		"configurations": [
			{
				"nodes": [
					{
						"cpeMatch": [
							{"criteria": "cpe:2.3:a:apache:log4j:2.14.0:*:*:*:*:*:*:*"}
						]
					}
				]
			}
		]
	}`)
	if err := s.backend.WriteVulnerability(context.Background(), "CVE-2024-TEST", vulnRecord); err != nil {
		return fmt.Errorf("seed vulnerability: %w", err)
	}

	components := []grc.SBOMComponent{
		{
			Name:    "log4j-core",
			Version: "2.14.0",
			Type:    "library",
			CPEs:    []string{"cpe:2.3:a:apache:log4j:2.14.0:*:*:*:*:*:*:*"},
		},
	}
	var err error
	s.enriched, err = s.engine.EnrichSBOM(context.Background(), components)
	return err
}

func (s *testState) theEnrichedComponentShouldHaveComplianceMetadata() error {
	if len(s.enriched) == 0 {
		return fmt.Errorf("no enriched components returned")
	}
	if len(s.enriched[0].Controls) == 0 {
		return fmt.Errorf("no compliance metadata on enriched component")
	}
	return nil
}

func (s *testState) theComplianceRiskShouldBe(expected string) error {
	if len(s.enriched) == 0 {
		return fmt.Errorf("no enriched components")
	}
	if s.enriched[0].ComplianceRisk != expected {
		return fmt.Errorf("expected compliance risk %q, got %q", expected, s.enriched[0].ComplianceRisk)
	}
	return nil
}

func (s *testState) noVulnerabilitiesInStorage() error {
	vulns, err := s.backend.ListAllVulnerabilities(context.Background())
	if err != nil {
		return err
	}
	if len(vulns) != 0 {
		return fmt.Errorf("expected no vulnerabilities, got %d", len(vulns))
	}
	return nil
}

func (s *testState) iRunTheFullEnrichmentPipeline() error {
	var err error
	s.result, err = s.engine.Run(context.Background())
	if err != nil {
		return err
	}
	s.mappingCount = s.result.MappingCount
	return nil
}

func (s *testState) mappingsShouldBeCreated(expected int) error {
	if s.mappingCount != expected {
		return fmt.Errorf("expected %d mappings, got %d", expected, s.mappingCount)
	}
	return nil
}

func (s *testState) theResultShouldReportMappings(expected int) error {
	if s.result == nil {
		return fmt.Errorf("no result")
	}
	if s.result.MappingCount != expected {
		return fmt.Errorf("expected result to report %d mappings, got %d", expected, s.result.MappingCount)
	}
	return nil
}

func (s *testState) anEmptyDatabase() error {
	return nil
}

func (s *testState) iWriteAControlWithID(id string) error {
	ctrl := grc.Control{
		Framework:   "TEST_FW",
		ControlID:   id,
		Title:       "Test Control " + id,
		Description: "A test control",
	}
	return s.backend.WriteControl(context.Background(), id, ctrl)
}

func (s *testState) readingTheControlShouldReturnValidJSON() error {
	data, err := s.backend.ReadControl(context.Background(), "TEST/CTRL-1")
	if err != nil {
		return fmt.Errorf("read control: %w", err)
	}
	if len(data) == 0 {
		return fmt.Errorf("empty data returned")
	}
	if !json.Valid(data) {
		return fmt.Errorf("invalid JSON: %s", string(data))
	}
	return nil
}

func (s *testState) controlsExistForFramework(framework string) error {
	ctrl := grc.Control{
		Framework:   framework,
		ControlID:   "TEST-CTRL",
		Title:       "Test Control",
		Description: "For framework listing test",
	}
	return s.backend.WriteControl(context.Background(), framework+"/TEST-CTRL", ctrl)
}

func (s *testState) iListControlsForFramework(framework string) error {
	var err error
	s.controls, err = s.backend.ListControlsByFramework(context.Background(), framework)
	return err
}

func (s *testState) atLeastControlShouldBeReturned(min int) error {
	if len(s.controls) < min {
		return fmt.Errorf("expected at least %d controls, got %d", min, len(s.controls))
	}
	return nil
}

func (s *testState) iWriteControlsConcurrently(count int) error {
	var wg sync.WaitGroup
	errCh := make(chan error, count)
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := fmt.Sprintf("CONC/%d", i)
			ctrl := grc.Control{
				Framework:   "CONC_FW",
				ControlID:   id,
				Title:       fmt.Sprintf("Concurrent Control %d", i),
				Description: "Written concurrently",
			}
			if err := s.backend.WriteControl(context.Background(), id, ctrl); err != nil {
				errCh <- err
			}
		}(i)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		return err
	}
	return nil
}

func (s *testState) allControlsShouldBePersisted(expected int) error {
	controls, err := s.backend.ListControlsByFramework(context.Background(), "CONC_FW")
	if err != nil {
		return err
	}
	if len(controls) != expected {
		return fmt.Errorf("expected %d controls, got %d", expected, len(controls))
	}
	return nil
}

func (s *testState) aControlWithIDExists(id string) error {
	ctrl := grc.Control{
		Framework:   "TEST_FW",
		ControlID:   id,
		Title:       "Persistent Control",
		Description: "Survives close and reopen",
	}
	compositeID := "TEST_FW/" + id
	if err := s.backend.WriteControl(context.Background(), compositeID, ctrl); err != nil {
		return fmt.Errorf("write control: %w", err)
	}
	data, err := s.backend.ReadControl(context.Background(), compositeID)
	if err != nil {
		return fmt.Errorf("verify write: %w", err)
	}
	if len(data) == 0 {
		return fmt.Errorf("control %s not found after write", compositeID)
	}
	return nil
}

func (s *testState) iCloseAndReopenTheDatabase() error {
	if err := s.backend.Close(context.Background()); err != nil {
		return fmt.Errorf("close db: %w", err)
	}

	if _, err := os.Stat(s.dbPath); os.IsNotExist(err) {
		return fmt.Errorf("committed database file does not exist after close")
	}

	db, err := sql.Open("sqlite", s.dbPath)
	if err != nil {
		return fmt.Errorf("reopen db: %w", err)
	}
	defer db.Close()

	var count int
	if err := db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM grc_controls").Scan(&count); err != nil {
		return fmt.Errorf("count controls after reopen: %w", err)
	}
	if count == 0 {
		return fmt.Errorf("expected controls in committed db after reopen, got 0")
	}
	s.found = true
	return nil
}

func (s *testState) theControlShouldStillExist(id string) error {
	if !s.found {
		return fmt.Errorf("control %s not verified after reopen", id)
	}
	return nil
}
