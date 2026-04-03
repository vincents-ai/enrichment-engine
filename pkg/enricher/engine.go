package enricher

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/shift/enrichment-engine/pkg/grc"
	grcbuiltin "github.com/shift/enrichment-engine/pkg/grc/builtin"
	"github.com/shift/enrichment-engine/pkg/storage"
)

type Config struct {
	Store         storage.Backend
	MaxParallel   int
	Logger        *slog.Logger
	ProviderNames []string
	RunAll        bool
	SkipProviders bool
	SkipMapping   bool
	Registry      *grc.Registry
}

type Engine struct {
	store         storage.Backend
	maxParallel   int
	logger        *slog.Logger
	registry      *grc.Registry
	runAll        bool
	providerNames []string
	skipProviders bool
	skipMapping   bool
}

func New(cfg Config) *Engine {
	if cfg.MaxParallel <= 0 {
		cfg.MaxParallel = 1
	}
	registry := cfg.Registry
	if registry == nil {
		registry = grcbuiltin.DefaultRegistry()
	}
	return &Engine{
		store:         cfg.Store,
		maxParallel:   cfg.MaxParallel,
		logger:        cfg.Logger,
		registry:      registry,
		runAll:        cfg.RunAll,
		providerNames: cfg.ProviderNames,
		skipProviders: cfg.SkipProviders,
		skipMapping:   cfg.SkipMapping,
	}
}

type Result struct {
	VulnCount     int
	ControlCount  int
	MappingCount  int
	ProviderCount int
	Duration      time.Duration
}

func (e *Engine) Run(ctx context.Context) (*Result, error) {
	start := time.Now()
	e.logger.Info("starting enrichment pipeline")
	result := &Result{}

	if !e.skipProviders {
		providerCount, controlCount, err := e.runProviders(ctx)
		if err != nil {
			return nil, fmt.Errorf("providers: %w", err)
		}
		result.ProviderCount = providerCount
		result.ControlCount = controlCount
	}

	if !e.skipMapping {
		vulns, err := e.store.ListAllVulnerabilities(ctx)
		if err != nil {
			return nil, fmt.Errorf("count vulnerabilities: %w", err)
		}
		result.VulnCount = len(vulns)

		cweMappings, err := e.mapByCWE(ctx)
		if err != nil {
			return nil, fmt.Errorf("CWE mapping: %w", err)
		}
		result.MappingCount += cweMappings

		cpeMappings, err := e.mapByCPE(ctx)
		if err != nil {
			return nil, fmt.Errorf("CPE mapping: %w", err)
		}
		result.MappingCount += cpeMappings
	}

	result.Duration = time.Since(start)
	e.logger.Info("enrichment pipeline complete",
		"controls", result.ControlCount,
		"vulns", result.VulnCount,
		"providers", result.ProviderCount,
		"mappings", result.MappingCount,
		"duration", result.Duration)
	return result, nil
}

func (e *Engine) runProviders(ctx context.Context) (int, int, error) {
	e.logger.Info("running GRC providers")

	names := e.providerNames
	if len(names) == 0 {
		names = nil
	}

	controlCount, err := e.registry.RunSelected(ctx, names, e.store, e.logger, e.maxParallel)
	if err != nil {
		return 0, 0, err
	}

	providerCount := len(names)
	if providerCount == 0 {
		providerCount = len(e.registry.List())
	}

	return providerCount, controlCount, nil
}

type vulnRecord struct {
	ID  string `json:"id"`
	CVE struct {
		ID         string `json:"id"`
		Weaknesses []struct {
			Description []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"description"`
		} `json:"weaknesses"`
		Configurations []struct {
			Nodes []struct {
				CPEMatch []struct {
					Criteria string `json:"criteria"`
				} `json:"cpeMatch"`
			} `json:"nodes"`
		} `json:"configurations"`
	} `json:"cve"`
}

func extractCWEs(record json.RawMessage) []string {
	var vuln vulnRecord
	if err := json.Unmarshal(record, &vuln); err != nil {
		return nil
	}
	var cwes []string
	seen := make(map[string]bool)
	for _, w := range vuln.CVE.Weaknesses {
		for _, d := range w.Description {
			if d.Lang == "en" && strings.HasPrefix(d.Value, "CWE-") {
				if !seen[d.Value] {
					cwes = append(cwes, d.Value)
					seen[d.Value] = true
				}
			}
		}
	}
	return cwes
}

func extractCPEs(record json.RawMessage) []string {
	var vuln vulnRecord
	if err := json.Unmarshal(record, &vuln); err != nil {
		return nil
	}
	var cpes []string
	seen := make(map[string]bool)
	for _, cfg := range vuln.CVE.Configurations {
		for _, node := range cfg.Nodes {
			for _, match := range node.CPEMatch {
				if !seen[match.Criteria] {
					cpes = append(cpes, match.Criteria)
					seen[match.Criteria] = true
				}
			}
		}
	}
	return cpes
}

func (e *Engine) mapByCWE(ctx context.Context) (int, error) {
	e.logger.Info("phase 2: mapping by CWE")

	vulns, err := e.store.ListAllVulnerabilities(ctx)
	if err != nil {
		return 0, fmt.Errorf("list vulnerabilities: %w", err)
	}
	e.logger.Info("loaded vulnerabilities for CWE mapping", "count", len(vulns))

	totalMappings := 0
	for _, vuln := range vulns {
		cwes := extractCWEs(vuln.Record)
		if len(cwes) == 0 {
			continue
		}

		for _, cwe := range cwes {
			controls, err := e.store.ListControlsByCWE(ctx, cwe)
			if err != nil {
				e.logger.Warn("failed to list controls by CWE", "cwe", cwe, "error", err)
				continue
			}

			for _, ctrl := range controls {
				evidence := fmt.Sprintf("CWE %s shared between %s and control %s/%s", cwe, vuln.ID, ctrl.Framework, ctrl.ControlID)
				if err := e.store.WriteMapping(ctx, vuln.ID, ctrl.ID, ctrl.Framework, "cwe", 0.8, evidence); err != nil {
					e.logger.Warn("failed to write CWE mapping", "vuln", vuln.ID, "control", ctrl.ID, "error", err)
					continue
				}
				totalMappings++
			}
		}
	}

	e.logger.Info("CWE mapping complete", "mappings", totalMappings)
	return totalMappings, nil
}

func (e *Engine) mapByCPE(ctx context.Context) (int, error) {
	e.logger.Info("phase 3: mapping by CPE")

	vulns, err := e.store.ListAllVulnerabilities(ctx)
	if err != nil {
		return 0, fmt.Errorf("list vulnerabilities: %w", err)
	}
	e.logger.Info("loaded vulnerabilities for CPE mapping", "count", len(vulns))

	controls, err := e.store.ListAllControls(ctx)
	if err != nil {
		return 0, fmt.Errorf("list controls: %w", err)
	}

	totalMappings := 0
	for _, vuln := range vulns {
		cpes := extractCPEs(vuln.Record)
		if len(cpes) == 0 {
			continue
		}

		for _, ctrl := range controls {
			if len(ctrl.RelatedCWEs) == 0 {
				continue
			}

			vulnCWEs := extractCWEs(vuln.Record)
			if len(vulnCWEs) == 0 {
				continue
			}

			for _, vulnCWE := range vulnCWEs {
				for _, ctrlCWE := range ctrl.RelatedCWEs {
					if vulnCWE == ctrlCWE {
						evidence := fmt.Sprintf("CPE-based indirect mapping via shared CWE %s: %s -> %s/%s", vulnCWE, vuln.ID, ctrl.Framework, ctrl.ControlID)
						if err := e.store.WriteMapping(ctx, vuln.ID, ctrl.ID, ctrl.Framework, "cpe", 0.6, evidence); err != nil {
							continue
						}
						totalMappings++
						break
					}
				}
			}
		}
	}

	e.logger.Info("CPE mapping complete", "mappings", totalMappings)
	return totalMappings, nil
}

func (e *Engine) EnrichSBOM(ctx context.Context, components []grc.SBOMComponent) ([]grc.EnrichedComponent, error) {
	e.logger.Info("enriching SBOM with GRC metadata", "components", len(components))

	enriched := make([]grc.EnrichedComponent, 0, len(components))
	for _, comp := range components {
		ec := grc.EnrichedComponent{
			SBOMComponent: comp,
		}

		for _, cpe := range comp.CPEs {
			controls, err := e.store.ListControlsByCPE(ctx, cpe)
			if err != nil {
				continue
			}
			for _, ctrl := range controls {
				ec.Controls = append(ec.Controls, ctrl.ID)
				ec.Frameworks = append(ec.Frameworks, ctrl.Framework)
			}
		}

		if len(ec.Controls) > 0 {
			ec.ComplianceRisk = "needs-review"
		}

		enriched = append(enriched, ec)
	}

	return enriched, nil
}
