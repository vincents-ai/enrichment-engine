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
	vulnzapi "github.com/shift/vulnz/pkg/api"
)

type Config struct {
	Store            storage.Backend
	MaxParallel      int
	Logger           *slog.Logger
	ProviderNames    []string
	RunAll           bool
	SkipProviders    bool
	SkipMapping      bool
	EnableTagMapping bool
	Registry         *grc.Registry
	// optional: path to vulnz workspace dir; if set, vulnz ingest runs before providers
	VulnzWorkspace string
}

// EnrichmentEngine defines the interface for the enrichment pipeline.
type EnrichmentEngine interface {
	// Run executes the full enrichment pipeline.
	Run(ctx context.Context) (*Result, error)
	// EnrichSBOM enriches a list of SBOM components with compliance metadata.
	EnrichSBOM(ctx context.Context, components []grc.SBOMComponent) ([]grc.EnrichedComponent, error)
}

// Engine implements the EnrichmentEngine interface.
type engine struct {
	store            storage.Backend
	maxParallel      int
	logger           *slog.Logger
	registry         *grc.Registry
	runAll           bool
	providerNames    []string
	skipProviders    bool
	skipMapping      bool
	enableTagMapping bool
	vulnzWorkspace   string
}

// New creates a new EnrichmentEngine.
// Returns EnrichmentEngine interface.
func New(cfg Config) EnrichmentEngine {
	if cfg.MaxParallel <= 0 {
		cfg.MaxParallel = 1
	}
	registry := cfg.Registry
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if registry == nil {
		registry = grcbuiltin.DefaultRegistry()
	}
	return &engine{
		store:            cfg.Store,
		maxParallel:      cfg.MaxParallel,
		logger:           cfg.Logger,
		registry:         registry,
		runAll:           cfg.RunAll,
		providerNames:    cfg.ProviderNames,
		skipProviders:    cfg.SkipProviders,
		skipMapping:      cfg.SkipMapping,
		enableTagMapping: cfg.EnableTagMapping,
		vulnzWorkspace:   cfg.VulnzWorkspace,
	}
}

type Result struct {
	VulnCount     int
	ControlCount  int
	MappingCount  int
	ProviderCount int
	Duration      time.Duration
}

func (e *engine) runVulnzIngest(ctx context.Context) error {
	if e.vulnzWorkspace == "" {
		return nil
	}
	e.logger.Info("running vulnz ingest", "workspace", e.vulnzWorkspace)
	return vulnzapi.Ingest(ctx, vulnzapi.IngestOptions{
		WorkspacePath: e.vulnzWorkspace,
	})
}

func (e *engine) Run(ctx context.Context) (*Result, error) {
	start := time.Now()
	e.logger.Info("starting enrichment pipeline")
	result := &Result{}

	if err := e.runVulnzIngest(ctx); err != nil {
		return nil, fmt.Errorf("vulnz ingest: %w", err)
	}

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

		if e.enableTagMapping {
			tagMappings, err := e.mapByTag(ctx)
			if err != nil {
				return nil, fmt.Errorf("tag mapping: %w", err)
			}
			result.MappingCount += tagMappings
		}
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

func (e *engine) runProviders(ctx context.Context) (int, int, error) {
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

func (e *engine) mapByCWE(ctx context.Context) (int, error) {
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

func (e *engine) mapByCPE(ctx context.Context) (int, error) {
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

	// Build CWE→controls index once at O(C) so each vuln lookup is O(CWEs_per_vuln)
	// instead of scanning every control per vuln (was O(V×C)).
	cweIndex := make(map[string][]*storage.ControlRow, len(controls))
	for i := range controls {
		ctrl := &controls[i]
		for _, cwe := range ctrl.RelatedCWEs {
			cweIndex[cwe] = append(cweIndex[cwe], ctrl)
		}
	}

	totalMappings := 0
	for _, vuln := range vulns {
		cpes := extractCPEs(vuln.Record)
		if len(cpes) == 0 {
			continue
		}

		vulnCWEs := extractCWEs(vuln.Record)
		if len(vulnCWEs) == 0 {
			continue
		}

		for _, vulnCWE := range vulnCWEs {
			for _, ctrl := range cweIndex[vulnCWE] {
				evidence := fmt.Sprintf("CPE-based indirect mapping via shared CWE %s: %s -> %s/%s", vulnCWE, vuln.ID, ctrl.Framework, ctrl.ControlID)
				if err := e.store.WriteMapping(ctx, vuln.ID, ctrl.ID, ctrl.Framework, "cpe", 0.6, evidence); err != nil {
					continue
				}
				totalMappings++
			}
		}
	}

	e.logger.Info("CPE mapping complete", "mappings", totalMappings)
	return totalMappings, nil
}

var cweToTags = map[string][]string{
	"CWE-502":  {"deserialization", "injection"},
	"CWE-119":  {"buffer-overflow", "memory", "memory-corruption"},
	"CWE-20":   {"input-validation", "injection"},
	"CWE-79":   {"xss", "injection", "web"},
	"CWE-78":   {"injection", "os-command", "command-injection"},
	"CWE-89":   {"injection", "sql-injection", "database"},
	"CWE-22":   {"path-traversal", "file", "injection"},
	"CWE-125":  {"buffer-overflow", "memory", "memory-corruption", "out-of-bounds-read"},
	"CWE-787":  {"buffer-overflow", "memory", "memory-corruption", "out-of-bounds-write"},
	"CWE-190":  {"integer", "arithmetic", "overflow"},
	"CWE-200":  {"information-disclosure", "data-leak"},
	"CWE-352":  {"csrf", "web"},
	"CWE-287":  {"authentication", "authn"},
	"CWE-306":  {"authentication", "authn"},
	"CWE-862":  {"authorization", "authz"},
	"CWE-863":  {"authorization", "authz"},
	"CWE-250":  {"authentication", "authn", "privilege"},
	"CWE-269":  {"authorization", "authz", "privilege"},
	"CWE-434":  {"upload", "file"},
	"CWE-400":  {"denial-of-service", "dos", "resource-exhaustion"},
	"CWE-50":   {"xml", "injection"},
	"CWE-918":  {"ssrf", "web", "network"},
	"CWE-346":  {"redirect", "web"},
	"CWE-327":  {"crypto", "cryptography"},
	"CWE-328":  {"crypto", "cryptography"},
	"CWE-329":  {"crypto", "cryptography"},
	"CWE-338":  {"crypto", "cryptography"},
	"CWE-310":  {"crypto", "cryptography"},
	"CWE-311":  {"crypto", "cryptography", "encryption"},
	"CWE-312":  {"crypto", "cryptography", "encryption"},
	"CWE-313":  {"crypto", "cryptography", "encryption"},
	"CWE-316":  {"crypto", "cryptography", "encryption"},
	"CWE-326":  {"crypto", "cryptography", "encryption"},
	"CWE-732":  {"permissions", "authorization"},
	"CWE-798":  {"authentication", "credentials", "hardcoded"},
	"CWE-259":  {"credentials", "hardcoded"},
	"CWE-770":  {"denial-of-service", "dos", "resource-exhaustion"},
	"CWE-776":  {"denial-of-service", "dos", "resource-exhaustion"},
	"CWE-416":  {"memory", "use-after-free", "memory-corruption"},
	"CWE-415":  {"memory", "double-free", "memory-corruption"},
	"CWE-822":  {"deserialization", "injection"},
	"CWE-829":  {"inclusion", "file"},
	"CWE-917":  {"deserialization", "injection"},
	"CWE-1336": {"template-injection", "injection", "web"},
}

func vulnTags(cwes []string) []string {
	seen := make(map[string]bool)
	var tags []string
	for _, cwe := range cwes {
		for _, tag := range cweToTags[cwe] {
			if !seen[tag] {
				seen[tag] = true
				tags = append(tags, tag)
			}
		}
	}
	return tags
}

func (e *engine) mapByTag(ctx context.Context) (int, error) {
	e.logger.Info("phase 4: mapping by tag")

	vulns, err := e.store.ListAllVulnerabilities(ctx)
	if err != nil {
		return 0, fmt.Errorf("list vulnerabilities: %w", err)
	}
	e.logger.Info("loaded vulnerabilities for tag mapping", "count", len(vulns))

	totalMappings := 0
	for _, vuln := range vulns {
		cwes := extractCWEs(vuln.Record)
		if len(cwes) == 0 {
			continue
		}

		tags := vulnTags(cwes)
		if len(tags) == 0 {
			continue
		}

		for _, tag := range tags {
			controls, err := e.store.ListControlsByTag(ctx, tag)
			if err != nil {
				e.logger.Warn("failed to list controls by tag", "tag", tag, "error", err)
				continue
			}

			for _, ctrl := range controls {
				evidence := fmt.Sprintf("Tag %s shared between %s and control %s/%s", tag, vuln.ID, ctrl.Framework, ctrl.ControlID)
				if err := e.store.WriteMapping(ctx, vuln.ID, ctrl.ID, ctrl.Framework, "tag", 0.4, evidence); err != nil {
					e.logger.Warn("failed to write tag mapping", "vuln", vuln.ID, "control", ctrl.ID, "error", err)
					continue
				}
				totalMappings++
			}
		}
	}

	e.logger.Info("tag mapping complete", "mappings", totalMappings)
	return totalMappings, nil
}

func (e *engine) EnrichSBOM(ctx context.Context, components []grc.SBOMComponent) ([]grc.EnrichedComponent, error) {
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
