package enricher

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/shift/enrichment-engine/pkg/grc"
	"github.com/shift/enrichment-engine/pkg/storage"
)

// Config configures the enrichment engine.
type Config struct {
	Store       storage.Backend
	MaxParallel int
	Logger      *slog.Logger
}

// Engine runs the enrichment pipeline that maps vulnerabilities to GRC controls.
type Engine struct {
	store       storage.Backend
	maxParallel int
	logger      *slog.Logger
}

// New creates a new enrichment engine.
func New(cfg Config) *Engine {
	if cfg.MaxParallel <= 0 {
		cfg.MaxParallel = 1
	}
	return &Engine{
		store:       cfg.Store,
		maxParallel: cfg.MaxParallel,
		logger:      cfg.Logger,
	}
}

// Result contains the enrichment outcome.
type Result struct {
	VulnCount    int
	ControlCount int
	MappingCount int
	Duration     time.Duration
}

// Run executes the full enrichment pipeline.
func (e *Engine) Run(ctx context.Context) (*Result, error) {
	start := time.Now()
	e.logger.Info("starting enrichment pipeline")

	result := &Result{}

	// Phase 1: Map CWEs to controls
	cweMappings, err := e.mapByCWE(ctx)
	if err != nil {
		return nil, fmt.Errorf("CWE mapping: %w", err)
	}
	result.MappingCount += cweMappings

	// Phase 2: Map CPEs to controls
	cpeMappings, err := e.mapByCPE(ctx)
	if err != nil {
		return nil, fmt.Errorf("CPE mapping: %w", err)
	}
	result.MappingCount += cpeMappings

	result.Duration = time.Since(start)
	e.logger.Info("enrichment pipeline complete",
		"mappings", result.MappingCount,
		"duration", result.Duration)

	return result, nil
}

// mapByCWE maps vulnerabilities to controls via shared CWE identifiers.
func (e *Engine) mapByCWE(ctx context.Context) (int, error) {
	e.logger.Info("phase 1: mapping by CWE")

	// TODO: Implement CWE-based mapping
	// 1. Read all vulnerabilities with CWE data
	// 2. Read all controls with RelatedCWEs
	// 3. Match and write mappings

	return 0, nil
}

// mapByCPE maps vulnerabilities to controls via CPE product matching.
func (e *Engine) mapByCPE(ctx context.Context) (int, error) {
	e.logger.Info("phase 2: mapping by CPE")

	// TODO: Implement CPE-based mapping
	// 1. Read all vulnerabilities with CPE data
	// 2. Read all controls that reference specific products/technologies
	// 3. Match and write mappings

	return 0, nil
}

// EnrichSBOM enriches an SBOM with GRC compliance metadata.
func (e *Engine) EnrichSBOM(ctx context.Context, components []grc.SBOMComponent) ([]grc.EnrichedComponent, error) {
	e.logger.Info("enriching SBOM with GRC metadata", "components", len(components))

	enriched := make([]grc.EnrichedComponent, 0, len(components))
	for _, comp := range components {
		ec := grc.EnrichedComponent{
			SBOMComponent: comp,
		}
		enriched = append(enriched, ec)
	}

	return enriched, nil
}
