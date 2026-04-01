package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/shift/enrichment-engine/internal/enricher"
	"github.com/shift/enrichment-engine/internal/mapper"
	"github.com/shift/enrichment-engine/internal/storage"
	"github.com/shift/vulnz/internal/provider"
	"github.com/shift/vulnz/internal/schema"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	ctx := context.Background()

	// Initialize workspace
	workspace := os.Getenv("ENRICH_WORKSPACE")
	if workspace == "" {
		workspace = "./data"
	}

	// Initialize schema validator
	validator, err := schema.NewValidator()
	if err != nil {
		logger.Error("failed to initialize schema validator", "error", err)
		os.Exit(1)
	}

	// Initialize storage
	store, err := storage.NewSQLiteBackend(workspace+"/enrichment.db", 1000)
	if err != nil {
		logger.Error("failed to initialize storage", "error", err)
		os.Exit(1)
	}
	defer store.Close(ctx)

	// Phase 1: Run vulnerability providers via vulnz executor
	logger.Info("Phase 1: Running vulnerability providers")
	exec := provider.NewExecutor(provider.ExecutorConfig{
		MaxParallel: 4,
		Workspace:   workspace + "/vulnz",
	}, logger)

	vulnProviders := []string{"nvd", "euvd", "kev", "bsi-cert-bund", "cert-fr", "epss"}
	vulnResults, err := exec.Run(ctx, vulnProviders)
	if err != nil {
		logger.Error("vulnerability provider execution failed", "error", err)
		os.Exit(1)
	}

	for _, r := range vulnResults {
		if r.Err != nil {
			logger.Error("provider failed", "provider", r.Provider, "error", r.Err)
		} else {
			logger.Info("provider completed", "provider", r.Provider, "count", r.Count)
		}
	}

	// Phase 2: Run GRC control providers
	logger.Info("Phase 2: Running GRC control providers")
	grcExec := enricher.NewGRCExecutor(enricher.GRCExecutorConfig{
		MaxParallel: 2,
		Workspace:   workspace + "/grc",
	}, logger)

	grcResults, err := grcExec.RunAll(ctx)
	if err != nil {
		logger.Error("GRC provider execution failed", "error", err)
		os.Exit(1)
	}

	for _, r := range grcResults {
		if r.Err != nil {
			logger.Error("GRC provider failed", "provider", r.Provider, "error", r.Err)
		} else {
			logger.Info("GRC provider completed", "provider", r.Provider, "count", r.Count)
		}
	}

	// Phase 3: Run enrichment/mapping engine
	logger.Info("Phase 3: Running enrichment engine")
	engine := mapper.NewEnrichmentEngine(mapper.EngineConfig{
		VulnWorkspace: workspace + "/vulnz",
		GRCWorkspace:  workspace + "/grc",
		Validator:     validator,
		Logger:        logger,
	})

	mappingResults, err := engine.Run(ctx)
	if err != nil {
		logger.Error("enrichment engine failed", "error", err)
		os.Exit(1)
	}

	logger.Info("enrichment complete",
		"vulnerabilities", mappingResults.VulnCount,
		"controls", mappingResults.ControlCount,
		"mappings", mappingResults.MappingCount,
	)

	fmt.Println("Enrichment complete. Results stored in:", workspace+"/enrichment.db")
}
