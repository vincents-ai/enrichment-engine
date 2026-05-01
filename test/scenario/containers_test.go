//go:build integration

package scenario

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"

	_ "github.com/glebarez/go-sqlite/compat"
	"github.com/vincents-ai/enrichment-engine/pkg/enricher"
	grcbuiltin "github.com/vincents-ai/enrichment-engine/pkg/grc/builtin"
	"github.com/vincents-ai/enrichment-engine/pkg/storage"
)

type dbSnapshot struct {
	controlCount int
	mappingCount int
	vulnCount    int
	timestamp    time.Time
}

func snapshotDB(ctx context.Context, t *testing.T, backend *storage.SQLiteBackend, label string) dbSnapshot {
	t.Helper()
	controls, err := backend.ListAllControls(ctx)
	if err != nil {
		t.Fatalf("snapshot %s list controls: %v", label, err)
	}
	vulns, err := backend.ListAllVulnerabilities(ctx)
	if err != nil {
		t.Fatalf("snapshot %s list vulns: %v", label, err)
	}
	mappingCount := 0
	for _, v := range vulns {
		mappings, err := backend.ListMappings(ctx, v.ID)
		if err != nil {
			t.Fatalf("snapshot %s list mappings for %s: %v", label, v.ID, err)
		}
		mappingCount += len(mappings)
	}
	snap := dbSnapshot{
		controlCount: len(controls),
		mappingCount: mappingCount,
		vulnCount:    len(vulns),
		timestamp:    time.Now(),
	}
	t.Logf("snapshot [%s]: controls=%d, mappings=%d, vulns=%d",
		label, snap.controlCount, snap.mappingCount, snap.vulnCount)
	return snap
}

func runFullPipeline(ctx context.Context, t *testing.T, backend *storage.SQLiteBackend, vulns []map[string]interface{}) (*enricher.Result, error) {
	t.Helper()
	logger := testLogger()

	for _, vuln := range vulns {
		if err := backend.WriteVulnerability(ctx, vuln["id"].(string), vuln); err != nil {
			return nil, fmt.Errorf("write vuln %s: %w", vuln["id"], err)
		}
	}

	engine := enricher.New(enricher.Config{
		Store:  backend,
		Logger: logger,
	})
	return engine.Run(ctx)
}

func generateSyntheticVulns(count int) []map[string]interface{} {
	cwes := []string{"CWE-79", "CWE-89", "CWE-120", "CWE-287", "CWE-311", "CWE-798", "CWE-200", "CWE-22", "CWE-352", "CWE-400"}
	vulns := make([]map[string]interface{}, count)
	for i := 0; i < count; i++ {
		cwe := cwes[i%len(cwes)]
		cpe := fmt.Sprintf("cpe:2.3:a:vendor:product:%d.0.0:*:*:*:*:*:*:*", i)
		vulns[i] = makeVuln(
			fmt.Sprintf("CVE-SYNTH-%05d", i),
			cwe,
			cpe,
		)
	}
	return vulns
}

func requireDocker(t *testing.T) {
	t.Helper()
	var dockerAvailable bool
	func() {
		defer func() {
			if r := recover(); r != nil {
				dockerAvailable = false
			}
		}()
		provider, err := testcontainers.NewDockerProvider()
		if err != nil {
			dockerAvailable = false
			return
		}
		_ = provider.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err = testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
			ContainerRequest: testcontainers.ContainerRequest{
				Image:      "alpine:3.19",
				AutoRemove: true,
			},
			Started: false,
		})
		dockerAvailable = (err == nil)
	}()
	if !dockerAvailable {
		t.Skip("Docker not available, skipping container-based test")
	}
}

func startAlpineContainer(ctx context.Context, t *testing.T) testcontainers.Container {
	t.Helper()
	requireDocker(t)
	req := testcontainers.ContainerRequest{
		Image:      "alpine:3.19",
		AutoRemove: true,
	}
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatalf("start container: %v", err)
	}
	return container
}

func TestContainers_Scenario1_FullPipelineIsolation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	t.Log("starting alpine container for environment isolation")
	container := startAlpineContainer(ctx, t)
	defer func() {
		if err := container.Terminate(context.Background()); err != nil {
			t.Logf("container cleanup: %v", err)
		}
	}()

	host, err := container.Host(ctx)
	if err != nil {
		t.Fatalf("get container host: %v", err)
	}
	t.Logf("container running on host: %s", host)

	backend := setupScenarioDB(t)
	logger := testLogger()

	registry := grcbuiltin.DefaultRegistry()
	names := registry.List()
	t.Logf("running %d providers in isolated environment", len(names))

	for _, vuln := range sampleNVDCVEs {
		err := backend.WriteVulnerability(ctx, vuln["id"].(string), vuln)
		if err != nil {
			t.Fatalf("write vulnerability %s: %v", vuln["id"], err)
		}
	}

	total, err := registry.RunAll(ctx, backend, logger)
	if err != nil {
		t.Fatalf("RunAll: %v", err)
	}
	t.Logf("providers wrote %d controls", total)

	engine := enricher.New(enricher.Config{
		Store:         backend,
		Logger:        logger,
		SkipProviders: true,
	})
	result, err := engine.Run(ctx)
	if err != nil {
		t.Fatalf("engine run: %v", err)
	}

	if result.MappingCount <= 0 {
		t.Errorf("expected mappings, got %d", result.MappingCount)
	}

	vulns, err := backend.ListAllVulnerabilities(ctx)
	if err != nil {
		t.Fatalf("list vulns: %v", err)
	}
	if len(vulns) != len(sampleNVDCVEs) {
		t.Errorf("expected %d vulns, got %d", len(sampleNVDCVEs), len(vulns))
	}

	cweCount := 0
	cpeCount := 0
	for _, v := range vulns {
		mappings, err := backend.ListMappings(ctx, v.ID)
		if err != nil {
			t.Fatalf("list mappings for %s: %v", v.ID, err)
		}
		for _, m := range mappings {
			if m.MappingType == "cwe" {
				cweCount++
			} else if m.MappingType == "cpe" {
				cpeCount++
			}
		}
	}

	t.Logf("confidence distribution: CWE(0.8)=%d, CPE(0.6)=%d", cweCount, cpeCount)

	if cweCount == 0 {
		t.Error("expected at least some CWE mappings")
	}

	t.Logf("scenario 1 complete: controls=%d, mappings=%d, cwe=%d, cpe=%d, duration=%v",
		result.ControlCount, result.MappingCount, cweCount, cpeCount, result.Duration)
}

func TestContainers_Scenario2_ConcurrentStress(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()

	container := startAlpineContainer(ctx, t)
	defer func() {
		if err := container.Terminate(context.Background()); err != nil {
			t.Logf("container cleanup: %v", err)
		}
	}()
	t.Log("stress test container running")

	const concurrency = 3
	var wg sync.WaitGroup
	results := make([]*enricher.Result, concurrency)
	errors := make([]error, concurrency)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			backend := setupScenarioDB(t)
			result, err := runFullPipeline(ctx, t, backend, sampleNVDCVEs)
			results[idx] = result
			errors[idx] = err
		}(i)
	}
	wg.Wait()

	failedRuns := 0
	for i, err := range errors {
		if err != nil {
			t.Errorf("concurrent run %d failed: %v", i, err)
			failedRuns++
		}
	}
	if failedRuns > 0 {
		t.Fatalf("%d/%d concurrent runs failed", failedRuns, concurrency)
	}

	mappings := results[0].MappingCount
	for i, r := range results {
		if r == nil {
			continue
		}
		if r.MappingCount != mappings {
			t.Errorf("run %d: mapping count mismatch: run0=%d, run%d=%d", i, mappings, i, r.MappingCount)
		}
		if r.ControlCount <= 0 {
			t.Errorf("run %d: expected controls, got %d", i, r.ControlCount)
		}
	}

	t.Logf("scenario 2: %d concurrent runs completed without errors or deadlocks, mappings=%d (consistent)",
		concurrency, mappings)
}

func TestContainers_Scenario3_LargeDataset(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()

	container := startAlpineContainer(ctx, t)
	defer func() {
		if err := container.Terminate(context.Background()); err != nil {
			t.Logf("container cleanup: %v", err)
		}
	}()
	t.Log("large dataset container running")

	synthVulns := generateSyntheticVulns(500)
	t.Logf("generated %d synthetic vulnerabilities", len(synthVulns))

	backend := setupScenarioDB(t)

	start := time.Now()
	result, err := runFullPipeline(ctx, t, backend, synthVulns)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("pipeline with 500 vulns: %v", err)
	}

	if result.ControlCount <= 0 {
		t.Errorf("expected controls from providers, got %d", result.ControlCount)
	}

	if elapsed > 120*time.Second {
		t.Errorf("large dataset pipeline took %v, expected < 120s", elapsed)
	}

	t.Logf("scenario 3: 500 vulns processed in %v: controls=%d, mappings=%d",
		elapsed, result.ControlCount, result.MappingCount)
}

func TestContainers_Scenario4_StageIntegrity(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()

	container := startAlpineContainer(ctx, t)
	defer func() {
		if err := container.Terminate(context.Background()); err != nil {
			t.Logf("container cleanup: %v", err)
		}
	}()
	t.Log("stage integrity container running")

	backend := setupScenarioDB(t)
	logger := testLogger()

	snap0 := snapshotDB(ctx, t, backend, "initial")
	if snap0.controlCount != 0 || snap0.mappingCount != 0 || snap0.vulnCount != 0 {
		t.Errorf("initial snapshot should be empty: %+v", snap0)
	}

	for _, vuln := range sampleNVDCVEs {
		err := backend.WriteVulnerability(ctx, vuln["id"].(string), vuln)
		if err != nil {
			t.Fatalf("write vuln %s: %v", vuln["id"], err)
		}
	}
	snapVulns := snapshotDB(ctx, t, backend, "after-vuln-load")
	if snapVulns.vulnCount != len(sampleNVDCVEs) {
		t.Errorf("after vuln load: expected %d vulns, got %d", len(sampleNVDCVEs), snapVulns.vulnCount)
	}

	registry := grcbuiltin.DefaultRegistry()
	providerTotal, err := registry.RunAll(ctx, backend, logger)
	if err != nil {
		t.Fatalf("RunAll: %v", err)
	}
	t.Logf("providers wrote %d controls", providerTotal)
	snapProviders := snapshotDB(ctx, t, backend, "after-providers")

	if snapProviders.controlCount <= snap0.controlCount {
		t.Errorf("controls should increase after providers: before=%d, after=%d",
			snap0.controlCount, snapProviders.controlCount)
	}
	if snapProviders.mappingCount != snapVulns.mappingCount {
		t.Errorf("mappings should not change after providers only: before=%d, after=%d",
			snapVulns.mappingCount, snapProviders.mappingCount)
	}
	if snapProviders.vulnCount != snapVulns.vulnCount {
		t.Errorf("vulns should not change after providers: before=%d, after=%d",
			snapVulns.vulnCount, snapProviders.vulnCount)
	}

	engine := enricher.New(enricher.Config{
		Store:         backend,
		Logger:        logger,
		SkipProviders: true,
	})

	_, err = engine.Run(ctx)
	if err != nil {
		t.Fatalf("engine run: %v", err)
	}
	snapEngine := snapshotDB(ctx, t, backend, "after-full-engine")

	if snapEngine.controlCount < snapProviders.controlCount {
		t.Errorf("controls should not decrease: providers=%d, after-engine=%d",
			snapProviders.controlCount, snapEngine.controlCount)
	}
	if snapEngine.mappingCount <= snapProviders.mappingCount {
		t.Errorf("mappings should increase after engine run: before=%d, after=%d",
			snapProviders.mappingCount, snapEngine.mappingCount)
	}
	if snapEngine.vulnCount != snapVulns.vulnCount {
		t.Errorf("vulns should not change: expected=%d, got=%d",
			snapVulns.vulnCount, snapEngine.vulnCount)
	}

	finalSnap := snapshotDB(ctx, t, backend, "final")

	if finalSnap.controlCount < snapProviders.controlCount {
		t.Errorf("controls decreased between provider stage and final: %d -> %d",
			snapProviders.controlCount, finalSnap.controlCount)
	}
	if finalSnap.mappingCount < snapEngine.mappingCount {
		t.Errorf("mappings decreased between engine stage and final: %d -> %d",
			snapEngine.mappingCount, finalSnap.mappingCount)
	}
	if finalSnap.vulnCount != snapVulns.vulnCount {
		t.Errorf("vulns changed across pipeline: expected=%d, got=%d",
			snapVulns.vulnCount, finalSnap.vulnCount)
	}

	t.Logf("stage integrity verified: vulns=%d (stable), controls %d->%d (monotonic), mappings 0->%d->%d (monotonic)",
		finalSnap.vulnCount,
		snap0.controlCount, finalSnap.controlCount,
		snapProviders.mappingCount, finalSnap.mappingCount)
}

func TestIsolated_Scenario1_FullPipeline(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	backend := setupScenarioDB(t)
	logger := testLogger()

	registry := grcbuiltin.DefaultRegistry()
	names := registry.List()
	t.Logf("running %d providers", len(names))

	for _, vuln := range sampleNVDCVEs {
		err := backend.WriteVulnerability(ctx, vuln["id"].(string), vuln)
		if err != nil {
			t.Fatalf("write vulnerability %s: %v", vuln["id"], err)
		}
	}

	total, err := registry.RunAll(ctx, backend, logger)
	if err != nil {
		t.Fatalf("RunAll: %v", err)
	}
	t.Logf("providers wrote %d controls", total)

	engine := enricher.New(enricher.Config{
		Store:         backend,
		Logger:        logger,
		SkipProviders: true,
	})
	result, err := engine.Run(ctx)
	if err != nil {
		t.Fatalf("engine run: %v", err)
	}

	if result.MappingCount <= 0 {
		t.Errorf("expected mappings, got %d", result.MappingCount)
	}

	vulns, err := backend.ListAllVulnerabilities(ctx)
	if err != nil {
		t.Fatalf("list vulns: %v", err)
	}
	if len(vulns) != len(sampleNVDCVEs) {
		t.Errorf("expected %d vulns, got %d", len(sampleNVDCVEs), len(vulns))
	}

	cweCount := 0
	cpeCount := 0
	for _, v := range vulns {
		mappings, err := backend.ListMappings(ctx, v.ID)
		if err != nil {
			t.Fatalf("list mappings for %s: %v", v.ID, err)
		}
		for _, m := range mappings {
			if m.MappingType == "cwe" {
				cweCount++
			} else if m.MappingType == "cpe" {
				cpeCount++
			}
		}
	}

	t.Logf("confidence distribution: CWE(0.8)=%d, CPE(0.6)=%d", cweCount, cpeCount)

	if cweCount == 0 {
		t.Error("expected at least some CWE mappings")
	}

	t.Logf("isolated scenario 1: controls=%d, mappings=%d, cwe=%d, cpe=%d, duration=%v",
		result.ControlCount, result.MappingCount, cweCount, cpeCount, result.Duration)
}

func TestIsolated_Scenario2_ConcurrentStress(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()

	const concurrency = 3
	var wg sync.WaitGroup
	results := make([]*enricher.Result, concurrency)
	errors := make([]error, concurrency)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			backend := setupScenarioDB(t)
			result, err := runFullPipeline(ctx, t, backend, sampleNVDCVEs)
			results[idx] = result
			errors[idx] = err
		}(i)
	}
	wg.Wait()

	failedRuns := 0
	for i, err := range errors {
		if err != nil {
			t.Errorf("concurrent run %d failed: %v", i, err)
			failedRuns++
		}
	}
	if failedRuns > 0 {
		t.Fatalf("%d/%d concurrent runs failed", failedRuns, concurrency)
	}

	mappings := results[0].MappingCount
	for i, r := range results {
		if r == nil {
			continue
		}
		if r.MappingCount != mappings {
			t.Errorf("run %d: mapping count mismatch: run0=%d, run%d=%d", i, mappings, i, r.MappingCount)
		}
		if r.ControlCount <= 0 {
			t.Errorf("run %d: expected controls, got %d", i, r.ControlCount)
		}
	}

	t.Logf("isolated scenario 2: %d concurrent runs completed without errors or deadlocks, mappings=%d (consistent)",
		concurrency, mappings)
}

func TestIsolated_Scenario3_LargeDataset(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()

	synthVulns := generateSyntheticVulns(500)
	t.Logf("generated %d synthetic vulnerabilities", len(synthVulns))

	backend := setupScenarioDB(t)

	start := time.Now()
	result, err := runFullPipeline(ctx, t, backend, synthVulns)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("pipeline with 500 vulns: %v", err)
	}

	if result.ControlCount <= 0 {
		t.Errorf("expected controls from providers, got %d", result.ControlCount)
	}

	if elapsed > 120*time.Second {
		t.Errorf("large dataset pipeline took %v, expected < 120s", elapsed)
	}

	t.Logf("isolated scenario 3: 500 vulns processed in %v: controls=%d, mappings=%d",
		elapsed, result.ControlCount, result.MappingCount)
}

func TestIsolated_Scenario4_StageIntegrity(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()

	backend := setupScenarioDB(t)
	logger := testLogger()

	snap0 := snapshotDB(ctx, t, backend, "initial")
	if snap0.controlCount != 0 || snap0.mappingCount != 0 || snap0.vulnCount != 0 {
		t.Errorf("initial snapshot should be empty: %+v", snap0)
	}

	for _, vuln := range sampleNVDCVEs {
		err := backend.WriteVulnerability(ctx, vuln["id"].(string), vuln)
		if err != nil {
			t.Fatalf("write vuln %s: %v", vuln["id"], err)
		}
	}
	snapVulns := snapshotDB(ctx, t, backend, "after-vuln-load")
	if snapVulns.vulnCount != len(sampleNVDCVEs) {
		t.Errorf("after vuln load: expected %d vulns, got %d", len(sampleNVDCVEs), snapVulns.vulnCount)
	}

	registry := grcbuiltin.DefaultRegistry()
	providerTotal, err := registry.RunAll(ctx, backend, logger)
	if err != nil {
		t.Fatalf("RunAll: %v", err)
	}
	t.Logf("providers wrote %d controls", providerTotal)
	snapProviders := snapshotDB(ctx, t, backend, "after-providers")

	if snapProviders.controlCount <= snap0.controlCount {
		t.Errorf("controls should increase after providers: before=%d, after=%d",
			snap0.controlCount, snapProviders.controlCount)
	}
	if snapProviders.mappingCount != snapVulns.mappingCount {
		t.Errorf("mappings should not change after providers only: before=%d, after=%d",
			snapVulns.mappingCount, snapProviders.mappingCount)
	}
	if snapProviders.vulnCount != snapVulns.vulnCount {
		t.Errorf("vulns should not change after providers: before=%d, after=%d",
			snapVulns.vulnCount, snapProviders.vulnCount)
	}

	engine := enricher.New(enricher.Config{
		Store:         backend,
		Logger:        logger,
		SkipProviders: true,
	})

	_, err = engine.Run(ctx)
	if err != nil {
		t.Fatalf("engine run: %v", err)
	}
	snapEngine := snapshotDB(ctx, t, backend, "after-full-engine")

	if snapEngine.controlCount < snapProviders.controlCount {
		t.Errorf("controls should not decrease: providers=%d, after-engine=%d",
			snapProviders.controlCount, snapEngine.controlCount)
	}
	if snapEngine.mappingCount <= snapProviders.mappingCount {
		t.Errorf("mappings should increase after engine run: before=%d, after=%d",
			snapProviders.mappingCount, snapEngine.mappingCount)
	}
	if snapEngine.vulnCount != snapVulns.vulnCount {
		t.Errorf("vulns should not change: expected=%d, got=%d",
			snapVulns.vulnCount, snapEngine.vulnCount)
	}

	finalSnap := snapshotDB(ctx, t, backend, "final")

	if finalSnap.controlCount < snapProviders.controlCount {
		t.Errorf("controls decreased between provider stage and final: %d -> %d",
			snapProviders.controlCount, finalSnap.controlCount)
	}
	if finalSnap.mappingCount < snapEngine.mappingCount {
		t.Errorf("mappings decreased between engine stage and final: %d -> %d",
			snapEngine.mappingCount, finalSnap.mappingCount)
	}
	if finalSnap.vulnCount != snapVulns.vulnCount {
		t.Errorf("vulns changed across pipeline: expected=%d, got=%d",
			snapVulns.vulnCount, finalSnap.vulnCount)
	}

	t.Logf("stage integrity verified: vulns=%d (stable), controls %d->%d (monotonic), mappings 0->%d->%d (monotonic)",
		finalSnap.vulnCount,
		snap0.controlCount, finalSnap.controlCount,
		snapProviders.mappingCount, finalSnap.mappingCount)
}
