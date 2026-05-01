# enrichment-engine - Interface Design Improvement Plan

## Current State Assessment

**Status**: Partial interface design
**Effort Required**: Small

### Existing Interfaces

| Interface | Location | Purpose |
|-----------|----------|---------|
| `grc.GRCProvider` | `pkg/grc/provider.go:13` | Interface for GRC data providers |
| `storage.Backend` | `pkg/storage/sqlite.go:19` | Storage for vulnerabilities, GRC controls, mappings |

### Interface Usage Patterns

1. **GRC Provider pattern**: Well-designed with `GRCProvider` interface and registry pattern
2. **Storage abstraction**: Uses its own `storage.Backend` interface (similar to vulnz's `pkg/storage`)
3. **Dependency**: Imports vulnz via `go.mod` replace directive (`../vulnz`)

## Required Refactoring

### 1. Align Storage Interface with vulnz (Priority: High)

**Problem**: After vulnz unifies its storage interfaces (see `IMPROVEMENTS_vulnz.md`), enrichment-engine's `storage.Backend` should align with the unified interface.

**Solution**:
```go
// pkg/storage/backend.go - Align with vulnz's unified interface
package storage

import (
    "context"
    "github.com/shift/vulnz/pkg/storage"
)

// Re-export vulnz's unified Backend interface for consistency
type Backend = storage.Backend

// Or if custom methods needed:
type Backend interface {
    storage.Backend // Embed unified interface
    
    // Any enrichment-engine specific methods
    // (currently none, but future-proofing)
}
```

**Files to modify**:
- `pkg/storage/sqlite.go` - update to implement unified interface
- `pkg/storage/backend.go` (new file for interface definition)
- Update all usages to reference unified interface

### 2. Extract Main Enrichment Engine Interface (Priority: High)

**Problem**: The main enrichment logic in `pkg/enricher/engine.go` uses concrete types.

**Solution**:
```go
// pkg/enricher/engine.go
type EnrichmentEngine interface {
    // Run executes the full enrichment pipeline
    Run(ctx context.Context, opts ...Option) (*EnrichmentResult, error)
    
    // RunProvider runs enrichment for a specific provider
    RunProvider(ctx context.Context, providerName string, opts ...Option) (*ProviderResult, error)
    
    // ListProviders returns available GRC providers
    ListProviders() []string
}

type Option func(*EnrichmentConfig)

type EnrichmentConfig struct {
    MaxParallel int
    Frameworks  []string
    Tags        []string
}

type EnrichmentResult struct {
    TotalMappings int
    ProvidersRun  []string
    Errors        []error
}

// Keep concrete type for internal use
type enrichmentEngine struct { /* implementation */ }

func NewEnrichmentEngine(backend storage.Backend, logger *slog.Logger) EnrichmentEngine {
    return &enrichmentEngine{
        backend: backend,
        logger:  logger,
        registry: grc.DefaultRegistry(),
    }
}
```

**Files to modify**:
- `pkg/enricher/engine.go` - extract interface and update constructor

### 3. Add CLI Command Interface (Priority: Medium)

**Problem**: CLI commands in `internal/cli/` use concrete types.

**Solution**:
```go
// internal/cli/runner.go
type CommandRunner interface {
    Run(ctx context.Context, args []string) error
}

// Each command implements this interface
type RunCommand struct { /* implementation */ }
type ListCommand struct { /* implementation */ }
type ClearCommand struct { /* implementation */ }
```

**Files to modify**:
- `internal/cli/root.go`
- `internal/cli/run.go`
- `internal/cli/list.go`
- `internal/cli/clear.go`
- `internal/cli/grc.go`

### 4. Standardize Registry Pattern (Priority: Low)

**Problem**: Registry uses factory functions instead of interface-based registration.

**Current pattern** (in `pkg/grc/provider.go`):
```go
type providerFactory func(s storage.Backend, l *slog.Logger) GRCProvider
```

**Optional improvement**:
```go
type GRCProviderFactory interface {
    Create(s storage.Backend, l *slog.Logger) GRCProvider
}

// Registry accepts factories
func (r *Registry) Register(name string, factory GRCProviderFactory)
```

**Files to modify**:
- `pkg/grc/provider.go`

## Implementation Order

1. **Phase 1** (1-2 hours): Align storage interface with vulnz unified interface (after vulnz completes Phase 1)
2. **Phase 2** (1-2 hours): Extract main EnrichmentEngine interface
3. **Phase 3** (1-2 hours): Add CLI Command interface
4. **Phase 4** (1 hour): Standardize Registry pattern (optional)

## Dependencies

- **Blocked by**: vulnz `IMPROVEMENTS_vulnz.md` Phase 1 (storage unification)
- **After completion**: transparenz-server can use aligned interfaces

## Testing Strategy

- All interface changes must maintain backward compatibility
- Add interface-based unit tests for EnrichmentEngine
- Mock interfaces for CLI command tests
- Ensure transparenz-server integration still works

## Success Criteria

- [ ] Storage interface aligned with vulnz unified interface
- [ ] EnrichmentEngine interface extracted
- [ ] CLI commands use interfaces (optional)
- [ ] Registry pattern standardized (optional)
- [ ] All existing tests pass
- [ ] No regressions in transparenz-server integration
- [ ] Documentation updated
