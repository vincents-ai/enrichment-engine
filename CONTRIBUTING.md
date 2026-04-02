# Contributing

## Development Environment

### Nix (recommended)

```sh
nix develop
```

This provides a complete shell with Go, gopls, golangci-lint, sqlite, jq, syft, grype, oscal-cli, and cyclonedx-cli.

### Manual

Requires Go 1.25+ and SQLite.

```sh
go mod download
go build ./cmd/enrich
```

## Adding a New GRC Provider

Each provider lives in its own package under `pkg/grc/<name>/`. Follow these steps:

### 1. Create the provider package

Create `pkg/grc/<name>/provider.go`:

```go
package <name>

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/shift/enrichment-engine/pkg/grc"
	"github.com/shift/enrichment-engine/pkg/storage"
)

const FrameworkID = "<FRAMEWORK_ID>"

type Provider struct {
	store  storage.Backend
	logger *slog.Logger
}

func New(store storage.Backend, logger *slog.Logger) *Provider {
	return &Provider{store: store, logger: logger}
}

func (p *Provider) Name() string { return "<name>" }

func (p *Provider) Run(ctx context.Context) (int, error) {
	controls := embeddedControls()
	count := 0
	for _, ctrl := range controls {
		id := fmt.Sprintf("%s/%s", FrameworkID, ctrl.ControlID)
		if err := p.store.WriteControl(ctx, id, ctrl); err != nil {
			p.logger.Warn("failed to write control", "id", id, "error", err)
			continue
		}
		count++
	}
	p.logger.Info("wrote controls to storage", "count", count)
	return count, nil
}
```

### 2. Define controls with CWE mappings

Controls must include `RelatedCWEs` for the enrichment engine to map vulnerabilities. Use a helper map:

```go
var cweMap = map[string][]string{
	"CTRL-001": {"CWE-79", "CWE-89"},
	"CTRL-002": {"CWE-287", "CWE-798"},
}

func embeddedControls() []grc.Control {
	return []grc.Control{
		{
			Framework:   FrameworkID,
			ControlID:   "CTRL-001",
			Title:       "Input Validation",
			Description: "All user input must be validated and sanitized.",
			Family:      "Security",
			RelatedCWEs: cweMap["CTRL-001"],
		},
	}
}
```

### 3. Register in the builtin registry

Add to `pkg/grc/builtin/builtin.go`:

```go
import "github.com/shift/enrichment-engine/pkg/grc/<name>"

// In DefaultRegistry():
reg.Register("<name>", func(s storage.Backend, l *slog.Logger) grc.GRCProvider {
	return <name>.New(s, l)
})
```

### 4. Add tests

Create `pkg/grc/<name>/provider_test.go`:

```go
package <name>

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/shift/enrichment-engine/pkg/storage"
)

func TestProvider(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	store, err := storage.NewSQLiteBackend(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close(context.Background())

	p := New(store, logger)
	if p.Name() != "<name>" {
		t.Errorf("expected name <name>, got %s", p.Name())
	}

	count, err := p.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if count == 0 {
		t.Error("expected controls to be written")
	}
}
```

### 5. Verify

```sh
go test ./pkg/grc/<name>/...
enrich providers   # verify your provider appears
```

## Code Style

- Follow [Effective Go](https://go.dev/doc/effective_go) conventions
- Tabs for indentation, not spaces
- No comments unless specifically requested
- All exported types and functions must have doc comments
- Use `log/slog` for logging, never `fmt.Println` in library code
- Provider package names use lowercase with underscores: `pci_dss`, `nist_csf`
- Control IDs use the framework's native identifier format

## Testing Requirements

All contributions must pass the four-layer test suite:

| Layer | Command |
|-------|---------|
| Unit | `go test ./pkg/...` |
| Integration | `go test ./test/integration/...` |
| Property-based | `go test ./pkg/... -run Rapid` |
| Behavioral | `GODOG=1 go test ./test/behavioral/...` |

New providers must include a unit test in their package.

## Commit Messages

Use conventional commits:

```
feat(grc): add PCI DSS v4.0 provider
fix(storage): handle concurrent writes in SQLite backend
test(enricher): add CWE mapping integration tests
refactor(cli): extract workspace initialization
```

## Pull Request Process

1. Fork the repository
2. Create a feature branch from `main`
3. Implement changes with tests
4. Run the full test suite (`go test ./...`)
5. Open a pull request with a clear description
6. Ensure all CI checks pass before requesting review
