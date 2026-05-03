# Contributing to Enrichment Engine

Thank you for your interest in contributing! This project maps CVEs to GRC controls across 74 providers and 67 EU/international frameworks.

## Prerequisites

- **Go 1.25+** — [go.dev/dl](https://go.dev/dl/)
- **Nix** (optional) — reproducible builds via `nix develop`

## Building

```bash
go build ./...
```

## Testing

```bash
# Unit tests
go test ./...

# Integration tests
go test -tags integration -count=1 -timeout 10m ./...

# Behavioral tests (godog)
go test -tags behavioral -count=1 -timeout 10m ./test/behavioral/...

# Verification tests
go test -tags verification -count=1 -timeout 30m ./test/verification/...

# Fuzz tests
make test-fuzz
```

## Adding a New GRC Provider

1. Create a new file in `internal/provider/<name>/`
2. Implement the `Provider` interface
3. Register in `internal/provider/registry.go`
4. Add behavioral test in `test/behavioral/`
5. Update provider list in README

## Commit Convention

We use [Conventional Commits](https://www.conventionalcommits.org/).

## License

By contributing, you agree that your contributions will be licensed under the AGPL-3.0 license.
