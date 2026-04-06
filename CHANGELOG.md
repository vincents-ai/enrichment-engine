# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

## [0.3.0] - 2026-04-06

### Added
- 9 new GRC providers: `nist_ssdf` (NIST SSDF), `slsa` (SLSA L1–L4), `eu_ai_act` (EU AI Act), `tisax` (TISAX), `b3s` (B3S), `ncsc_caf` (NCSC CAF), `bait` (BAIT), `vait` (VAIT), `kait_zait` (KAIT/ZAIT) — total registry now 54 providers
- vulnz-go library integration: vulnerability ingestion via `runVulnzIngest`
- Tags added to all 54 GRC providers enabling full `mapByTag()` coverage
- End-to-end testing with NixOS VM tests and Go E2E scenario suite
- Export, ingest, and vulnz packages
- 15 additional tests across enrichment, storage, behavioral, and E2E domains
- CI coverage gate enforced at 90% minimum

### Fixed
- sqlite3 driver double-registration panic (removed glebarez compat shim)
- 2 behavioral test failures in CI
- golangci-lint v2 configuration (removed `typecheck` linter, now built-in)
- Flaky storage tests in CI

## [0.2.0] - 2026-04-03

### Added
- Full CLI flag wiring: `--workspace`, `--log-level`, `--skip-mapping`, `--provider`, `--skip-providers`
- Parallel provider execution
- `enrich status` command reporting workspace state
- `Version` variable plumbed through to `enrich version`
- `ListControlsByCPE` via indirect CWE lookup
- `Result.VulnCount` and `Result.ProviderCount` fields
- CWE-502, CWE-119, CWE-78, CWE-22 coverage added to relevant providers
- Verification test suite: 18 CVEs across 14 CWEs, 88 provider CWEs verified
- 99.3% Go statement coverage (up from 57.8%)
- 100% CWE coverage across all mapped CVEs
- 4-layer test suite: unit, integration, property-based (rapid), behavioral (godog), E2E scenario
- `RelatedCWEs` populated for 12 providers
- CI/CD pipeline, `golangci-lint`, `Makefile`, README, CONTRIBUTING

### Fixed
- `mapping_type` added to DB primary key so CWE and CPE mappings coexist without collision
- `EnrichSBOM` integration tests now carry proper vuln+CWE data chain
- Shared HTTP client with 30-second timeout across all providers
- `os.CreateTemp` used in all providers (replaced unsafe temp file patterns)

### Removed
- Unused types: `Framework`, `Asset`, `Threat`, `Risk`, `PURL`
- Stale rapid testdata from pre-fix failures

## [0.1.0] - 2026-04-01

### Added
- Core enrichment engine infrastructure: SQLite WAL backend, schema, provider registry
- Three-phase enrichment pipeline: provider execution → CWE direct mapping (confidence 0.8) → CPE indirect mapping (confidence 0.6)
- SBOM enrichment pass annotating components with applicable controls and frameworks
- `enrich run`, `enrich providers`, `enrich status`, `enrich version` CLI commands
- 45 built-in GRC providers across four categories:
  - EU Regulatory (18): CEN-CENELEC CRA, CEN-CENELEC Cyber, CERT-EU, DORA, ENISA CRA mapping, ENISA threat, ENS, ETSI NIS2, ETSI standards, EUCC, EU Common Criteria, EU CRA, EU Cybersecurity Act, EU Data Act, EU RED, GDPR, NIS2, NIS2 Implementing Acts
  - EU National Standards (7): ACN/PSNC, ANSSI EBIOS, BIO/IT-Grundschutz, BSI Grundschutz, SecNumCloud, TOMs, RoPA
  - International Frameworks (14): CIS Benchmarks, CIS Controls, COBIT, CMMC, CSA CCM, DISA STIGs, FedRAMP, HIPAA, ISO 27001, NIST CSF, NIST OSCAL, PCI DSS, SOC 2, SCAP/XCCDF
  - ISMS Feeds (6): CSPM, IAM, K8s/Terraform, MISP, MITRE ATT&CK, VERIS/VCDB
- Pure-Go SQLite driver (no CGO dependency)
- Nix flake with full development shell (Go, gopls, golangci-lint, sqlite, jq, syft, grype, oscal-cli, cyclonedx-cli)
- Unit tests for storage, schema, and 23 GRC providers
- Property-based tests using `pgregory.net/rapid`

### Fixed
- BSI IT-Grundschutz provider updated to parse XML instead of JSON
- Pure-Go SQLite migration fixing schema compilation under `CGO_ENABLED=0`
