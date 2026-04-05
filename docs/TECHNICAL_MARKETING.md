# Enrichment Engine -- Technical Product Brief

> **Bridging the gap between vulnerability data and regulatory compliance.**

---

## The Problem

Security teams operate in two disconnected worlds. On one side, vulnerability scanners produce CVEs, CWEs, and CPEs -- technical artifacts describing what is broken. On the other, compliance teams manage control frameworks like NIS2, DORA, ISO 27001, HIPAA, and PCI DSS -- regulatory artifacts describing what must be done. Translating between these two domains is manual, error-prone, and unscalable.

Every vulnerability disclosure triggers the same question: **which of our compliance obligations does this affect?** Without automated traceability, organizations either over-audit (checking everything against every framework) or under-audit (missing real obligations), both of which carry material risk.

## The Solution

**Enrichment Engine** is a Go-native GRC enrichment pipeline that automatically maps CVE vulnerabilities to compliance control frameworks via CWE matching. It ingests NVD 2.0 vulnerability feeds, cross-references them against 45 regulatory and standards frameworks, and produces auditable traceability artifacts in CycloneDX 1.5 format.

A single binary. Zero external runtime dependencies. CGO-free.

---

## Core Capabilities

### Multi-Phase Enrichment Pipeline

The engine applies a layered mapping strategy, each phase with a calibrated confidence score:

| Phase | Method | Confidence | Description |
|-------|--------|-----------|-------------|
| 1 | CWE Direct Mapping | **0.8** | Vulnerability CWE identifiers matched directly against control `RelatedCWEs` fields |
| 2 | CPE Indirect Mapping | **0.6** | CPE-based cross-referencing via shared CWE bridges between vulnerabilities and controls |
| 3 | Tag-Based Mapping | **0.4** | Semantic tag matching (injection, crypto, auth) for broad coverage of edge cases |

Higher confidence scores indicate more deterministic mappings. Lower scores flag areas requiring human review. Every mapping includes an evidence chain for audit traceability.

### 45 GRC Framework Providers

The engine ships with 45 pre-built compliance control catalogs, organized into four categories:

**EU Regulatory (18 providers)**
DORA, NIS2 Directive, EU CRA, GDPR, EU Cybersecurity Act, EU Data Act, EU RED, ETSI NIS2, ETSI Standards, ENISA Threat Landscape, ENISA CRA Mapping, CEN-CENELEC CRA, CEN-CENELEC Cybersecurity, EUCC, EU Common Criteria, CERT-EU, ENS, NIS2 Implementing Acts

**EU National Standards (7 providers)**
BSI IT-Grundschutz & Grundschutz Compendium (Germany), ANSSI EBIOS & SecNumCloud (France), ACN/PSNC (Italy), TOMs, ROPA

**International Frameworks (14 providers)**
ISO/IEC 27001, NIST CSF, NIST OSCAL, PCI DSS, HIPAA, SOC 2, FedRAMP, CMMC, COBIT, CSA CCM, CIS Controls, CIS Benchmarks, DISA STIGs, SCAP/XCCDF

**ISMS & Threat Intelligence (6 providers)**
MITRE ATT&CK, MISP, VERIS/Vcdb, CSPM, IAM, K8s & Terraform

### NVD 2.0 Ingestion

Native support for the National Vulnerability Database 2.0 REST API format. Ingest vulnerability records from JSON files or stdin, with automatic CWE and CPE extraction, deduplication, and English-language filtering.

### SBOM Enrichment

Pass a Software Bill of Materials and get back enriched components with:
- Applicable compliance controls per component
- Relevant framework associations
- Compliance risk classification (`needs-review` when controls are found)

### CycloneDX 1.5 Export

Export the complete enrichment result as a standards-compliant CycloneDX 1.5 JSON BOM, including:
- Vulnerability-to-control mappings as `affects` references
- Mapping metadata (type, confidence, evidence) as `properties`
- Full audit trail embedded in the BOM artifact

---

## Architecture

```
NVD 2.0 Feed              GRC Providers (45)           CLI / Library API
     |                          |                           |
     v                          v                           v
+-----------+           +----------------+          +------------------+
| Ingestion |           |  Provider       |          |  Cobra CLI       |
| (CVE/CWE/ |           |  Registry       |          |  run / ingest /  |
|  CPE ext) |           |  (parallel/seq) |          |  export / status |
+-----+-----+           +-------+--------+          +--------+---------+
      |                         |                           |
      v                         v                           |
+---------------------------------------------------------------+
|                    SQLite WAL Storage                          |
|  vulnerabilities | grc_controls | vulnerability_grc_mappings  |
+----------------------------+------------------------------+
                             |
                    +--------v--------+
                    | Enrichment      |
                    | Engine          |
                    | (CWE/CPE/Tag)   |
                    +--------+--------+
                             |
                    +--------v--------+
                    | CycloneDX 1.5   |
                    | Serializer      |
                    +-----------------+
```

### Design Principles

- **Provider Pattern**: Each framework is an isolated provider implementing `GRCProvider`. Add new frameworks without touching core logic.
- **Registry Pattern**: Central `Registry` manages provider lifecycle, supports sorted listing, name filtering, and configurable parallel or sequential execution.
- **Atomic Storage**: SQLite writes go to a `.tmp` file; on `Close()`, the WAL is checkpointed and the file is atomically renamed. Crash-safe by design.
- **Functional Options**: Configuration via options pattern (`enricher.Config`, `vulnz.WithBaseURL()`, `cyclonedx.WithToolName()`).
- **Interface Segregation**: Clean `storage.Backend` interface with 11 methods -- swap SQLite for PostgreSQL without touching business logic.

---

## Technical Specifications

| Specification | Detail |
|---|---|
| Language | Go 1.25 |
| Binary | Single static binary, CGO-free |
| Storage | SQLite (WAL mode) via pure-Go driver |
| Output Format | CycloneDX 1.5 JSON |
| Vulnerability Source | NVD 2.0 REST API |
| Supported Architectures | linux/amd64, linux/arm64 |
| License | AGPL-3.0-only |
| Part of | Transparenz ecosystem |

### Dependencies (Production)

| Dependency | Purpose |
|---|---|
| `spf13/cobra` | CLI framework |
| `glebarez/go-sqlite` | Pure-Go SQLite (CGO-free) |
| `santhosh-tekuri/jsonschema` | JSON Schema validation for control catalogs |

### Dependencies (Development)

| Dependency | Purpose |
|---|---|
| `cucumber/godog` | BDD behavioral testing (Gherkin) |
| `testcontainers/testcontainers-go` | Container-based integration tests |
| `pgregory.net/rapid` | Property-based testing |

---

## Quality Assurance

### Four-Layer Test Strategy

| Layer | Approach | Coverage |
|---|---|---|
| **Unit Tests** | 30+ test files across all packages | CRUD, mapping logic, CWE/CPE extraction, schema validation |
| **Property-Based Tests** | `pgregory.net/rapid` fuzzing | Deduplication, malformed input safety, concurrent write safety, round-trip consistency |
| **Integration Tests** | Multi-provider, real data pipelines | Provider isolation, framework filtering, full pipeline with real providers, DB persistence |
| **Behavioral Tests** | Gherkin scenarios via godog | 6 feature files covering end-to-end CLI workflows |

### Static Analysis

11 linters enforced via golangci-lint: `govet`, `errcheck`, `gofmt`, `goimports`, `staticcheck`, `unused`, `gosimple`, `ineffassign`, `typecheck`, `misspell`, `gosec`.

### CI/CD

- GitHub Actions CI: lint, test (Go 1.24 + 1.25 matrix, race detector), build
- GitHub Actions Release: multi-arch binary builds triggered on `v*` tags with auto-generated release notes
- Nix flake: reproducible dev shell and build environment

---

## Deployment

### As a CLI Tool

```sh
enrich run --all                                    # Full pipeline
enrich run --provider hipaa --provider gdpr         # Selective frameworks
enrich run --all --skip-mapping                     # Providers only
enrich ingest --file cve-data.json                  # Load NVD 2.0 data
enrich export --output enriched-bom.json            # CycloneDX export
enrich providers                                    # List all 45 frameworks
enrich status                                       # Workspace health
```

### As a Library

```go
engine := enricher.New(enricher.Config{Store: store, Logger: logger})
result, err := engine.Run(ctx)
enriched, err := engine.EnrichSBOM(ctx, components)
```

Full programmatic API for embedding into CI/CD pipelines, policy engines, or GRC platforms.

### Build

```sh
go build ./cmd/enrich    # CGO-free, portable
nix build                 # Reproducible via Nix
```

---

## Use Cases

| Use Case | Description |
|---|---|
| **Compliance Automation** | Automatically determine which controls a new CVE impacts across all applicable frameworks |
| **Audit Readiness** | Generate auditable traceability between vulnerabilities and compliance obligations |
| **SBOM-Driven Risk Assessment** | Enrich software supply chain artifacts with compliance context |
| **Regulatory Gap Analysis** | Identify which controls lack vulnerability coverage (and vice versa) |
| **Multi-Framework Convergence** | See a single vulnerability's impact across NIS2, DORA, ISO 27001, and PCI DSS simultaneously |
| **CI/CD Pipeline Integration** | Embed compliance checks into build pipelines via the Go library API |

---

## Why Enrichment Engine

- **Breadth**: 45 frameworks out of the box -- EU regulatory, international standards, national schemes, and threat intelligence feeds
- **Depth**: Multi-phase mapping with calibrated confidence scores, not binary pass/fail
- **Traceability**: Every mapping includes evidence chains for audit compliance
- **Standards**: CycloneDX 1.5 output, NVD 2.0 input, JSON Schema validation
- **Simplicity**: Single binary, zero runtime dependencies, SQLite storage
- **Extensibility**: Provider interface makes adding new frameworks trivial
- **Correctness**: Four-layer test strategy with property-based and behavioral testing
- **Open Source**: AGPL-3.0-only, part of the Transparenz ecosystem
