# enrichment-engine

[![Go Version](https://img.shields.io/badge/Go-1.25-00ADD8)](https://go.dev/)
[![License: Commercial](https://img.shields.io/badge/License-Commercial%20%2B%20AGPL--3.0-orange)](LICENSE.md)
[![Build: Nix](https://img.shields.io/badge/Build-Nix-5277C3)](https://nixos.org/)

GRC enrichment engine for vulnerability-to-compliance control mapping. Part of the [Transparenz](https://github.com/vincents-ai/transparenz) ecosystem.

Maps CVEs to compliance control frameworks via CWE matching, producing auditable traceability between vulnerabilities and regulatory requirements across 74 GRC providers.

## Architecture

```
GRC Providers (74)              Storage (SQLite WAL)          Enrichment Engine
+------------------+          +--------------------+        +------------------+
| EU Regulatory    |  writes  | vulnerabilities    |  reads | CWE mapping      |
| EU Standards     | ------> | grc_controls       | ------> |  (confidence 0.8)|
| International    |          | vuln_grc_mappings  |        | CPE mapping      |
| ISMS Feeds       |          +--------------------+        |  (confidence 0.6)|
+------------------+                                           +------------------+
```

Three-phase pipeline:
1. **Provider execution** -- all registered providers write their control catalogs to SQLite
2. **CWE direct mapping** -- vulnerability CWEs matched against control `RelatedCWEs` (confidence 0.8)
3. **CPE indirect mapping** -- CPE-based cross-referencing via shared CWEs (confidence 0.6)

SBOM enrichment is available as a separate pass, annotating components with applicable controls and frameworks.

## Quick Start

### Build

```sh
go build ./cmd/enrich
```

Or via Nix:

```sh
nix build
```

### CLI Usage

```sh
# Run all providers and full enrichment pipeline
enrich run --all

# Run providers only, skip mapping
enrich run --all --skip-mapping

# Run specific providers
enrich run --provider hipaa --provider gdpr

# List registered providers
enrich providers

# Workspace status
enrich status

# Version
enrich version
```

### Flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--workspace` | `-w` | `./data` | Workspace directory for SQLite database |
| `--log-level` | `-l` | `info` | Log level: debug, info, warn, error |

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ENRICH_WORKSPACE` | `./data` | Default workspace directory |
| `ENRICH_LOG_LEVEL` | `info` | Default log level |

## Supported Frameworks

### EU Regulatory (25)

| Provider | Description |
|----------|-------------|
| `cen_cenelec_cra` | CEN-CENELEC Cyber Resilience Act alignment |
| `cen_cenelec_cyber` | CEN-CENELEC cybersecurity standards |
| `cert_eu` | CERT-EU incident response and coordination |
| `dora` | Digital Operational Resilience Act (DORA) |
| `enisa_cra_mapping` | ENISA CRA cross-framework mapping |
| `enisa_threat` | ENISA threat landscape |
| `ens` | European National Scheme |
| `etsi_nis2` | ETSI NIS2 implementing standards |
| `etsi_standards` | ETSI cybersecurity standards |
| `eucc` | EUCC (EU Common Criteria) certification |
| `eu_ai_act` | EU Artificial Intelligence Act |
| `eu_common_criteria` | EU Common Criteria evaluation |
| `eu_cra` | EU Cyber Resilience Act |
| `eu_cybersecurity_act` | EU Cybersecurity Act |
| `eu_data_act` | EU Data Act |
| `eu_red` | EU Radio Equipment Directive |
| `gdpr` | General Data Protection Regulation |
| `nis2` | NIS2 Directive |
| `nis2_implementing_acts` | NIS2 implementing acts |
| `eba_ict_guidelines` | EBA ICT and Security Risk Management Guidelines (GL/2025/02) |
| `enisa_supply_chain` | ENISA ICT supply chain security |
| `enisa_healthcare` | ENISA healthcare cybersecurity |
| `eu_cer` | EU Cybersecurity Certification Framework |
| `eu_mdr_cyber` | EU MDR medical device cybersecurity |
| `swift_cscf` | SWIFT Customer Security Controls Framework (CSCF) |

### EU National Standards (15)

| Provider | Description |
|----------|-------------|
| `acn_psnc` | ACN/PSNC (Italy) |
| `anssi_ebios` | ANSSI EBIOS Risk Manager (France) |
| `b3s` | B3S sector-specific security standard (Germany) |
| `bait` | BAIT banking supervisory requirements for IT (Germany) |
| `bio` | BSI IT-Grundschutz (Germany) |
| `bsi_grundschutz` | BSI Grundschutz Compendium (Germany) |
| `kait_zait` | KAIT/ZAIT capital markets and payments IT requirements (Germany) |
| `ncsc_caf` | NCSC Cyber Assessment Framework (UK) |
| `secnumcloud` | SecNumCloud (France) |
| `tisax` | TISAX automotive information security assessment (Germany) |
| `toms` | Technical and Organizational Measures |
| `ropa` | Records of Processing Activities |
| `vait` | VAIT insurance supervisory requirements for IT (Germany) |
| `cyber_essentials` | NCSC Cyber Essentials (UK) |
| `nerc_cip` | NERC Critical Infrastructure Protection |

### International Frameworks (27)

| Provider | Description |
|----------|-------------|
| `cis_benchmarks` | CIS Benchmarks |
| `cis_controls` | CIS Critical Security Controls |
| `cobit` | COBIT governance framework |
| `cmmc` | CMMC (US DoD) |
| `csa_ccm` | CSA Cloud Controls Matrix |
| `disa_stigs` | DISA STIGs |
| `fedramp` | FedRAMP |
| `hipaa` | HIPAA Security Rule |
| `iso27001` | ISO/IEC 27001 |
| `nist_csf` | NIST Cybersecurity Framework |
| `nist_oscal` | NIST OSCAL |
| `nist_ssdf` | NIST SSDF (Secure Software Development Framework) |
| `pci_dss` | PCI DSS |
| `slsa` | SLSA supply-chain security levels (L1–L4) |
| `soc2` | SOC 2 |
| `scap_xccdf` | SCAP/XCCDF profiles |
| `iec_62443` | IEC 62443 industrial automation security |
| `iso27017` | ISO/IEC 27017 cloud security |
| `iso27701` | ISO/IEC 27701 privacy information management |
| `iso42001` | ISO/IEC 42001 AI management system |
| `iso27018` | ISO/IEC 27018 PII in public clouds |
| `iso_sae_21434` | ISO/SAE 21434 automotive cybersecurity |
| `nist_cscrm` | NIST SP 800-161 Rev.1 C-SCRM |
| `nist_sp800_53` | NIST SP 800-53 Rev.5 |
| `openssf_scorecard` | OpenSSF Scorecard supply-chain security |
| `owasp_asvs` | OWASP ASVS v4.0.3 |
| `psd2_rts` | PSD2 RTS Strong Customer Authentication |

### ISMS Feeds (7)

| Provider | Description |
|----------|-------------|
| `cspm` | Cloud Security Posture Management |
| `iam` | Identity and Access Management |
| `k8s_terraform` | Kubernetes and Terraform controls |
| `misp` | MISP threat intelligence |
| `mitre_attack` | MITRE ATT&CK |
| `veris_vcdb` | VERIS/Vcdb incident database |
| `mitre_attack_ics` | MITRE ATT&CK for Industrial Control Systems |

## Library Usage

The engine is usable as an importable Go library:

```go
package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/vincents-ai/enrichment-engine/pkg/enricher"
	"github.com/vincents-ai/enrichment-engine/pkg/grc"
	"github.com/vincents-ai/enrichment-engine/pkg/storage"
)

func main() {
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	store, err := storage.NewSQLiteBackend("./data/enrichment.db")
	if err != nil {
		panic(err)
	}
	defer store.Close(ctx)

	engine := enricher.New(enricher.Config{
		Store:  store,
		Logger: logger,
	})

	result, err := engine.Run(ctx)
	if err != nil {
		panic(err)
	}
	logger.Info("enrichment complete",
		"controls", result.ControlCount,
		"mappings", result.MappingCount,
		"duration", result.Duration,
	)

	components := []grc.SBOMComponent{
		{
			Name:    "log4j-core",
			Version: "2.14.0",
			Type:    "library",
			CPEs:    []string{"cpe:2.3:a:apache:log4j:2.14.0:*:*:*:*:*:*:*"},
		},
	}
	enriched, err := engine.EnrichSBOM(ctx, components)
	if err != nil {
		panic(err)
	}
	for _, ec := range enriched {
		logger.Info("component", "name", ec.Name, "risk", ec.ComplianceRisk)
	}
}
```

## Development

### Nix (recommended)

```sh
nix develop
```

Provides Go, gopls, golangci-lint, sqlite, jq, syft, grype, oscal-cli, and cyclonedx-cli.

### Manual

Requires Go 1.25+ and SQLite.

```sh
go build ./cmd/enrich
```

## Testing

Four-layer test strategy:

| Layer | Location | Command |
|-------|----------|---------|
| Unit tests | `pkg/**/*_test.go` | `go test ./pkg/...` |
| Integration (Layer 2) | `test/integration/` | `go test ./test/integration/...` |
| Property-based (rapid) | `pkg/**/rapid_test.go` | `go test ./pkg/... -run Rapid` |
| Behavioral (godog) | `test/behavioral/` | `GODOG=1 go test ./test/behavioral/...` |
| E2E scenario | `test/scenario/` | `go test -tags=integration ./test/scenario/...` |

Run all standard tests:

```sh
go test ./...
```

## PDF Parser

The `pkg/pdfparser/` package provides a Go library for extracting structured controls from ISO standard PDFs:

```go
import "github.com/vincents-ai/enrichment-engine/pkg/pdfparser"

p := pdfparser.New()
controls, err := p.ParseFile("path/to/standard.pdf")
```

Tested against ISO/IEC 27000:2018 (freely available). Run integration tests with:
```sh
go test ./pkg/pdfparser/... -tags=pdf_integration
```

## License

AGPL-3.0-only. See [LICENSE](LICENSE).
