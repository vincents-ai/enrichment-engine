package enisa_supply_chain

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/vincents-ai/enrichment-engine/pkg/grc"
	"github.com/vincents-ai/enrichment-engine/pkg/storage"
)

const FrameworkID = "ENISA_SUPPLY_CHAIN"

type Provider struct {
	store  storage.Backend
	logger *slog.Logger
}

func New(store storage.Backend, logger *slog.Logger) *Provider {
	return &Provider{store: store, logger: logger}
}

func (p *Provider) Name() string {
	return "enisa_supply_chain"
}

func (p *Provider) Run(ctx context.Context) (int, error) {
	p.logger.Info("loading ENISA Supply Chain Security controls")

	controls := staticControls()
	count := 0
	for _, ctrl := range controls {
		id := fmt.Sprintf("%s/%s", FrameworkID, ctrl.ControlID)
		if err := p.store.WriteControl(ctx, id, ctrl); err != nil {
			p.logger.Warn("failed to write control", "id", id, "error", err)
			continue
		}
		count++
	}

	p.logger.Info("wrote ENISA Supply Chain controls to storage", "count", count)
	return count, nil
}

func staticControls() []grc.Control {
	ref := func(section string) []grc.Reference {
		return []grc.Reference{{Source: "ENISA ICT Supply Chain Security", Section: section}}
	}

	return []grc.Control{
		{
			Framework:   FrameworkID,
			ControlID:   "SCS-1",
			Title:       "Supplier Risk Assessment",
			Family:      "Supplier Assessment",
			Description: "Organisations should systematically evaluate the cybersecurity posture of their technology vendors before onboarding and on an ongoing basis. This involves reviewing the vendor's security certifications, incident history, and adherence to recognised security standards to ensure they meet acceptable risk thresholds.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-1357"},
			Tags:        []string{"supply-chain", "governance"},
			References:  ref("SCS-1"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "SCS-2",
			Title:       "Software Integrity Verification",
			Family:      "Software Integrity",
			Description: "All software components received from external sources must be verified for authenticity and integrity before deployment. Organisations should employ cryptographic signatures, checksums, and provenance checks to confirm that binaries and packages have not been tampered with during distribution.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-494", "CWE-829"},
			Tags:        []string{"supply-chain", "integrity"},
			References:  ref("SCS-2"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "SCS-3",
			Title:       "Third-Party Risk Governance",
			Family:      "Third-Party Risk",
			Description: "A formal governance structure must be established to oversee risks introduced by third-party service providers and subcontractors throughout the product lifecycle. This includes maintaining an inventory of all external dependencies, defining acceptable use policies, and conducting periodic reviews of third-party access and data handling practices.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-1357"},
			Tags:        []string{"supply-chain", "governance"},
			References:  ref("SCS-3"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "SCS-4",
			Title:       "Software Bill of Materials Management",
			Family:      "SBOM",
			Description: "Organisations are expected to require and maintain machine-readable software bills of materials for all procured and internally developed software. SBOMs enable rapid identification of vulnerable components when new security flaws are disclosed and support end-to-end transparency of the software supply chain.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-823", "CWE-1357"},
			Tags:        []string{"supply-chain", "integrity", "vulnerability-management"},
			References:  ref("SCS-4"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "SCS-5",
			Title:       "Vulnerability Coordination",
			Family:      "Vulnerability Management",
			Description: "A coordinated vulnerability disclosure and response process must be in place for all software components within the supply chain. This includes subscribing to vendor security advisories, participating in information-sharing communities, and establishing timelines for patching or mitigating newly discovered flaws in third-party components.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-1357", "CWE-829"},
			Tags:        []string{"supply-chain", "vulnerability-management"},
			References:  ref("SCS-5"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "SCS-6",
			Title:       "Supply Chain Incident Response",
			Family:      "Incident Response",
			Description: "Incident response plans should explicitly address compromise scenarios originating from the supply chain, including malicious updates, compromised build environments, and rogue component substitutions. Teams must be able to rapidly isolate affected systems, identify the entry vector through the supply chain, and coordinate with affected vendors.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-494", "CWE-1357"},
			Tags:        []string{"supply-chain", "governance"},
			References:  ref("SCS-6"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "SCS-7",
			Title:       "Contractual Security Obligations",
			Family:      "Contractual Controls",
			Description: "Procurement contracts must include binding cybersecurity clauses that specify minimum security baselines, notification timelines for breaches, audit rights, and liability for supply chain security failures. These contractual provisions should be enforceable and regularly reviewed to keep pace with evolving threat landscapes.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-1357"},
			Tags:        []string{"supply-chain", "governance"},
			References:  ref("SCS-7"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "SCS-8",
			Title:       "Continuous Supply Chain Monitoring",
			Family:      "Monitoring",
			Description: "Organisations should deploy continuous monitoring capabilities to detect anomalous behaviour indicative of supply chain compromise, such as unexpected code changes, unauthorised repository access, or deviations from established build pipelines. Monitoring data should feed into the overall security operations centre for correlation with other threat intelligence.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-829", "CWE-823"},
			Tags:        []string{"supply-chain", "integrity"},
			References:  ref("SCS-8"),
		},
	}
}
