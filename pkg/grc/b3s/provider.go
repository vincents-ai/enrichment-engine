package b3s

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/shift/enrichment-engine/pkg/grc"
	"github.com/shift/enrichment-engine/pkg/storage"
)

const FrameworkID = "B3S"

// Provider implements B3S (Branchenspezifische Sicherheitsstandards) NIS2 OES critical infrastructure controls.
type Provider struct {
	store  storage.Backend
	logger *slog.Logger
}

// New creates a new B3S provider.
func New(store storage.Backend, logger *slog.Logger) *Provider {
	return &Provider{
		store:  store,
		logger: logger,
	}
}

// Name returns the provider identifier.
func (p *Provider) Name() string {
	return "b3s"
}

// Run writes all B3S controls to storage.
func (p *Provider) Run(ctx context.Context) (int, error) {
	p.logger.Info("loading B3S NIS2 OES critical infrastructure controls")

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

	p.logger.Info("wrote B3S controls to storage", "count", count)
	return count, nil
}

func staticControls() []grc.Control {
	ref := func(section string) []grc.Reference {
		return []grc.Reference{
			{
				Source:  "B3S NIS2 OES (BSI/UP KRITIS)",
				Section: section,
			},
		}
	}

	return []grc.Control{
		{
			Framework:   FrameworkID,
			ControlID:   "B3S.1.1",
			Title:       "Asset and network management",
			Family:      "Asset Management",
			Description: "An inventory of all assets and network components is maintained and kept current.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-1059"},
			Tags:        []string{"asset-management", "network"},
			References:  ref("B3S.1.1"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "B3S.1.2",
			Title:       "Software inventory and SBOM",
			Family:      "Asset Management",
			Description: "A software inventory including SBOM is maintained for all critical infrastructure components.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-1357"},
			Tags:        []string{"supply-chain", "asset-management"},
			References:  ref("B3S.1.2"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "B3S.2.1",
			Title:       "Access control and IAM",
			Family:      "Identity and Access Management",
			Description: "Access to critical infrastructure systems is controlled through identity and access management.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-284", "CWE-287"},
			Tags:        []string{"access-control", "authentication"},
			References:  ref("B3S.2.1"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "B3S.2.2",
			Title:       "Privilege management",
			Family:      "Identity and Access Management",
			Description: "Privileged access is managed and monitored with least-privilege enforcement.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-250", "CWE-269"},
			Tags:        []string{"privilege", "authz"},
			References:  ref("B3S.2.2"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "B3S.3.1",
			Title:       "Patch management",
			Family:      "Vulnerability Management",
			Description: "Security patches are identified, tested, and applied to critical infrastructure systems in a timely manner.",
			Level:       "standard",
			RelatedCWEs: []string{},
			Tags:        []string{"vulnerability-management"},
			References:  ref("B3S.3.1"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "B3S.3.2",
			Title:       "Vulnerability scanning",
			Family:      "Vulnerability Management",
			Description: "Regular vulnerability scanning is performed on critical infrastructure systems.",
			Level:       "standard",
			RelatedCWEs: []string{},
			Tags:        []string{"vulnerability-management"},
			References:  ref("B3S.3.2"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "B3S.4.1",
			Title:       "Cryptographic protection",
			Family:      "Cryptography",
			Description: "Cryptographic protection is applied to sensitive data at rest and in transit.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-327", "CWE-326", "CWE-311"},
			Tags:        []string{"crypto", "encryption"},
			References:  ref("B3S.4.1"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "B3S.4.2",
			Title:       "Secure communication",
			Family:      "Cryptography",
			Description: "Communications between critical infrastructure components use secure protocols.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-319"},
			Tags:        []string{"crypto", "network"},
			References:  ref("B3S.4.2"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "B3S.5.1",
			Title:       "Incident detection",
			Family:      "Security Monitoring and Incident Management",
			Description: "Security events are logged and monitored to detect incidents in critical infrastructure.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-778"},
			Tags:        []string{"logging", "incident-response"},
			References:  ref("B3S.5.1"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "B3S.5.2",
			Title:       "Incident response and recovery",
			Family:      "Security Monitoring and Incident Management",
			Description: "Incident response and recovery plans are established and tested for critical infrastructure.",
			Level:       "standard",
			RelatedCWEs: []string{},
			Tags:        []string{"incident-response"},
			References:  ref("B3S.5.2"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "B3S.6.1",
			Title:       "Supply chain security",
			Family:      "Supply Chain Management",
			Description: "Security requirements are imposed throughout the supply chain including software component integrity.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-1357", "CWE-494"},
			Tags:        []string{"supply-chain", "integrity"},
			References:  ref("B3S.6.1"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "B3S.6.2",
			Title:       "Third-party component validation",
			Family:      "Supply Chain Management",
			Description: "Third-party software components are validated for security before integration.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-1357"},
			Tags:        []string{"supply-chain"},
			References:  ref("B3S.6.2"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "B3S.7.1",
			Title:       "Secure software development",
			Family:      "Software Security",
			Description: "Secure software development practices are applied to all software used in critical infrastructure.",
			Level:       "standard",
			RelatedCWEs: []string{},
			Tags:        []string{"sdlc"},
			References:  ref("B3S.7.1"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "B3S.7.2",
			Title:       "Security testing",
			Family:      "Software Security",
			Description: "Security testing is performed on software used in critical infrastructure.",
			Level:       "standard",
			RelatedCWEs: []string{},
			Tags:        []string{"testing"},
			References:  ref("B3S.7.2"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "B3S.8.1",
			Title:       "Business continuity for critical infrastructure",
			Family:      "Resilience",
			Description: "Business continuity controls ensure availability of critical infrastructure services including denial-of-service protection.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-400"},
			Tags:        []string{"availability", "denial-of-service"},
			References:  ref("B3S.8.1"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "B3S.9.1",
			Title:       "Reporting obligations to BSI",
			Family:      "Governance and Compliance",
			Description: "Significant security incidents are reported to the BSI in accordance with BSIG §8b requirements.",
			Level:       "standard",
			RelatedCWEs: []string{},
			Tags:        []string{"governance", "incident-response"},
			References:  ref("B3S.9.1"),
		},
	}
}
