package vait

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/shift/enrichment-engine/pkg/grc"
	"github.com/shift/enrichment-engine/pkg/storage"
)

const FrameworkID = "VAIT"

// Provider implements VAIT (Versicherungsaufsichtliche Anforderungen an die IT) BaFin insurance IT supervisory controls.
type Provider struct {
	store  storage.Backend
	logger *slog.Logger
}

// New creates a new VAIT provider.
func New(store storage.Backend, logger *slog.Logger) *Provider {
	return &Provider{
		store:  store,
		logger: logger,
	}
}

// Name returns the provider identifier.
func (p *Provider) Name() string {
	return "vait"
}

// Run writes all VAIT controls to storage.
func (p *Provider) Run(ctx context.Context) (int, error) {
	p.logger.Info("loading VAIT BaFin insurance IT supervisory controls")

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

	p.logger.Info("wrote VAIT controls to storage", "count", count)
	return count, nil
}

func staticControls() []grc.Control {
	ref := func(section string) []grc.Reference {
		return []grc.Reference{
			{
				Source:  "VAIT (BaFin insurance sector IT requirements)",
				Section: section,
			},
		}
	}

	return []grc.Control{
		{
			Framework:   FrameworkID,
			ControlID:   "VAIT.1.1",
			Title:       "IT strategy (insurance)",
			Family:      "IT Strategy",
			Description: "An IT strategy aligned with business objectives is established and maintained for the insurance institution.",
			Level:       "standard",
			RelatedCWEs: []string{},
			Tags:        []string{"governance", "insurance"},
			References:  ref("VAIT.1.1"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "VAIT.2.1",
			Title:       "Information risk management",
			Family:      "Information Risk Management",
			Description: "Information risks are identified, assessed, and managed in the context of insurance IT systems.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-693"},
			Tags:        []string{"risk-management", "insurance"},
			References:  ref("VAIT.2.1"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "VAIT.3.1",
			Title:       "Information security management",
			Family:      "Information Security Management",
			Description: "An information security management framework is established for the insurance institution.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-693"},
			Tags:        []string{"governance", "insurance"},
			References:  ref("VAIT.3.1"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "VAIT.4.1",
			Title:       "User access rights",
			Family:      "User Access Rights",
			Description: "User access rights to insurance IT systems are granted on a need-to-know basis and reviewed periodically.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-284", "CWE-269"},
			Tags:        []string{"access-control", "authz", "insurance"},
			References:  ref("VAIT.4.1"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "VAIT.4.2",
			Title:       "Privileged access",
			Family:      "User Access Rights",
			Description: "Privileged access to insurance IT systems is restricted and monitored.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-250"},
			Tags:        []string{"privilege", "insurance"},
			References:  ref("VAIT.4.2"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "VAIT.5.1",
			Title:       "IT operations",
			Family:      "IT Operations",
			Description: "IT operations ensure the availability and integrity of insurance IT systems.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-400"},
			Tags:        []string{"availability", "insurance"},
			References:  ref("VAIT.5.1"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "VAIT.6.1",
			Title:       "Application security (insurance core systems)",
			Family:      "Application Development",
			Description: "Security is integrated into the development and maintenance of insurance core systems with protection against injection vulnerabilities.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-693", "CWE-89"},
			Tags:        []string{"sdlc", "injection", "insurance"},
			References:  ref("VAIT.6.1"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "VAIT.6.2",
			Title:       "Secure software procurement",
			Family:      "Application Development",
			Description: "Security requirements are imposed on software procurement for insurance IT systems.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-1357"},
			Tags:        []string{"supply-chain", "insurance"},
			References:  ref("VAIT.6.2"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "VAIT.7.1",
			Title:       "IT outsourcing",
			Family:      "IT Outsourcing",
			Description: "IT outsourcing arrangements in the insurance sector are subject to security controls and supervisory oversight.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-1357"},
			Tags:        []string{"supply-chain", "insurance"},
			References:  ref("VAIT.7.1"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "VAIT.8.1",
			Title:       "Logging and monitoring",
			Family:      "IT Operations",
			Description: "Security events in insurance IT systems are logged and monitored.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-778"},
			Tags:        []string{"logging", "insurance"},
			References:  ref("VAIT.8.1"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "VAIT.9.1",
			Title:       "Incident management",
			Family:      "IT Operations",
			Description: "IT security incidents are managed and reported to BaFin in accordance with insurance supervisory requirements.",
			Level:       "standard",
			RelatedCWEs: []string{},
			Tags:        []string{"incident-response", "insurance"},
			References:  ref("VAIT.9.1"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "VAIT.10.1",
			Title:       "Data protection for policyholder data",
			Family:      "Data Security",
			Description: "Policyholder and sensitive insurance data is protected using encryption and access controls.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-311", "CWE-200"},
			Tags:        []string{"encryption", "information-disclosure", "insurance"},
			References:  ref("VAIT.10.1"),
		},
	}
}
