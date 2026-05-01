package bait

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/vincents-ai/enrichment-engine/pkg/grc"
	"github.com/vincents-ai/enrichment-engine/pkg/storage"
)

const FrameworkID = "BAIT"

// Provider implements BAIT (Bankaufsichtliche Anforderungen an die IT) BaFin banking IT supervisory controls.
type Provider struct {
	store  storage.Backend
	logger *slog.Logger
}

// New creates a new BAIT provider.
func New(store storage.Backend, logger *slog.Logger) *Provider {
	return &Provider{
		store:  store,
		logger: logger,
	}
}

// Name returns the provider identifier.
func (p *Provider) Name() string {
	return "bait"
}

// Run writes all BAIT controls to storage.
func (p *Provider) Run(ctx context.Context) (int, error) {
	p.logger.Info("loading BAIT BaFin banking IT supervisory controls")

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

	p.logger.Info("wrote BAIT controls to storage", "count", count)
	return count, nil
}

func staticControls() []grc.Control {
	ref := func(section string) []grc.Reference {
		return []grc.Reference{
			{
				Source:  "BAIT (BaFin circular 10/2017, updated 2021)",
				Section: section,
			},
		}
	}

	return []grc.Control{
		{
			Framework:   FrameworkID,
			ControlID:   "BAIT.1.1",
			Title:       "IT strategy and governance",
			Family:      "IT Strategy",
			Description: "An IT strategy is defined, documented, and aligned with the overall business strategy of the institution.",
			Level:       "standard",
			RelatedCWEs: []string{},
			Tags:        []string{"governance", "banking"},
			References:  ref("BAIT.1.1"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "BAIT.2.1",
			Title:       "Information risk management",
			Family:      "Information Risk Management",
			Description: "Information risks are identified, assessed, and managed throughout the institution.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-693"},
			Tags:        []string{"risk-management", "banking"},
			References:  ref("BAIT.2.1"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "BAIT.3.1",
			Title:       "Information security management",
			Family:      "Information Security Management",
			Description: "An information security management system is established with appropriate policies and controls.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-693"},
			Tags:        []string{"governance", "banking"},
			References:  ref("BAIT.3.1"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "BAIT.4.1",
			Title:       "User access rights",
			Family:      "User Access Rights",
			Description: "User access rights are granted on a need-to-know basis and reviewed regularly.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-284", "CWE-269"},
			Tags:        []string{"access-control", "authz", "banking"},
			References:  ref("BAIT.4.1"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "BAIT.4.2",
			Title:       "Privileged access management",
			Family:      "User Access Rights",
			Description: "Privileged access rights are managed, monitored, and restricted to authorised personnel.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-250", "CWE-269"},
			Tags:        []string{"privilege", "banking"},
			References:  ref("BAIT.4.2"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "BAIT.5.1",
			Title:       "IT project and change management",
			Family:      "IT Projects and Application Development",
			Description: "IT projects and changes are managed securely with appropriate review and approval processes.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-693"},
			Tags:        []string{"sdlc", "banking"},
			References:  ref("BAIT.5.1"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "BAIT.6.1",
			Title:       "IT operations",
			Family:      "IT Operations",
			Description: "IT operations are managed securely with availability controls to prevent disruption to banking services.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-400", "CWE-693"},
			Tags:        []string{"availability", "banking"},
			References:  ref("BAIT.6.1"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "BAIT.7.1",
			Title:       "Application development security",
			Family:      "IT Projects and Application Development",
			Description: "Security is integrated into application development processes including protection against injection and memory safety issues.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-693", "CWE-119", "CWE-89"},
			Tags:        []string{"sdlc", "injection", "banking"},
			References:  ref("BAIT.7.1"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "BAIT.7.2",
			Title:       "Security in software procurement",
			Family:      "IT Projects and Application Development",
			Description: "Security requirements are imposed on procured software and third-party components.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-1357"},
			Tags:        []string{"supply-chain", "banking"},
			References:  ref("BAIT.7.2"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "BAIT.8.1",
			Title:       "IT outsourcing controls",
			Family:      "IT Outsourcing",
			Description: "IT outsourcing arrangements are subject to appropriate security controls and contractual requirements.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-1357"},
			Tags:        []string{"supply-chain", "banking"},
			References:  ref("BAIT.8.1"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "BAIT.8.2",
			Title:       "Third-party monitoring",
			Family:      "IT Outsourcing",
			Description: "Third-party service providers are monitored for security compliance on an ongoing basis.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-1357"},
			Tags:        []string{"supply-chain"},
			References:  ref("BAIT.8.2"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "BAIT.9.1",
			Title:       "Critical infrastructure protection (KRITIS)",
			Family:      "Critical Infrastructure",
			Description: "Critical banking infrastructure is protected against availability threats including denial-of-service attacks.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-400", "CWE-693"},
			Tags:        []string{"availability", "denial-of-service", "banking"},
			References:  ref("BAIT.9.1"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "BAIT.10.1",
			Title:       "Logging and monitoring",
			Family:      "IT Operations",
			Description: "Security-relevant events are logged and monitored to detect and respond to security incidents.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-778"},
			Tags:        []string{"logging", "banking"},
			References:  ref("BAIT.10.1"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "BAIT.11.1",
			Title:       "IT incident management",
			Family:      "IT Operations",
			Description: "IT security incidents are identified, escalated, managed, and reported in accordance with regulatory requirements.",
			Level:       "standard",
			RelatedCWEs: []string{},
			Tags:        []string{"incident-response", "banking"},
			References:  ref("BAIT.11.1"),
		},
	}
}
