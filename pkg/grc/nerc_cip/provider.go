package nerc_cip

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/vincents-ai/enrichment-engine/pkg/grc"
	"github.com/vincents-ai/enrichment-engine/pkg/storage"
)

const FrameworkID = "NERC_CIP"

type Provider struct {
	store  storage.Backend
	logger *slog.Logger
}

func New(store storage.Backend, logger *slog.Logger) *Provider {
	return &Provider{store: store, logger: logger}
}

func (p *Provider) Name() string {
	return "nerc_cip"
}

func (p *Provider) Run(ctx context.Context) (int, error) {
	p.logger.Info("loading NERC CIP controls")

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

	p.logger.Info("wrote NERC CIP controls to storage", "count", count)
	return count, nil
}

func staticControls() []grc.Control {
	ref := func(section string) []grc.Reference {
		return []grc.Reference{{Source: "NERC CIP Standards", Section: section}}
	}

	return []grc.Control{
		{
			Framework:   FrameworkID,
			ControlID:   "CIP-001",
			Title:       "Critical Asset Identification and BES Cyber System Categorisation",
			Family:      "Asset Identification",
			Description: "Entities must identify all assets associated with the bulk electric system and categorise associated cyber systems based on their potential impact on reliable grid operation. Categorisation determines the applicable security requirements, with higher-impact systems subject to more stringent controls covering access, monitoring, and change management.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-287", "CWE-693"},
			Tags:        []string{"governance", "supply-chain"},
			References:  ref("CIP-001"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "CIP-002",
			Title:       "Personnel and Training Requirements",
			Family:      "Access Control",
			Description: "All individuals with authorised access to critical cyber assets must undergo background checks, receive role-specific cybersecurity training, and have their access privileges reviewed on a regular cycle. Training must cover both technical security procedures and the entity's specific policies for protecting bulk electric system assets.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-287", "CWE-306"},
			Tags:        []string{"access-control", "governance"},
			References:  ref("CIP-002"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "CIP-003",
			Title:       "Security Management Controls",
			Family:      "Configuration Management",
			Description: "A documented cyber security policy must be established and maintained, covering the protection of all critical cyber assets with change management procedures that require authorisation before any modifications are applied. The policy should address both technical configurations and procedural safeguards for operational technology environments.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-693", "CWE-770"},
			Tags:        []string{"governance", "integrity", "vulnerability-management"},
			References:  ref("CIP-003"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "CIP-004",
			Title:       "Electronic Security Perimeter and Access Control",
			Family:      "Access Control",
			Description: "Electronic security perimeters must be defined around all critical cyber assets, with access strictly controlled through encrypted communication channels and strong authentication mechanisms. All access events should be logged and monitored for anomalous activity, and remote access must be limited to authorised personnel with a documented business need.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-287", "CWE-306"},
			Tags:        []string{"access-control", "network"},
			References:  ref("CIP-004"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "CIP-005",
			Title:       "Cyber Security Incident Response and Reporting",
			Family:      "Incident Response",
			Description: "Entities must develop and maintain incident response plans specifically for cyber events affecting critical cyber assets, with defined escalation procedures and mandatory reporting timelines to the Electricity Subsector Coordinating Council and relevant regulatory bodies. Plans must be tested through regular exercises that simulate realistic attack scenarios.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-770", "CWE-693"},
			Tags:        []string{"governance", "vulnerability-management"},
			References:  ref("CIP-005"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "CIP-006",
			Title:       "Recovery Planning for Critical Cyber Assets",
			Family:      "Recovery Planning",
			Description: "Recovery plans must ensure that critical cyber assets can be restored to operational status within defined timeframes following a cyber incident. Plans should include verified backup procedures, alternative system configurations, and documented manual operational procedures to maintain grid reliability while systems are being recovered.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-770"},
			Tags:        []string{"governance", "integrity"},
			References:  ref("CIP-006"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "CIP-007",
			Title:       "Vulnerability and Patch Management",
			Family:      "Vulnerability Assessment",
			Description: "A structured vulnerability management programme must be in place to identify, assess, and remediate security weaknesses in critical cyber assets, with risk-based patching timelines that balance the urgency of fixes against the need for operational stability. Where patching is not immediately feasible, compensating controls must be documented and implemented.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-693", "CWE-770"},
			Tags:        []string{"vulnerability-management", "supply-chain"},
			References:  ref("CIP-007"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "CIP-008",
			Title:       "Supply Chain and Third-Party Risk Management",
			Family:      "Supply Chain",
			Description: "Entities must assess and manage cybersecurity risks associated with vendors, contractors, and service providers who have access to or influence over critical cyber assets. This includes verifying vendor security practices, maintaining a list of all third-party software and hardware dependencies, and ensuring contractual obligations for timely vulnerability notification.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-1357", "CWE-287"},
			Tags:        []string{"supply-chain", "governance", "integrity"},
			References:  ref("CIP-008"),
		},
	}
}
