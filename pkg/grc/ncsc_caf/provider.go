package ncsc_caf

// NCSC Cyber Assessment Framework is licensed under UK Open Government Licence v3.0.
// Original: https://www.ncsc.gov.uk/collection/caf
// Descriptions are paraphrased for AGPL compatibility.

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/shift/enrichment-engine/pkg/grc"
	"github.com/shift/enrichment-engine/pkg/storage"
)

const FrameworkID = "NCSC_CAF"

// Provider implements the NCSC Cyber Assessment Framework (CAF) v3.1.
type Provider struct {
	store  storage.Backend
	logger *slog.Logger
}

// New creates a new NCSC CAF provider.
func New(store storage.Backend, logger *slog.Logger) *Provider {
	return &Provider{
		store:  store,
		logger: logger,
	}
}

// Name returns the provider identifier.
func (p *Provider) Name() string {
	return "ncsc_caf"
}

// Run writes all NCSC CAF controls to storage.
func (p *Provider) Run(ctx context.Context) (int, error) {
	p.logger.Info("loading NCSC CAF v3.1 controls")

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

	p.logger.Info("wrote NCSC CAF controls to storage", "count", count)
	return count, nil
}

func staticControls() []grc.Control {
	ref := func(section string) []grc.Reference {
		return []grc.Reference{
			{
				Source:  "NCSC Cyber Assessment Framework v3.1",
				URL:     "https://www.ncsc.gov.uk/collection/caf",
				Section: section,
			},
		}
	}

	return []grc.Control{
		{
			Framework:   FrameworkID,
			ControlID:   "A1",
			Title:       "Governance",
			Family:      "Objective A: Managing Security Risk",
			Description: "Organisations must establish clear governance structures that define accountability for security decisions and set strategic direction for protecting critical systems. This includes board-level engagement, documented security policies, and regular review cycles to ensure controls remain aligned with the evolving threat landscape.",
			Level:       "standard",
			RelatedCWEs: []string{},
			Tags:        []string{"governance"},
			References:  ref("A1"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "A2",
			Title:       "Risk management",
			Family:      "Objective A: Managing Security Risk",
			Description: "A structured approach to identifying, evaluating, and prioritising threats to operational technology and information systems is essential for directing security investment where it matters most. Without this discipline, organisations risk allocating resources to the wrong problems while leaving critical exposure unaddressed.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-693"},
			Tags:        []string{"governance", "risk-management"},
			References:  ref("A2"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "A3",
			Title:       "Asset management",
			Family:      "Objective A: Managing Security Risk",
			Description: "You cannot protect what you do not know exists. Maintaining an accurate, up-to-date inventory of all hardware, software, data, and supporting services ensures that security controls are applied consistently and that nothing critical slips through the gaps.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-1059"},
			Tags:        []string{"asset-management"},
			References:  ref("A3"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "A4",
			Title:       "Supply chain",
			Family:      "Objective A: Managing Security Risk",
			Description: "Third-party vendors and service providers introduce risk that extends beyond an organisation's direct control. Rigorous supplier assessment, contractual security requirements, and ongoing assurance activities are needed to prevent a weak link in the supply chain from becoming an entry point into essential services.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-1357", "CWE-494"},
			Tags:        []string{"supply-chain", "integrity"},
			References:  ref("A4"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "B1",
			Title:       "Service protection policies and processes",
			Family:      "Objective B: Protecting Against Cyber Attack",
			Description: "Documented policies translate security intent into actionable rules that teams across the organisation can follow. Communicating and enforcing these standards consistently ensures that protective measures are applied uniformly rather than left to individual interpretation.",
			Level:       "standard",
			RelatedCWEs: []string{},
			Tags:        []string{"governance"},
			References:  ref("B1"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "B2",
			Title:       "Identity and access control",
			Family:      "Objective B: Protecting Against Cyber Attack",
			Description: "Limiting access to only those individuals who genuinely require it reduces the attack surface and limits the damage an adversary can inflict if credentials are compromised. Robust authentication mechanisms, least-privilege assignment, and regular access reviews form the foundation of this control.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-284", "CWE-287", "CWE-306"},
			Tags:        []string{"access-control", "authentication"},
			References:  ref("B2"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "B3",
			Title:       "Data security",
			Family:      "Objective B: Protecting Against Cyber Attack",
			Description: "Safeguarding sensitive information through encryption, access restrictions, and proper handling procedures prevents unauthorised disclosure, tampering, or destruction. For operators of essential services, a data breach can undermine public trust and cascade into operational disruption.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-311", "CWE-312", "CWE-200"},
			Tags:        []string{"crypto", "encryption", "information-disclosure"},
			References:  ref("B3"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "B4",
			Title:       "System security",
			Family:      "Objective B: Protecting Against Cyber Attack",
			Description: "Hardening infrastructure and keeping software patched closes the vulnerabilities that attackers routinely exploit. A disciplined vulnerability management programme, combined with secure configuration baselines, significantly raises the cost and complexity of a successful intrusion.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-693", "CWE-119"},
			Tags:        []string{"memory", "vulnerability-management"},
			References:  ref("B4"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "B5",
			Title:       "Resilient networks and systems",
			Family:      "Objective B: Protecting Against Cyber Attack",
			Description: "Designing systems to degrade gracefully rather than fail catastrophically ensures that essential services remain available even under sustained or sophisticated attack. Architectural redundancy, network segmentation, and capacity planning all contribute to maintaining operational continuity.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-400", "CWE-770"},
			Tags:        []string{"denial-of-service", "availability"},
			References:  ref("B5"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "B6",
			Title:       "Staff awareness and training",
			Family:      "Objective B: Protecting Against Cyber Attack",
			Description: "People are frequently the weakest link in any security posture, whether through phishing susceptibility, poor password hygiene, or unintentional policy violations. Regular, role-specific training transforms employees from a liability into an effective line of defence.",
			Level:       "standard",
			RelatedCWEs: []string{},
			Tags:        []string{"training"},
			References:  ref("B6"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "C1",
			Title:       "Security monitoring",
			Family:      "Objective C: Detecting Cyber Security Events",
			Description: "Continuous visibility into network traffic, system logs, and user activity enables early detection of anomalous behaviour that may indicate a compromise. Without effective monitoring, intrusions can persist undetected for weeks or months, allowing attackers to deepen their foothold.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-778"},
			Tags:        []string{"logging"},
			References:  ref("C1"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "C2",
			Title:       "Proactive security event discovery",
			Family:      "Objective C: Detecting Cyber Security Events",
			Description: "Relying solely on reactive alerts leaves gaps in detection coverage. Actively seeking indicators of compromise using threat intelligence feeds and vulnerability advisories helps organisations uncover threats before they escalate into full-blown incidents.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-693"},
			Tags:        []string{"vulnerability-management"},
			References:  ref("C2"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "D1",
			Title:       "Response and recovery planning",
			Family:      "Objective D: Minimising the Impact of Cyber Security Incidents",
			Description: "A well-rehearsed incident response plan reduces confusion and delays when a breach occurs, enabling faster containment and restoration of services. Regularly testing these plans through tabletop exercises and simulations ensures that teams can execute under pressure.",
			Level:       "standard",
			RelatedCWEs: []string{},
			Tags:        []string{"incident-response"},
			References:  ref("D1"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "D2",
			Title:       "Improvements",
			Family:      "Objective D: Minimising the Impact of Cyber Security Incidents",
			Description: "Every incident, and even near-misses, holds lessons that can strengthen defences if captured and acted upon. Embedding a feedback loop between incident analysis and control refinement drives continuous improvement and prevents the same weaknesses from being exploited repeatedly.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-693"},
			Tags:        []string{"sdlc"},
			References:  ref("D2"),
		},
	}
}
