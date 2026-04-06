package ncsc_caf

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
			Description: "The organisation has appropriate management policies and processes in place to govern its approach to the security of network and information systems.",
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
			Description: "The organisation takes appropriate steps to identify, assess and understand security risks to the network and information systems supporting the delivery of essential services.",
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
			Description: "Everything required to deliver, maintain or support network and information systems is determined and understood.",
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
			Description: "The organisation understands and manages security risks to networks and information systems supporting essential services that arise as a result of dependencies on external suppliers.",
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
			Description: "The organisation defines, implements, communicates and enforces appropriate policies and processes that direct its overall approach to securing systems and data that support delivery of essential services.",
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
			Description: "The organisation understands, documents and manages access to networks and information systems supporting essential services.",
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
			Description: "Data stored or processed by the organisation's essential service is protected from unautho rised access, modification or deletion.",
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
			Description: "The network and information systems are protected from cyber attack using appropriate technical controls and vulnerability management.",
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
			Description: "The organisation builds resilience against cyber attack and system failure into the design, implementation, operation and management of systems that support essential services.",
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
			Description: "Staff have appropriate awareness and training to support the security of network and information systems.",
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
			Description: "The organisation monitors the security of the networks and information systems that support the delivery of essential services.",
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
			Description: "The organisation uses threat intelligence and vulnerability information to proactively discover security events.",
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
			Description: "The organisation has and tests effective plans for responding to and recovering from cyber security incidents.",
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
			Description: "Lessons learned from cyber security incidents and near misses are used to drive improvements in security.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-693"},
			Tags:        []string{"sdlc"},
			References:  ref("D2"),
		},
	}
}
