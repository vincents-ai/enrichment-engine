package eu_mdr_cyber

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/shift/enrichment-engine/pkg/grc"
	"github.com/shift/enrichment-engine/pkg/storage"
)

const FrameworkID = "EU_MDR_CYBER"

type Provider struct {
	store  storage.Backend
	logger *slog.Logger
}

func New(store storage.Backend, logger *slog.Logger) *Provider {
	return &Provider{store: store, logger: logger}
}

func (p *Provider) Name() string {
	return "eu_mdr_cyber"
}

func (p *Provider) Run(ctx context.Context) (int, error) {
	p.logger.Info("loading EU MDR Cybersecurity controls")

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

	p.logger.Info("wrote EU MDR Cybersecurity controls to storage", "count", count)
	return count, nil
}

func staticControls() []grc.Control {
	ref := func(section string) []grc.Reference {
		return []grc.Reference{{Source: "EU MDR 2017/745", Section: section}}
	}

	return []grc.Control{
		{
			Framework:   FrameworkID,
			ControlID:   "MDR-CY-01",
			Title:       "Cybersecurity Risk Management Integration",
			Family:      "Risk Management",
			Description: "Integrate cybersecurity risk identification and mitigation into the overarching risk management process for medical devices throughout their entire lifecycle. This includes systematically identifying threats, assessing vulnerabilities in software and hardware components, and implementing proportionate controls to reduce residual risk to acceptable levels.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-119", "CWE-778"},
			Tags:        []string{"sdlc", "governance", "vulnerability-management"},
			References:  ref("Annex I, Ch. I, 1"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "MDR-CY-02",
			Title:       "Software of a Medical Device Validation",
			Family:      "Software Validation",
			Description: "Validate all software components that form part of a medical device to confirm they perform as intended under foreseeable conditions of use. The validation process must encompass unit testing, integration testing, system-level verification, and user acceptance testing with documented evidence that cybersecurity requirements have been satisfied.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-119", "CWE-494"},
			Tags:        []string{"sdlc", "vulnerability-management"},
			References:  ref("Annex I, Ch. I, 5"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "MDR-CY-03",
			Title:       "Clinical Evaluation with Cybersecurity Evidence",
			Family:      "Clinical Evaluation",
			Description: "Incorporate cybersecurity performance data into the clinical evaluation of medical devices to demonstrate that security controls do not adversely affect clinical safety or device efficacy. Clinical evidence must account for potential scenarios where compromised device security could lead to patient harm.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-287", "CWE-306"},
			Tags:        []string{"governance", "supply-chain"},
			References:  ref("Annex XIV"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "MDR-CY-04",
			Title:       "Post-Market Cybersecurity Surveillance",
			Family:      "Post-Market Surveillance",
			Description: "Establish a continuous post-market surveillance system that actively monitors for newly discovered vulnerabilities, exploits, and security incidents affecting deployed medical devices. The system must support timely identification of emerging threats and trigger corrective actions when patient safety is at risk.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-778", "CWE-494"},
			Tags:        []string{"vulnerability-management", "logging", "governance"},
			References:  ref("Art. 83-84"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "MDR-CY-05",
			Title:       "Unique Device Identification for Security Traceability",
			Family:      "UDI System",
			Description: "Leverage the Unique Device Identification system to support cybersecurity traceability by ensuring that each device and its software components can be uniquely identified throughout the supply chain. This enables precise targeting of security patches and facilitates rapid identification of affected devices during vulnerability disclosures.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-778"},
			Tags:        []string{"supply-chain", "governance"},
			References:  ref("Art. 24-27"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "MDR-CY-06",
			Title:       "Technical Documentation of Security Architecture",
			Family:      "Technical Documentation",
			Description: "Prepare comprehensive technical documentation that describes the cybersecurity architecture of the medical device, including data flow diagrams, trust boundaries, encryption mechanisms, authentication controls, and the rationale for security design decisions. Documentation must be maintained throughout the device lifecycle.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-287", "CWE-306"},
			Tags:        []string{"sdlc", "governance"},
			References:  ref("Annex II"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "MDR-CY-07",
			Title:       "Notified Body Cybersecurity Assessment",
			Family:      "Notified Bodies",
			Description: "Ensure that conformity assessment by notified bodies includes a thorough evaluation of the manufacturer's cybersecurity processes and the security properties of the medical device. Notified bodies must possess the competence to assess software security controls, vulnerability management practices, and incident response capabilities.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-119", "CWE-287"},
			Tags:        []string{"supply-chain", "governance"},
			References:  ref("Art. 35-48"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "MDR-CY-08",
			Title:       "Cybersecurity Incident Reporting and Field Safety",
			Family:      "Incident Reporting",
			Description: "Report cybersecurity incidents that could result in patient harm or device malfunction through the field safety corrective action process. Manufacturers must establish procedures for receiving, investigating, and escalating security vulnerability reports from external researchers, users, and threat intelligence sources.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-119", "CWE-287", "CWE-306"},
			Tags:        []string{"logging", "vulnerability-management", "governance"},
			References:  ref("Art. 87-89"),
		},
	}
}
