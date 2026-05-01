package iso_sae_21434

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/vincents-ai/enrichment-engine/pkg/grc"
	"github.com/vincents-ai/enrichment-engine/pkg/storage"
)

const FrameworkID = "ISO_SAE_21434"

type Provider struct {
	store  storage.Backend
	logger *slog.Logger
}

func New(store storage.Backend, logger *slog.Logger) *Provider {
	return &Provider{store: store, logger: logger}
}

func (p *Provider) Name() string {
	return "iso_sae_21434"
}

func (p *Provider) Run(ctx context.Context) (int, error) {
	p.logger.Info("loading ISO/SAE 21434 Automotive Cybersecurity controls")

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

	p.logger.Info("wrote ISO/SAE 21434 controls to storage", "count", count)
	return count, nil
}

func staticControls() []grc.Control {
	ref := func(section string) []grc.Reference {
		return []grc.Reference{{Source: "ISO/SAE 21434:2021", Section: section}}
	}

	return []grc.Control{
		{
			Framework:   FrameworkID,
			ControlID:   "IS21434-01",
			Title:       "Cybersecurity Governance and Organisational Management",
			Family:      "Organizational Cybersecurity Management",
			Description: "Establish an organisational structure with clearly defined roles, responsibilities, and accountability for cybersecurity across the vehicle engineering lifecycle. The structure must include a cybersecurity management system that is integrated with existing quality and functional safety management processes to ensure consistent governance.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-1357"},
			Tags:        []string{"governance", "supply-chain"},
			References:  ref("Clause 5"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "IS21434-02",
			Title:       "Cybersecurity Risk Assessment and Treatment",
			Family:      "Risk Assessment",
			Description: "Perform structured risk assessments at each phase of the vehicle lifecycle to identify, analyse, and evaluate cybersecurity threats and vulnerabilities. Risk treatment decisions must be documented with clear justification for accepted, mitigated, transferred, or avoided risks, and residual risk levels must be communicated to relevant stakeholders.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-119", "CWE-494"},
			Tags:        []string{"vulnerability-management", "governance"},
			References:  ref("Clause 6"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "IS21434-03",
			Title:       "Cybersecurity Requirements Specification",
			Family:      "Cybersecurity Requirements",
			Description: "Derive and specify cybersecurity requirements that address identified risks and are traceable to the cybersecurity goals defined during concept phase. Requirements must cover functional, non-functional, and interface security aspects and must be allocated to specific hardware and software components within the vehicle architecture.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-287", "CWE-829"},
			Tags:        []string{"sdlc", "integrity"},
			References:  ref("Clause 9"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "IS21434-04",
			Title:       "Cybersecurity Design and Architecture Verification",
			Family:      "Design Verification",
			Description: "Verify that the cybersecurity design and architecture of the vehicle system satisfy the specified security requirements through structured reviews, threat modelling, and analysis techniques. Verification activities must confirm that security controls are correctly allocated, that trust boundaries are properly defined, and that attack surfaces are minimised.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-119", "CWE-287"},
			Tags:        []string{"sdlc", "integrity"},
			References:  ref("Clause 10"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "IS21434-05",
			Title:       "Cybersecurity Validation Testing",
			Family:      "Validation",
			Description: "Validate that the implemented vehicle system meets its cybersecurity goals and effectively mitigates the identified risk scenarios through comprehensive testing activities. Validation must include functional testing of security mechanisms, vulnerability scanning, penetration testing, and fuzz testing of external interfaces.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-119", "CWE-494"},
			Tags:        []string{"vulnerability-management", "sdlc"},
			References:  ref("Clause 11"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "IS21434-06",
			Title:       "Cybersecurity Monitoring and Incident Response",
			Family:      "Monitoring & Response",
			Description: "Implement monitoring capabilities to detect cybersecurity events affecting vehicles in the field and establish incident response procedures to analyse, contain, and remediate security incidents. Post-incident analysis must feed back into the risk assessment process to update threat models and improve future resilience.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-778"},
			Tags:        []string{"vulnerability-management", "governance"},
			References:  ref("Clause 12"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "IS21434-07",
			Title:       "Post-Development Cybersecurity Update Management",
			Family:      "Post-Development",
			Description: "Manage cybersecurity updates for vehicles and components after the start of production, including vulnerability assessment of fielded systems, development and distribution of security patches, and decommissioning of legacy systems. Update management must ensure that vehicles remain protected against newly discovered threats throughout their operational lifetime.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-494", "CWE-829"},
			Tags:        []string{"vulnerability-management", "supply-chain", "integrity"},
			References:  ref("Clause 13"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "IS21434-08",
			Title:       "Supply Chain Cybersecurity Risk Management",
			Family:      "Supply Chain",
			Description: "Assess and manage cybersecurity risks introduced through suppliers, tier-two vendors, and third-party components integrated into the vehicle platform. Supply chain risk management must include contractual security requirements, supplier audits, and processes for handling vulnerability disclosures affecting third-party software or hardware.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-1357", "CWE-494", "CWE-829"},
			Tags:        []string{"supply-chain", "governance"},
			References:  ref("Clause 7"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "IS21434-09",
			Title:       "Threat Analysis and Risk Assessment Methodology",
			Family:      "Threat Analysis",
			Description: "Apply a systematic threat analysis and risk assessment methodology such as STRIDE or attack tree analysis to identify potential attack vectors, threat actors, and impact scenarios for vehicle systems. The methodology must be applied iteratively throughout the engineering lifecycle and must consider both intentional and unintentional threat sources.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-119", "CWE-287", "CWE-1357"},
			Tags:        []string{"sdlc", "vulnerability-management", "integrity"},
			References:  ref("Clause 8"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "IS21434-10",
			Title:       "Cybersecurity Incident Response in Production",
			Family:      "Incident Response",
			Description: "Define and operationalise an incident response capability that covers detection, analysis, containment, eradication, and recovery from cybersecurity incidents affecting production vehicles. The capability must include coordination with external parties such as CERTs, regulators, and suppliers, and must support evidence preservation for forensic analysis.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-287", "CWE-829"},
			Tags:        []string{"governance", "vulnerability-management"},
			References:  ref("Clause 15"),
		},
	}
}
