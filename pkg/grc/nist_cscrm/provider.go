package nist_cscrm

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/vincents-ai/enrichment-engine/pkg/grc"
	"github.com/vincents-ai/enrichment-engine/pkg/storage"
)

const FrameworkID = "NIST_CSCRM_800_161"

// Provider implements NIST SP 800-161 Rev.1 Cyber Supply Chain Risk Management (C-SCRM).
// ADR-015: build-time embed, no runtime fetch. Both NIST URLs returned 404 so
// controls are hardcoded via staticControls() following the nist_ssdf pattern.
type Provider struct {
	store  storage.Backend
	logger *slog.Logger
}

// New creates a new NIST C-SCRM provider.
func New(store storage.Backend, logger *slog.Logger) *Provider {
	return &Provider{
		store:  store,
		logger: logger,
	}
}

// Name returns the provider identifier.
func (p *Provider) Name() string {
	return "nist_cscrm"
}

// Run writes all NIST SP 800-161 Rev.1 C-SCRM controls to storage.
func (p *Provider) Run(ctx context.Context) (int, error) {
	p.logger.Info("loading NIST SP 800-161 Rev.1 C-SCRM controls")

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

	p.logger.Info("wrote NIST C-SCRM controls to storage", "count", count)
	return count, nil
}

func staticControls() []grc.Control {
	ref := func(section string) []grc.Reference {
		return []grc.Reference{{Source: "NIST SP 800-161 Rev.1", Section: section}}
	}

	return []grc.Control{
		// SR family — Supply Chain Risk Management
		{
			Framework:   FrameworkID,
			ControlID:   "SR-1",
			Title:       "Supply Chain Risk Management Policy and Procedures",
			Family:      "Supply Chain Risk Management",
			Description: "Develop, document, disseminate, review, and update a supply chain risk management policy and procedures.",
			Level:       "standard",
			RelatedCWEs: []string{},
			Tags:        []string{"supply-chain", "governance"},
			References:  ref("SR-1"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "SR-2",
			Title:       "Supply Chain Risk Management Plan",
			Family:      "Supply Chain Risk Management",
			Description: "Develop a plan for managing supply chain risks associated with the research, development, design, manufacturing, acquisition, delivery, integration, operations, maintenance, and disposal of systems, system components, or system services.",
			Level:       "standard",
			RelatedCWEs: []string{},
			Tags:        []string{"supply-chain", "governance"},
			References:  ref("SR-2"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "SR-3",
			Title:       "Supply Chain Controls and Processes",
			Family:      "Supply Chain Risk Management",
			Description: "Establish a process or processes to identify and address weaknesses or deficiencies in the supply chain elements and processes of the system and its components.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-494", "CWE-829"},
			Tags:        []string{"supply-chain", "integrity"},
			References:  ref("SR-3"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "SR-4",
			Title:       "Provenance",
			Family:      "Supply Chain Risk Management",
			Description: "Document, monitor, and maintain valid provenance of the following systems, system components, and associated data: hardware, software, and firmware.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-494", "CWE-829"},
			Tags:        []string{"supply-chain", "integrity"},
			References:  ref("SR-4"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "SR-5",
			Title:       "Acquisition Strategies, Tools, and Methods",
			Family:      "Supply Chain Risk Management",
			Description: "Employ the following acquisition strategies, contract tools, and procurement methods to protect against, identify, and mitigate supply chain risks.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-494", "CWE-913"},
			Tags:        []string{"supply-chain", "governance"},
			References:  ref("SR-5"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "SR-6",
			Title:       "Supplier Assessments and Reviews",
			Family:      "Supply Chain Risk Management",
			Description: "Assess and review the supply chain-related risks associated with suppliers or contractors and the system, system component, or system service they provide.",
			Level:       "standard",
			RelatedCWEs: []string{},
			Tags:        []string{"supply-chain", "governance"},
			References:  ref("SR-6"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "SR-7",
			Title:       "Supply Chain Operations Security",
			Family:      "Supply Chain Risk Management",
			Description: "Employ the following operations security controls to protect supply chain-related information for the system, system component, or system service.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-829"},
			Tags:        []string{"supply-chain"},
			References:  ref("SR-7"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "SR-8",
			Title:       "Notification Agreements",
			Family:      "Supply Chain Risk Management",
			Description: "Establish agreements and procedures with entities involved in the supply chain for the notification of supply chain compromises and the results of assessments or audits.",
			Level:       "standard",
			RelatedCWEs: []string{},
			Tags:        []string{"supply-chain", "governance"},
			References:  ref("SR-8"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "SR-9",
			Title:       "Tamper Resistance and Detection",
			Family:      "Supply Chain Risk Management",
			Description: "Implement a tamper protection program for the system, system component, or system service.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-494", "CWE-1329"},
			Tags:        []string{"supply-chain", "integrity"},
			References:  ref("SR-9"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "SR-10",
			Title:       "Inspection of Systems or Components",
			Family:      "Supply Chain Risk Management",
			Description: "Inspect the following systems or system components to detect tampering in the following situations: prior to use, when returning from repair or maintenance, and when requested.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-1329"},
			Tags:        []string{"supply-chain", "integrity"},
			References:  ref("SR-10"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "SR-11",
			Title:       "Component Authenticity",
			Family:      "Supply Chain Risk Management",
			Description: "Develop and implement anti-counterfeit policy and procedures that include the means to detect and prevent counterfeit components from entering the system.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-494", "CWE-829"},
			Tags:        []string{"supply-chain", "integrity"},
			References:  ref("SR-11"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "SR-12",
			Title:       "Component Disposal",
			Family:      "Supply Chain Risk Management",
			Description: "Dispose of system components using the following techniques and methods to prevent the release of potentially sensitive information.",
			Level:       "standard",
			RelatedCWEs: []string{},
			Tags:        []string{"supply-chain"},
			References:  ref("SR-12"),
		},
		// SA family — System and Services Acquisition
		{
			Framework:   FrameworkID,
			ControlID:   "SA-3",
			Title:       "System Development Life Cycle",
			Family:      "System and Services Acquisition",
			Description: "Manage the system using the following system development life cycle that incorporates information security and privacy considerations.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-494", "CWE-829"},
			Tags:        []string{"sdlc", "supply-chain"},
			References:  ref("SA-3"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "SA-4",
			Title:       "Acquisition Process",
			Family:      "System and Services Acquisition",
			Description: "Include the following requirements, descriptions, and criteria, explicitly or by reference, using the defined acquisition contracts for the system, system component, or system service.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-494", "CWE-913"},
			Tags:        []string{"sdlc", "supply-chain", "governance"},
			References:  ref("SA-4"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "SA-8",
			Title:       "Security and Privacy Engineering Principles",
			Family:      "System and Services Acquisition",
			Description: "Apply the following systems security and privacy engineering principles in the specification, design, development, implementation, and modification of the system and system components.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-829"},
			Tags:        []string{"sdlc", "governance"},
			References:  ref("SA-8"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "SA-9",
			Title:       "External System Services",
			Family:      "System and Services Acquisition",
			Description: "Require that providers of external system services comply with organizational security and privacy requirements and employ security controls in accordance with applicable laws, executive orders, directives, policies, regulations, and standards.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-494", "CWE-829", "CWE-913"},
			Tags:        []string{"supply-chain", "governance"},
			References:  ref("SA-9"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "SA-10",
			Title:       "Developer Configuration Management",
			Family:      "System and Services Acquisition",
			Description: "Require the developer of the system, system component, or system service to manage and control changes to the system, component, or service during development and maintenance.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-494", "CWE-913"},
			Tags:        []string{"sdlc", "supply-chain"},
			References:  ref("SA-10"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "SA-12",
			Title:       "Memory Protection",
			Family:      "System and Services Acquisition",
			Description: "Implement the following controls to protect the memory of the system: data execution prevention, address space layout randomization.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-787"},
			Tags:        []string{"sdlc"},
			References:  ref("SA-12"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "SA-15",
			Title:       "Development Process, Standards, and Tools",
			Family:      "System and Services Acquisition",
			Description: "Require the developer of the system, system component, or system service to follow a documented development process that explicitly addresses security requirements.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-494", "CWE-829"},
			Tags:        []string{"sdlc", "supply-chain"},
			References:  ref("SA-15"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "SA-17",
			Title:       "Developer Security and Privacy Architecture and Design",
			Family:      "System and Services Acquisition",
			Description: "Require the developer of the system, system component, or system service to produce a design specification and security architecture that is consistent with the security architecture of the organisation.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-829"},
			Tags:        []string{"sdlc", "governance"},
			References:  ref("SA-17"),
		},
		// PM family — Program Management
		{
			Framework:   FrameworkID,
			ControlID:   "PM-30",
			Title:       "Supply Chain Risk Management Strategy",
			Family:      "Program Management",
			Description: "Develop an organisation-wide strategy for managing supply chain risks associated with the development, acquisition, maintenance, and disposal of systems, system components, and system services.",
			Level:       "standard",
			RelatedCWEs: []string{},
			Tags:        []string{"supply-chain", "governance"},
			References:  ref("PM-30"),
		},
		// RA family — Risk Assessment
		{
			Framework:   FrameworkID,
			ControlID:   "RA-3",
			Title:       "Risk Assessment",
			Family:      "Risk Assessment",
			Description: "Conduct a risk assessment, including supply chain risks, of the system or organisation and document results in a risk assessment report.",
			Level:       "standard",
			RelatedCWEs: []string{},
			Tags:        []string{"governance", "supply-chain"},
			References:  ref("RA-3"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "RA-9",
			Title:       "Criticality Analysis",
			Family:      "Risk Assessment",
			Description: "Identify critical system components and functions by performing a criticality analysis to support supply chain risk management decisions.",
			Level:       "standard",
			RelatedCWEs: []string{},
			Tags:        []string{"supply-chain", "governance"},
			References:  ref("RA-9"),
		},
		// CA family — Assessment, Authorization, and Monitoring
		{
			Framework:   FrameworkID,
			ControlID:   "CA-8",
			Title:       "Penetration Testing",
			Family:      "Assessment, Authorization, and Monitoring",
			Description: "Conduct penetration testing of the system or system components.",
			Level:       "standard",
			RelatedCWEs: []string{},
			Tags:        []string{"supply-chain", "vulnerability-management"},
			References:  ref("CA-8"),
		},
		// SI family — System and Information Integrity
		{
			Framework:   FrameworkID,
			ControlID:   "SI-7",
			Title:       "Software, Firmware, and Information Integrity",
			Family:      "System and Information Integrity",
			Description: "Employ integrity verification tools to detect unauthorised changes to the following software, firmware, and information.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-494", "CWE-829"},
			Tags:        []string{"supply-chain", "integrity"},
			References:  ref("SI-7"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "SI-19",
			Title:       "De-Identification",
			Family:      "System and Information Integrity",
			Description: "Remove the following elements of data from the dataset when the dataset is released from the system.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-200"},
			Tags:        []string{"supply-chain"},
			References:  ref("SI-19"),
		},
		// SC family — System and Communications Protection
		{
			Framework:   FrameworkID,
			ControlID:   "SC-29",
			Title:       "Heterogeneity",
			Family:      "System and Communications Protection",
			Description: "Employ a diverse set of information technologies in the implementation of the system.",
			Level:       "standard",
			RelatedCWEs: []string{},
			Tags:        []string{"supply-chain"},
			References:  ref("SC-29"),
		},
		// Additional SA enhancements
		{
			Framework:   FrameworkID,
			ControlID:   "SA-19",
			Title:       "Component Authenticity",
			Family:      "System and Services Acquisition",
			Description: "Develop and implement anti-counterfeit policy and procedures that include the means to detect and prevent counterfeit components from entering the system and report counterfeits.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-494", "CWE-829"},
			Tags:        []string{"supply-chain", "integrity"},
			References:  ref("SA-19"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "SA-20",
			Title:       "Customized Development of Critical Components",
			Family:      "System and Services Acquisition",
			Description: "Reimplement or custom develop the following critical system components.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-494", "CWE-829"},
			Tags:        []string{"supply-chain", "sdlc"},
			References:  ref("SA-20"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "SA-21",
			Title:       "Developer Screening",
			Family:      "System and Services Acquisition",
			Description: "Require that the developer of the system, system component, or system service have appropriate access authorizations as determined by assigned classifications and satisfy screening criteria.",
			Level:       "standard",
			RelatedCWEs: []string{},
			Tags:        []string{"supply-chain", "governance"},
			References:  ref("SA-21"),
		},
		// Additional SR enhancements
		{
			Framework:   FrameworkID,
			ControlID:   "SR-2.1",
			Title:       "Establish C-SCRM Team",
			Family:      "Supply Chain Risk Management",
			Description: "Establish a dedicated C-SCRM team with representatives from supply chain, security, and legal functions to govern and implement the C-SCRM plan.",
			Level:       "enhanced",
			RelatedCWEs: []string{},
			Tags:        []string{"supply-chain", "governance"},
			References:  ref("SR-2(1)"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "SR-3.1",
			Title:       "Diverse Supply Chain Sources",
			Family:      "Supply Chain Risk Management",
			Description: "Employ diverse supplier sources to reduce exposure to a single supplier or country of origin as a supply chain risk management strategy.",
			Level:       "enhanced",
			RelatedCWEs: []string{},
			Tags:        []string{"supply-chain"},
			References:  ref("SR-3(1)"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "SR-3.2",
			Title:       "Limitation of Harm",
			Family:      "Supply Chain Risk Management",
			Description: "Employ the following controls to limit harm from potential adversaries identifying and targeting the organizational supply chain.",
			Level:       "enhanced",
			RelatedCWEs: []string{"CWE-494", "CWE-829"},
			Tags:        []string{"supply-chain", "integrity"},
			References:  ref("SR-3(2)"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "SR-6.1",
			Title:       "Testing and Analysis",
			Family:      "Supply Chain Risk Management",
			Description: "Employ independent testing and analysis of supply chain elements, processes, products, and services.",
			Level:       "enhanced",
			RelatedCWEs: []string{},
			Tags:        []string{"supply-chain", "vulnerability-management"},
			References:  ref("SR-6(1)"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "SR-9.1",
			Title:       "Multiple Stages of System Development Life Cycle",
			Family:      "Supply Chain Risk Management",
			Description: "Employ anti-tamper technologies, tools, and techniques throughout the system development life cycle.",
			Level:       "enhanced",
			RelatedCWEs: []string{"CWE-494", "CWE-1329"},
			Tags:        []string{"supply-chain", "integrity", "sdlc"},
			References:  ref("SR-9(1)"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "SR-11.1",
			Title:       "Anti-Counterfeit Training",
			Family:      "Supply Chain Risk Management",
			Description: "Train personnel in how to detect counterfeit system components including hardware, software, and firmware.",
			Level:       "enhanced",
			RelatedCWEs: []string{"CWE-494"},
			Tags:        []string{"supply-chain", "integrity"},
			References:  ref("SR-11(1)"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "SR-11.2",
			Title:       "Configuration Control for Component Service and Repair",
			Family:      "Supply Chain Risk Management",
			Description: "Maintain configuration control over the following system components awaiting service or repair and serviced or repaired components awaiting return to service.",
			Level:       "enhanced",
			RelatedCWEs: []string{"CWE-494", "CWE-829"},
			Tags:        []string{"supply-chain", "integrity"},
			References:  ref("SR-11(2)"),
		},
		// Additional PM
		{
			Framework:   FrameworkID,
			ControlID:   "PM-9",
			Title:       "Risk Management Strategy",
			Family:      "Program Management",
			Description: "Develop a comprehensive strategy to manage security and supply chain risks to organisational operations, assets, individuals, and other organisations.",
			Level:       "standard",
			RelatedCWEs: []string{},
			Tags:        []string{"governance", "supply-chain"},
			References:  ref("PM-9"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "PM-16",
			Title:       "Threat Awareness Program",
			Family:      "Program Management",
			Description: "Implement a threat awareness program that includes a cross-organisation information-sharing capability to support supply chain risk management.",
			Level:       "standard",
			RelatedCWEs: []string{},
			Tags:        []string{"supply-chain", "governance"},
			References:  ref("PM-16"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "PM-16.1",
			Title:       "Suppliers and Developers",
			Family:      "Program Management",
			Description: "Share threat and vulnerability information with suppliers and developers, and receive information from suppliers and developers to support supply chain risk management.",
			Level:       "enhanced",
			RelatedCWEs: []string{"CWE-829"},
			Tags:        []string{"supply-chain", "vulnerability-management"},
			References:  ref("PM-16(1)"),
		},
		// Additional RA enhancements
		{
			Framework:   FrameworkID,
			ControlID:   "RA-3.1",
			Title:       "Supply Chain Risk Assessment",
			Family:      "Risk Assessment",
			Description: "Assess supply chain risks associated with the system and system components and incorporate supply chain risks into the organisation risk assessment.",
			Level:       "enhanced",
			RelatedCWEs: []string{},
			Tags:        []string{"supply-chain", "governance"},
			References:  ref("RA-3(1)"),
		},
		// SI enhancements
		{
			Framework:   FrameworkID,
			ControlID:   "SI-7.1",
			Title:       "Integrity Checks",
			Family:      "System and Information Integrity",
			Description: "Perform an integrity check of the system, system component, or system service at startup, at defined transitional states, and on an ongoing basis.",
			Level:       "enhanced",
			RelatedCWEs: []string{"CWE-494", "CWE-829"},
			Tags:        []string{"supply-chain", "integrity"},
			References:  ref("SI-7(1)"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "SI-7.6",
			Title:       "Cryptographic Protection",
			Family:      "System and Information Integrity",
			Description: "Implement cryptographic mechanisms to detect unauthorised changes to software, firmware, and information.",
			Level:       "enhanced",
			RelatedCWEs: []string{"CWE-494", "CWE-829"},
			Tags:        []string{"integrity", "supply-chain"},
			References:  ref("SI-7(6)"),
		},
	}
}
