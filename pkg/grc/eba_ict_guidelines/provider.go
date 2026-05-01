package eba_ict_guidelines

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/vincents-ai/enrichment-engine/pkg/grc"
	"github.com/vincents-ai/enrichment-engine/pkg/storage"
)

const FrameworkID = "EBA_ICT_GL_2025"

// Provider implements the EBA Guidelines on ICT and Security Risk Management
// (EBA GL/2025/02).
type Provider struct {
	store  storage.Backend
	logger *slog.Logger
}

// New creates a new EBA ICT Guidelines provider.
func New(store storage.Backend, logger *slog.Logger) *Provider {
	return &Provider{
		store:  store,
		logger: logger,
	}
}

// Name returns the provider identifier.
func (p *Provider) Name() string {
	return "eba_ict_guidelines"
}

// Run writes all EBA ICT GL/2025/02 controls to storage.
func (p *Provider) Run(ctx context.Context) (int, error) {
	p.logger.Info("loading EBA ICT GL/2025/02 controls")

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

	p.logger.Info("wrote EBA ICT GL/2025/02 controls to storage", "count", count)
	return count, nil
}

func staticControls() []grc.Control {
	ref := func(section string) []grc.Reference {
		return []grc.Reference{{
			Source:  "EBA GL/2025/02",
			URL:     "https://www.eba.europa.eu/regulation-and-policy/operational-resilience/guidelines-ict-and-security-risk-management",
			Section: section,
		}}
	}

	return []grc.Control{
		// §5.2 General ICT Risk Management Framework
		{
			Framework:   FrameworkID,
			ControlID:   "§5.2.1",
			Title:       "ICT Risk Management Governance",
			Family:      "General ICT Risk Management Framework",
			Description: "Institutions must establish a comprehensive ICT risk management framework that is integrated into the overall risk management structure and approved by the management body. The framework must define roles, responsibilities, and accountabilities for ICT risk across the three lines of defence, ensuring that ICT risks related to software supply chain components and third-party dependencies are explicitly scoped. Clear ownership of ICT risk governance is a prerequisite for managing software supply chain risks systematically.",
			Level:       "standard",
			RelatedCWEs: []string{},
			Tags:        []string{"governance"},
			References:  ref("§5.2"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "§5.2.2",
			Title:       "ICT Risk Appetite Statement",
			Family:      "General ICT Risk Management Framework",
			Description: "Institutions must define and maintain an ICT risk appetite statement that quantifies acceptable levels of ICT risk exposure, including risks arising from the use of open-source components, unpatched dependencies, and third-party software. The risk appetite must be reviewed at least annually and whenever material changes to the ICT environment occur, and must be cascaded to operational teams responsible for software development and deployment. An explicit risk appetite enables proportionate control investment across the software supply chain.",
			Level:       "standard",
			RelatedCWEs: []string{},
			Tags:        []string{"governance", "supply-chain"},
			References:  ref("§5.2"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "§5.2.3",
			Title:       "ICT Risk Taxonomy and Classification",
			Family:      "General ICT Risk Management Framework",
			Description: "Institutions must maintain a documented taxonomy of ICT risk categories that covers cyber risk, operational risk, technology risk, and supply chain risk, including risks introduced through SBOM components with known vulnerabilities. The taxonomy must be used consistently across risk identification, assessment, and reporting processes, ensuring that software supply chain risks are not conflated with or hidden within broader operational risk categories. A precise taxonomy supports accurate risk quantification and targeted remediation prioritisation.",
			Level:       "standard",
			RelatedCWEs: []string{},
			Tags:        []string{"governance", "supply-chain"},
			References:  ref("§5.2"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "§5.2.4",
			Title:       "Continuous ICT Risk Monitoring",
			Family:      "General ICT Risk Management Framework",
			Description: "Institutions must implement continuous monitoring of their ICT risk profile, including real-time detection of emerging vulnerabilities in deployed software components and changes in the threat landscape relevant to their technology stack. Monitoring must cover the full lifecycle of software assets, from development through production, and must include automated feeds from vulnerability databases and threat intelligence sources. Continuous monitoring prevents latent SBOM vulnerabilities from persisting undetected in production environments.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-1104"},
			Tags:        []string{"governance", "vulnerability-management"},
			References:  ref("§5.2"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "§5.2.5",
			Title:       "ICT Risk Reporting to Management Body",
			Family:      "General ICT Risk Management Framework",
			Description: "Institutions must establish regular ICT risk reporting to the management body, including key risk indicators, significant ICT incidents, status of remediation activities, and emerging risks from the software supply chain. Reports must be sufficiently detailed to enable informed decision-making on ICT risk treatment and investment in security controls, including prioritisation of software patching and dependency management activities. Regular board-level reporting ensures that ICT and supply chain risks receive appropriate strategic attention.",
			Level:       "standard",
			RelatedCWEs: []string{},
			Tags:        []string{"governance"},
			References:  ref("§5.2"),
		},

		// §5.3 ICT Strategy
		{
			Framework:   FrameworkID,
			ControlID:   "§5.3.1",
			Title:       "Multi-Year ICT Strategy",
			Family:      "ICT Strategy",
			Description: "Institutions must develop and maintain a documented multi-year ICT strategy that aligns technology investments with business objectives and risk appetite, including strategic decisions on technology stack, software sourcing, and supply chain risk management. The strategy must be reviewed at least annually and updated to reflect changes in the threat environment, regulatory requirements, and technology landscape affecting the institution's software dependencies. A coherent ICT strategy is the foundation for sustainable supply chain risk management.",
			Level:       "standard",
			RelatedCWEs: []string{},
			Tags:        []string{"governance", "supply-chain"},
			References:  ref("§5.3"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "§5.3.2",
			Title:       "Technology Roadmap",
			Family:      "ICT Strategy",
			Description: "Institutions must maintain a technology roadmap that plans the evolution of their ICT systems, including scheduled upgrades, migrations away from end-of-life software, and adoption of new technologies with assessed risk profiles. The roadmap must explicitly address the remediation of legacy dependencies that cannot receive security patches and must align with the institution's vulnerability management programme. A documented roadmap prevents unplanned accumulation of unsupported software components in the SBOM.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-1104"},
			Tags:        []string{"governance", "vulnerability-management", "sdlc"},
			References:  ref("§5.3"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "§5.3.3",
			Title:       "Legacy System Risk Management",
			Family:      "ICT Strategy",
			Description: "Institutions must identify and formally document all legacy ICT systems that are no longer supported by vendors or that cannot be patched to current security standards, and must implement compensating controls to reduce the associated risk. Legacy components in the software supply chain must be tracked in the SBOM with accurate end-of-support dates and risk assessments, enabling informed decisions on migration or isolation. Unmanaged legacy dependencies represent a disproportionate share of exploitable vulnerabilities in financial sector infrastructure.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-1104", "CWE-693"},
			Tags:        []string{"governance", "supply-chain", "vulnerability-management"},
			References:  ref("§5.3"),
		},

		// §5.4 ICT Governance
		{
			Framework:   FrameworkID,
			ControlID:   "§5.4.1",
			Title:       "Management Body Responsibility for ICT",
			Family:      "ICT Governance",
			Description: "The management body must take ultimate responsibility for the institution's ICT risk management framework, approving the ICT strategy, risk appetite, and material ICT policies including those governing software supply chain security and SBOM management. The management body must ensure that adequate resources are allocated to ICT security functions and that ICT risks are considered in all material business decisions involving technology adoption or outsourcing. Board accountability for ICT risk is a prerequisite for effective supply chain governance.",
			Level:       "standard",
			RelatedCWEs: []string{},
			Tags:        []string{"governance"},
			References:  ref("§5.4"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "§5.4.2",
			Title:       "ICT Function Organisation",
			Family:      "ICT Governance",
			Description: "Institutions must establish a clearly defined ICT function with documented organisational structure, reporting lines, and sufficient staffing with appropriate competencies to manage ICT and security risks. The ICT function must include dedicated capability for software security, covering secure development practices, vulnerability management, and oversight of third-party software components in the supply chain. Adequate organisational capacity in the ICT function is a structural prerequisite for effective SBOM governance.",
			Level:       "standard",
			RelatedCWEs: []string{},
			Tags:        []string{"governance", "sdlc"},
			References:  ref("§5.4"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "§5.4.3",
			Title:       "ICT Roles and Responsibilities",
			Family:      "ICT Governance",
			Description: "Institutions must document and communicate clear roles and responsibilities for ICT risk management, including ownership of specific systems, applications, and software components that constitute the SBOM. Role definitions must cover the full lifecycle from software procurement and development through deployment, monitoring, and decommissioning, ensuring no gaps in accountability exist for supply chain components. Clear role assignment prevents the unmonitored introduction of vulnerable components into production systems.",
			Level:       "standard",
			RelatedCWEs: []string{},
			Tags:        []string{"governance", "supply-chain"},
			References:  ref("§5.4"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "§5.4.4",
			Title:       "Third-Party ICT Oversight",
			Family:      "ICT Governance",
			Description: "Institutions must implement a formal oversight framework for third-party ICT service providers and software suppliers, including due diligence on their security practices, contractual security requirements, and ongoing monitoring of their compliance with those requirements. The oversight programme must cover software supply chain risk, including the security posture of open-source maintainers and commercial software vendors whose components appear in the institution's SBOM. Inadequate third-party oversight is a primary vector for supply chain compromise in financial institutions.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-494", "CWE-829"},
			Tags:        []string{"governance", "supply-chain"},
			References:  ref("§5.4"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "§5.4.5",
			Title:       "Board-Level ICT Risk Reporting",
			Family:      "ICT Governance",
			Description: "Institutions must provide the management body with regular, structured reporting on the ICT risk profile, including the status of key ICT controls, significant incidents, and emerging risks from the technology environment and supply chain. Reporting must be timely, accurate, and presented in a format that enables non-technical board members to understand the risk landscape and make informed decisions on ICT risk treatment. Effective board reporting on ICT risks, including supply chain vulnerabilities, drives proportionate investment in security controls.",
			Level:       "standard",
			RelatedCWEs: []string{},
			Tags:        []string{"governance"},
			References:  ref("§5.4"),
		},

		// §5.5 Information Security
		{
			Framework:   FrameworkID,
			ControlID:   "§5.5.1",
			Title:       "Information Security Policy",
			Family:      "Information Security",
			Description: "Institutions must establish and maintain a comprehensive information security policy that is approved by the management body, communicated to all relevant staff, and reviewed at least annually or following significant security events. The policy must address the security of the full software supply chain, including requirements for secure coding, dependency management, and the handling of SBOM data. A well-maintained security policy provides the normative foundation for all technical security controls applied to software assets.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-1188"},
			Tags:        []string{"governance", "sdlc"},
			References:  ref("§5.5"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "§5.5.2",
			Title:       "Information Classification",
			Family:      "Information Security",
			Description: "Institutions must implement an information classification scheme that categorises data and systems according to their sensitivity, criticality, and regulatory requirements, with appropriate security controls applied at each classification level. SBOM data, source code, build artefacts, and deployment configurations must be classified and protected commensurate with the sensitivity of the systems they describe. Inappropriate handling of SBOM and configuration data can enable targeted attacks on known vulnerable components.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-200"},
			Tags:        []string{"governance", "supply-chain"},
			References:  ref("§5.5"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "§5.5.3",
			Title:       "Access Control",
			Family:      "Information Security",
			Description: "Institutions must implement access controls based on the principle of least privilege, ensuring that users, service accounts, and automated processes can only access the ICT resources and data necessary for their authorised functions. Access to build pipelines, software repositories, and deployment systems must be tightly controlled and regularly reviewed to prevent unauthorised modification of software supply chain artefacts. Overprivileged access to development and deployment infrastructure is a primary enabler of software supply chain attacks.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-284", "CWE-269"},
			Tags:        []string{"access-control", "supply-chain", "sdlc"},
			References:  ref("§5.5"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "§5.5.4",
			Title:       "Cryptographic Controls",
			Family:      "Information Security",
			Description: "Institutions must implement a cryptographic policy that specifies approved algorithms, key lengths, and key management procedures for protecting data at rest and in transit, including the cryptographic signing of software artefacts in the supply chain. Code signing, package integrity verification, and secure key management for build and deployment infrastructure must be mandated to ensure the authenticity and integrity of deployed software components. Absent or weak cryptographic controls over software artefacts enable tampering and substitution attacks in the supply chain.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-327", "CWE-326", "CWE-345"},
			Tags:        []string{"cryptography", "integrity", "supply-chain"},
			References:  ref("§5.5"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "§5.5.5",
			Title:       "Network Security",
			Family:      "Information Security",
			Description: "Institutions must implement network segmentation, perimeter controls, and secure communication protocols to protect ICT systems and data from unauthorised network access, including isolation of build and deployment infrastructure from production networks. Network traffic to and from package repositories, container registries, and other software supply chain infrastructure must be monitored and controlled to detect and prevent exfiltration or injection of malicious content. Network-level controls are a critical compensating control for software supply chain vulnerabilities that have not yet been patched.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-319", "CWE-295"},
			Tags:        []string{"network", "supply-chain"},
			References:  ref("§5.5"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "§5.5.6",
			Title:       "Vulnerability Management",
			Family:      "Information Security",
			Description: "Institutions must implement a formal vulnerability management process that covers the identification, assessment, prioritisation, and remediation of vulnerabilities in all ICT systems, including third-party and open-source software components listed in the SBOM. Vulnerability scanning must be performed continuously or at defined intervals and must include automated correlation against known vulnerability databases (e.g. NVD, CVE) to ensure that newly disclosed vulnerabilities in deployed components are detected promptly. Systematic vulnerability management of SBOM components is the primary technical control for supply chain risk reduction.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-1104", "CWE-693"},
			Tags:        []string{"vulnerability-management", "supply-chain"},
			References:  ref("§5.5"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "§5.5.7",
			Title:       "Patch Management",
			Family:      "Information Security",
			Description: "Institutions must implement a structured patch management process with defined timelines for deploying security patches to ICT systems based on the severity of the vulnerability and the criticality of the affected system. Patch deployment timelines must account for software supply chain dependencies, ensuring that patches to upstream libraries and frameworks are propagated through the dependency tree and redeployed in affected applications. Delayed or incomplete patching of SBOM dependencies is a leading cause of preventable security incidents in financial institutions.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-1104"},
			Tags:        []string{"vulnerability-management", "supply-chain", "sdlc"},
			References:  ref("§5.5"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "§5.5.8",
			Title:       "Security Information and Event Management",
			Family:      "Information Security",
			Description: "Institutions must deploy a security information and event management (SIEM) capability that aggregates, correlates, and analyses security events from across their ICT environment, including events from build pipelines, software repositories, and deployment systems. SIEM rules must include detection logic for indicators of software supply chain compromise, such as unexpected package downloads, unsigned artefact deployments, and anomalous build process behaviour. Effective SIEM coverage of supply chain infrastructure enables early detection of compromise before malicious software reaches production.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-778"},
			Tags:        []string{"logging", "supply-chain"},
			References:  ref("§5.5"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "§5.5.9",
			Title:       "Penetration Testing",
			Family:      "Information Security",
			Description: "Institutions must conduct regular penetration testing of their ICT systems and applications, including threat-led penetration testing of critical systems, to identify exploitable vulnerabilities that automated scanning may miss. Penetration tests must include assessment of software supply chain attack vectors, such as dependency confusion, malicious package injection, and build pipeline compromise, to evaluate the effectiveness of implemented controls. Regular penetration testing provides evidence of control effectiveness and drives prioritised remediation of exploitable weaknesses.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-1104", "CWE-693"},
			Tags:        []string{"vulnerability-management", "supply-chain", "sdlc"},
			References:  ref("§5.5"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "§5.5.10",
			Title:       "Secure Software Development",
			Family:      "Information Security",
			Description: "Institutions must implement secure software development lifecycle (SDLC) practices, including security requirements definition, threat modelling, secure coding standards, security testing, and code review, applied consistently across all software development activities. SDLC controls must include mandatory SBOM generation for all developed and assembled software, automated dependency scanning in CI/CD pipelines, and prohibition on the use of components with known critical vulnerabilities. Embedding security into the SDLC is the most cost-effective point at which to address software supply chain risk.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-1104", "CWE-676"},
			Tags:        []string{"sdlc", "supply-chain", "vulnerability-management"},
			References:  ref("§5.5"),
		},

		// §5.6 ICT-Related Incident Management
		{
			Framework:   FrameworkID,
			ControlID:   "§5.6.1",
			Title:       "ICT Incident Classification",
			Family:      "ICT-Related Incident Management",
			Description: "Institutions must establish a documented incident classification scheme that categorises ICT incidents by severity, impact, and type, with specific criteria for identifying major ICT incidents that trigger regulatory reporting obligations. The classification scheme must include categories for supply chain incidents, such as the discovery of a compromised dependency or a malicious package in a production SBOM, enabling appropriate escalation and response. Consistent incident classification ensures that supply chain incidents receive proportionate management attention and regulatory notification.",
			Level:       "standard",
			RelatedCWEs: []string{},
			Tags:        []string{"governance", "supply-chain"},
			References:  ref("§5.6"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "§5.6.2",
			Title:       "Incident Detection Capability",
			Family:      "ICT-Related Incident Management",
			Description: "Institutions must deploy technical controls and processes capable of detecting ICT incidents in a timely manner, including automated alerting based on security event correlation, anomaly detection, and threat intelligence integration. Detection capabilities must cover supply chain attack indicators, such as unexpected modifications to software components, build artefact hash mismatches, and deployment of components not present in the authorised SBOM. Prompt detection of supply chain incidents is critical for limiting the blast radius of successful attacks.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-778"},
			Tags:        []string{"logging", "supply-chain", "vulnerability-management"},
			References:  ref("§5.6"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "§5.6.3",
			Title:       "Incident Response Process",
			Family:      "ICT-Related Incident Management",
			Description: "Institutions must maintain documented incident response procedures that define roles, responsibilities, escalation paths, and response actions for ICT incidents across all severity levels, including supply chain compromise scenarios. Response procedures must include steps for isolating affected systems, reverting to known-good software versions using authorised SBOM baselines, and preserving evidence for forensic analysis. A well-rehearsed incident response capability is essential for minimising the impact of supply chain incidents on business continuity and customer data protection.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-778", "CWE-693"},
			Tags:        []string{"governance", "supply-chain"},
			References:  ref("§5.6"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "§5.6.4",
			Title:       "Major ICT Incident Reporting to EBA",
			Family:      "ICT-Related Incident Management",
			Description: "Institutions must report major ICT-related incidents to their competent authority and, where applicable, to the EBA in accordance with the prescribed timelines and reporting templates, including an initial notification, an intermediate report, and a final report. Supply chain incidents that result in significant service disruption, data breach, or systemic risk must be assessed against the major incident criteria and reported accordingly. Timely and accurate regulatory reporting of supply chain incidents supports systemic risk monitoring across the financial sector.",
			Level:       "standard",
			RelatedCWEs: []string{},
			Tags:        []string{"governance"},
			References:  ref("§5.6"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "§5.6.5",
			Title:       "Root Cause Analysis",
			Family:      "ICT-Related Incident Management",
			Description: "Institutions must perform documented root cause analysis for all major ICT incidents, identifying the underlying technical, process, and governance factors that enabled the incident to occur and persist undetected. Root cause analyses of supply chain incidents must trace the vulnerability or compromise through the full dependency chain, identifying which SBOM components were affected and why existing controls failed to prevent or detect the incident. Root cause analysis findings must be used to drive systemic improvements in ICT and supply chain risk controls.",
			Level:       "standard",
			RelatedCWEs: []string{},
			Tags:        []string{"governance", "supply-chain"},
			References:  ref("§5.6"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "§5.6.6",
			Title:       "Lessons Learned Process",
			Family:      "ICT-Related Incident Management",
			Description: "Institutions must implement a formal lessons learned process that translates findings from incident post-mortems and root cause analyses into concrete improvements to ICT controls, processes, and governance. Lessons from supply chain incidents must be shared internally across development, operations, and risk functions, and where appropriate, with industry peers through information sharing mechanisms, to strengthen collective defence. A systematic lessons learned process prevents recurrence of supply chain incidents and continuously improves the maturity of security controls.",
			Level:       "standard",
			RelatedCWEs: []string{},
			Tags:        []string{"governance"},
			References:  ref("§5.6"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "§5.6.7",
			Title:       "ICT Incident Register",
			Family:      "ICT-Related Incident Management",
			Description: "Institutions must maintain a comprehensive ICT incident register that records all detected incidents, including details of the incident type, affected systems, timeline, impact, response actions taken, and remediation status. The register must capture supply chain incidents with sufficient granularity to enable trend analysis across SBOM components, dependency types, and attack vectors, supporting continuous improvement of supply chain risk management. A well-maintained incident register is a key source of evidence for both internal risk management and regulatory examination.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-778"},
			Tags:        []string{"logging", "governance", "supply-chain"},
			References:  ref("§5.6"),
		},

		// §5.7 Business Continuity Management
		{
			Framework:   FrameworkID,
			ControlID:   "§5.7.1",
			Title:       "Business Continuity Plan",
			Family:      "Business Continuity Management",
			Description: "Institutions must develop and maintain documented business continuity plans (BCPs) that define procedures for maintaining or restoring critical ICT services and business functions in the event of a significant disruption, including disruptions caused by supply chain incidents. BCPs must address scenarios in which widely-used software components are found to contain critical vulnerabilities or backdoors, requiring emergency patching or rollback of deployed software across multiple systems simultaneously. A comprehensive BCP that includes supply chain disruption scenarios is essential for operational resilience.",
			Level:       "standard",
			RelatedCWEs: []string{},
			Tags:        []string{"governance", "supply-chain"},
			References:  ref("§5.7"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "§5.7.2",
			Title:       "Recovery Time and Point Objectives",
			Family:      "Business Continuity Management",
			Description: "Institutions must define Recovery Time Objectives (RTOs) and Recovery Point Objectives (RPOs) for all critical ICT systems and services, reflecting the maximum acceptable downtime and data loss for each system given its business criticality. RTO/RPO definitions must account for supply chain scenarios, including the time required to identify, validate, and deploy patched or replacement software components from an authorised SBOM baseline. Clearly defined and tested RTO/RPO commitments underpin credible operational resilience planning.",
			Level:       "standard",
			RelatedCWEs: []string{},
			Tags:        []string{"governance"},
			References:  ref("§5.7"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "§5.7.3",
			Title:       "Crisis Management Framework",
			Family:      "Business Continuity Management",
			Description: "Institutions must establish a crisis management framework that defines the escalation path, decision-making authority, and communication protocols for managing severe ICT disruptions that threaten business continuity or financial stability. The crisis management process must include pre-defined response playbooks for major supply chain incidents, such as the discovery of a malicious component in production, ensuring that senior management can make timely decisions on emergency remediation. Effective crisis management capability reduces the duration and impact of major supply chain incidents.",
			Level:       "standard",
			RelatedCWEs: []string{},
			Tags:        []string{"governance", "supply-chain"},
			References:  ref("§5.7"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "§5.7.4",
			Title:       "Backup and Data Recovery",
			Family:      "Business Continuity Management",
			Description: "Institutions must implement backup procedures for all critical ICT systems and data, with backup frequency, retention period, and recovery procedures defined in accordance with RTO/RPO requirements. Backup scope must include software artefacts, build configurations, and SBOM records to enable recovery to a known-good software state following a supply chain compromise that requires rollback of deployed components. Regular testing of recovery from backup ensures that SBOM-based recovery procedures are operationally viable.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-693"},
			Tags:        []string{"governance", "integrity", "supply-chain"},
			References:  ref("§5.7"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "§5.7.5",
			Title:       "Recovery Testing",
			Family:      "Business Continuity Management",
			Description: "Institutions must regularly test their recovery capabilities through exercises that simulate realistic disruption scenarios, including supply chain attacks, and must document the results and use them to improve recovery plans and procedures. Recovery tests must validate that SBOM-based rollback procedures are operable and that authorised software versions can be redeployed within defined RTO commitments from known-good artefact stores. Untested recovery procedures are unreliable in a real incident and must be validated through regular structured exercises.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-693"},
			Tags:        []string{"governance"},
			References:  ref("§5.7"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "§5.7.6",
			Title:       "Critical Services Mapping",
			Family:      "Business Continuity Management",
			Description: "Institutions must maintain a current mapping of all critical business services to the underlying ICT systems, applications, and software components (including SBOM dependencies) that support them, enabling rapid impact assessment when a supply chain incident affects a specific component. The mapping must be kept up to date as systems evolve and must be accessible to incident response teams during a crisis without reliance on potentially compromised systems. Accurate service dependency mapping is a prerequisite for effective impact assessment and prioritised recovery during supply chain incidents.",
			Level:       "standard",
			RelatedCWEs: []string{},
			Tags:        []string{"governance", "supply-chain"},
			References:  ref("§5.7"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "§5.7.7",
			Title:       "BCM Framework Governance",
			Family:      "Business Continuity Management",
			Description: "Institutions must establish a business continuity management (BCM) framework that is approved by the management body, assigns clear ownership for BCM activities, and ensures that BCM considerations are integrated into all material ICT change and procurement decisions. The BCM framework must include supply chain resilience as a first-class concern, requiring continuity assessments for critical software suppliers and alternative sourcing plans where single points of failure are identified. Governance-level integration of BCM and supply chain risk management prevents continuity gaps from developing as the software supply chain evolves.",
			Level:       "standard",
			RelatedCWEs: []string{},
			Tags:        []string{"governance", "supply-chain"},
			References:  ref("§5.7"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "§5.7.8",
			Title:       "Disaster Recovery",
			Family:      "Business Continuity Management",
			Description: "Institutions must implement disaster recovery capabilities for critical ICT systems, including geographically separated recovery sites or cloud-based failover, with sufficient capacity and current software versions to meet defined RTO/RPO commitments. Disaster recovery environments must maintain synchronised, validated SBOM records and must be subject to the same supply chain security controls as production environments to prevent recovery infrastructure from becoming a weaker attack surface. Disaster recovery planning must explicitly address supply chain scenarios that could affect primary and recovery sites simultaneously.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-693"},
			Tags:        []string{"governance", "supply-chain"},
			References:  ref("§5.7"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "§5.7.9",
			Title:       "Supply Chain Continuity",
			Family:      "Business Continuity Management",
			Description: "Institutions must assess the continuity risk posed by concentration in their software supply chain, including dependencies on single commercial vendors, single open-source maintainers, or single package registries, and must implement mitigation measures such as private mirrors, alternative suppliers, or internal forks for critical components. Continuity plans must document the steps required to substitute a critical supply chain component that becomes unavailable or compromised, including testing these substitution procedures at defined intervals. Supply chain concentration risk is a systemic concern for the financial sector and must be managed with the same rigour as infrastructure concentration risk.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-494", "CWE-829"},
			Tags:        []string{"governance", "supply-chain"},
			References:  ref("§5.7"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "§5.7.10",
			Title:       "BCM Governance and Oversight",
			Family:      "Business Continuity Management",
			Description: "Institutions must subject their BCM framework to independent review or audit at regular intervals to assess its effectiveness and completeness, including coverage of supply chain disruption scenarios. BCM governance must include a process for updating plans in response to material changes to the ICT environment, new supply chain dependencies, or lessons learned from exercises and actual incidents. Ongoing oversight of the BCM framework ensures that it remains relevant and effective as the institution's software supply chain evolves.",
			Level:       "standard",
			RelatedCWEs: []string{},
			Tags:        []string{"governance"},
			References:  ref("§5.7"),
		},
	}
}
