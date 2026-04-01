package toms

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/shift/enrichment-engine/pkg/grc"
	"github.com/shift/enrichment-engine/pkg/storage"
)

const (
	FrameworkID = "TOMS_GDPR_ART32"
	CatalogURL  = ""
)

type Provider struct {
	store  storage.Backend
	logger *slog.Logger
}

func New(store storage.Backend, logger *slog.Logger) *Provider {
	return &Provider{store: store, logger: logger}
}

func (p *Provider) Name() string {
	return "toms"
}

func (p *Provider) Run(ctx context.Context) (int, error) {
	return p.writeEmbeddedControls(ctx)
}

func (p *Provider) writeEmbeddedControls(ctx context.Context) (int, error) {
	controls := embeddedControls()
	count := 0
	for _, ctrl := range controls {
		id := fmt.Sprintf("%s/%s", FrameworkID, ctrl.ControlID)
		if err := p.store.WriteControl(ctx, id, ctrl); err != nil {
			p.logger.Warn("failed to write control", "id", id, "error", err)
			continue
		}
		count++
	}
	if p.logger != nil {
		p.logger.Info("wrote TOMs controls", "count", count)
	}
	return count, nil
}

func embeddedControls() []grc.Control {
	return []grc.Control{
		{
			Framework: FrameworkID, ControlID: "TOM-TECH-1.1",
			Title: "Encryption at Rest", Family: "Technical Measures",
			Description:            "Implement encryption at rest for all personal data stores using AES-256 or equivalent algorithms. Encryption keys must be managed via a centralized key management system with separation of duties.",
			Level:                  "critical",
			RelatedCWEs:            []string{"CWE-311", "CWE-326", "CWE-320"},
			References:             []grc.Reference{{Source: "GDPR Article 32(1)(a)", URL: "https://gdpr-info.eu/art-32-gdpr/", Section: "Encryption"}, {Source: "ENISA Guidelines on Security of Personal Data Processing", URL: "https://www.enisa.europa.eu/", Section: "Technical Measures"}},
			ImplementationGuidance: "Deploy AES-256 encryption on all databases, file systems, and object storage. Use centralized KMS (AWS KMS, Azure Key Vault, HashiCorp Vault). Rotate keys annually. Separate key custodians from data custodians.",
			AssessmentMethods:      []string{"Encryption Audit", "Key Management Review", "Penetration Testing"},
		},
		{
			Framework: FrameworkID, ControlID: "TOM-TECH-1.2",
			Title: "Encryption in Transit", Family: "Technical Measures",
			Description:            "Enforce TLS 1.2 or higher for all data in transit, including internal service-to-service communication. Certificate pinning should be used for mobile and API clients.",
			Level:                  "critical",
			RelatedCWEs:            []string{"CWE-319", "CWE-326"},
			References:             []grc.Reference{{Source: "GDPR Article 32(1)(a)", URL: "https://gdpr-info.eu/art-32-gdpr/", Section: "Encryption"}, {Source: "ENISA TLS Guidelines", URL: "https://www.enisa.europa.eu/", Section: "TLS"}},
			ImplementationGuidance: "Disable TLS 1.0 and 1.1. Enforce TLS 1.2+ on all endpoints. Use strong cipher suites (ECDHE, AES-GCM). Enable HSTS. Implement certificate pinning for mobile apps.",
			AssessmentMethods:      []string{"SSL Labs Scan", "Internal TLS Audit", "Certificate Inventory Review"},
		},
		{
			Framework: FrameworkID, ControlID: "TOM-TECH-1.3",
			Title: "End-to-End Encryption", Family: "Technical Measures",
			Description:            "Implement end-to-end encryption for data flows where the processing entity should not have access to plaintext data, such as messaging platforms, data sharing between controllers, and encrypted backups.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-311", "CWE-319"},
			References:             []grc.Reference{{Source: "GDPR Article 32(1)(a)", URL: "https://gdpr-info.eu/art-32-gdpr/", Section: "E2EE"}},
			ImplementationGuidance: "Use E2EE for sensitive communications (Signal protocol, PGP). Implement zero-knowledge architecture where possible. Ensure encryption keys are held by data subjects or controllers, not processors.",
			AssessmentMethods:      []string{"Architecture Review", "E2EE Implementation Audit", "Manual Review"},
		},
		{
			Framework: FrameworkID, ControlID: "TOM-TECH-1.4",
			Title: "Pseudonymization Implementation", Family: "Technical Measures",
			Description:            "Implement pseudonymization techniques to reduce linkability of personal data, including tokenization, data masking, and k-anonymity for datasets shared for analytics or research purposes.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-200", "CWE-359"},
			References:             []grc.Reference{{Source: "GDPR Article 32(1)(a)", URL: "https://gdpr-info.eu/art-32-gdpr/", Section: "Pseudonymization"}, {Source: "GDPR Recital 78", URL: "https://gdpr-info.eu/recitals/no-78/", Section: "Recital 78"}},
			ImplementationGuidance: "Implement pseudonymization at the application layer. Use separate pseudonymization service with access controls. Apply k-anonymity (k>=5) for shared datasets. Maintain re-identification keys separately with restricted access.",
			AssessmentMethods:      []string{"Pseudonymization Audit", "Re-identification Risk Assessment", "Manual Review"},
		},
		{
			Framework: FrameworkID, ControlID: "TOM-TECH-1.5",
			Title: "Role-Based Access Control (RBAC)", Family: "Technical Measures",
			Description:            "Implement RBAC to ensure that access to personal data is restricted to authorized personnel based on their role and the principle of need-to-know.",
			Level:                  "critical",
			RelatedCWEs:            []string{"CWE-284", "CWE-862", "CWE-269"},
			References:             []grc.Reference{{Source: "GDPR Article 32(1)(b)", URL: "https://gdpr-info.eu/art-32-gdpr/", Section: "Access Control"}, {Source: "ISO 27001 A.9.1", URL: "https://www.iso.org/standard/27001", Section: "Access Control"}},
			ImplementationGuidance: "Define roles with minimum required permissions. Implement role hierarchy. Separate admin roles from regular user roles. Enforce RBAC at application and infrastructure layers. Log all access attempts.",
			AssessmentMethods:      []string{"RBAC Matrix Review", "Access Control Audit", "Privileged Access Review"},
		},
		{
			Framework: FrameworkID, ControlID: "TOM-TECH-1.6",
			Title: "Attribute-Based Access Control (ABAC)", Family: "Technical Measures",
			Description:            "Implement ABAC for fine-grained access control decisions based on attributes of the user, resource, action, and environment (time, location, device compliance).",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-284", "CWE-862"},
			References:             []grc.Reference{{Source: "GDPR Article 32(1)(b)", URL: "https://gdpr-info.eu/art-32-gdpr/", Section: "Access Control"}},
			ImplementationGuidance: "Define access policies based on user attributes (department, clearance), resource attributes (classification), and environmental attributes (time, location, device posture). Use Open Policy Agent or equivalent.",
			AssessmentMethods:      []string{"Policy Engine Audit", "Access Decision Logging Review", "Manual Review"},
		},
		{
			Framework: FrameworkID, ControlID: "TOM-TECH-1.7",
			Title: "Logging and Monitoring", Family: "Technical Measures",
			Description:            "Implement comprehensive logging of all access to personal data, including read, write, and delete operations, with tamper-evident log storage and real-time monitoring for anomalous access patterns.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-778", "CWE-775"},
			References:             []grc.Reference{{Source: "GDPR Article 32(1)(d)", URL: "https://gdpr-info.eu/art-32-gdpr/", Section: "Testing and Evaluation"}},
			ImplementationGuidance: "Enable audit logging on all systems processing personal data. Send logs to centralized SIEM. Implement append-only log storage. Set up alerts for bulk data access, failed authentication, and off-hours access.",
			AssessmentMethods:      []string{"Log Coverage Audit", "SIEM Rule Review", "Alert Response Testing"},
		},
		{
			Framework: FrameworkID, ControlID: "TOM-TECH-1.8",
			Title: "Intrusion Detection and Prevention", Family: "Technical Measures",
			Description:            "Deploy intrusion detection and prevention systems (IDS/IPS) at network boundaries and on critical servers to detect and block unauthorized access attempts to systems processing personal data.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-693"},
			References:             []grc.Reference{{Source: "GDPR Article 32(1)(b)", URL: "https://gdpr-info.eu/art-32-gdpr/", Section: "System and Service Security"}},
			ImplementationGuidance: "Deploy network-based IDS/IPS (Suricata, Snort) at perimeter and internal network segments. Enable host-based IDS on critical servers. Integrate with SIEM for correlation and alerting.",
			AssessmentMethods:      []string{"IDS/IPS Configuration Review", "Detection Rate Testing", "SIEM Integration Audit"},
		},
		{
			Framework: FrameworkID, ControlID: "TOM-TECH-1.9",
			Title: "Backup and Recovery", Family: "Technical Measures",
			Description:            "Implement regular, encrypted backups of all personal data with tested recovery procedures. Backups must be stored in geographically separate locations with access controls.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-24", "CWE-311"},
			References:             []grc.Reference{{Source: "GDPR Article 32(1)(c)", URL: "https://gdpr-info.eu/art-32-gdpr/", Section: "Availability"}, {Source: "ENISA Backup Guidelines", URL: "https://www.enisa.europa.eu/", Section: "Backup"}},
			ImplementationGuidance: "Perform daily incremental and weekly full backups. Encrypt all backups. Store in at least two geographically separate locations. Test recovery quarterly. Implement backup access controls.",
			AssessmentMethods:      []string{"Backup Schedule Audit", "Recovery Test Results", "Backup Encryption Verification"},
		},
		{
			Framework: FrameworkID, ControlID: "TOM-TECH-1.10",
			Title: "Data Masking for Non-Production Environments", Family: "Technical Measures",
			Description:            "Ensure that non-production environments (dev, test, staging) use masked or synthetic data instead of production personal data. Masking must preserve data format and referential integrity.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-200", "CWE-359"},
			References:             []grc.Reference{{Source: "GDPR Article 32(1)(a)", URL: "https://gdpr-info.eu/art-32-gdpr/", Section: "Pseudonymization"}},
			ImplementationGuidance: "Deploy data masking tools for database cloning. Use format-preserving encryption for structured data. Generate synthetic datasets for testing. Prohibit production data copies to non-prod environments.",
			AssessmentMethods:      []string{"Non-Production Data Audit", "Masking Tool Configuration Review", "Manual Review"},
		},
		{
			Framework: FrameworkID, ControlID: "TOM-TECH-1.11",
			Title: "Tokenization for Payment and Sensitive Data", Family: "Technical Measures",
			Description:            "Implement tokenization to replace sensitive data elements (payment card numbers, national IDs, SSNs) with non-reversible tokens, reducing PCI DSS and GDPR compliance scope.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-200", "CWE-311"},
			References:             []grc.Reference{{Source: "PCI DSS Tokenization Guidelines", URL: "https://www.pcisecuritystandards.org/", Section: "Tokenization"}},
			ImplementationGuidance: "Deploy a tokenization service (vault-based or vaultless). Store only tokens in application databases. Maintain token mapping in a secure, isolated vault with restricted access.",
			AssessmentMethods:      []string{"Tokenization Architecture Review", "Vault Security Audit", "PCI DSS Assessment"},
		},
		{
			Framework: FrameworkID, ControlID: "TOM-TECH-1.12",
			Title: "Key Management System", Family: "Technical Measures",
			Description:            "Implement a centralized key management system (KMS) for all encryption keys with hardware security module (HSM) backing, automated key rotation, and audit logging of all key operations.",
			Level:                  "critical",
			RelatedCWEs:            []string{"CWE-320", "CWE-326", "CWE-311"},
			References:             []grc.Reference{{Source: "NIST SP 800-57", URL: "https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final", Section: "Key Management"}},
			ImplementationGuidance: "Deploy centralized KMS (AWS KMS, Azure Key Vault, HashiCorp Vault). Use HSM-backed key storage. Automate key rotation (annual for data keys, quarterly for API keys). Log all key access.",
			AssessmentMethods:      []string{"KMS Configuration Audit", "HSM Compliance Review", "Key Rotation Log Review"},
		},
		{
			Framework: FrameworkID, ControlID: "TOM-TECH-1.13",
			Title: "Secure Development Lifecycle (SDLC)", Family: "Technical Measures",
			Description:            "Integrate security into every phase of the software development lifecycle including threat modeling, secure coding standards, code review, SAST/DAST scanning, and penetration testing.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-16", "CWE-94", "CWE-494"},
			References:             []grc.Reference{{Source: "GDPR Article 25 (Data Protection by Design)", URL: "https://gdpr-info.eu/art-25-gdpr/", Section: "SDLC"}, {Source: "OWASP SAMM", URL: "https://owaspsamm.org/", Section: "Secure Development"}},
			ImplementationGuidance: "Implement OWASP SAMM or BSIMM framework. Conduct threat modeling during design. Enforce secure coding standards. Run SAST/DAST in CI/CD pipeline. Perform annual penetration testing.",
			AssessmentMethods:      []string{"SDLC Maturity Assessment", "CI/CD Security Pipeline Review", "Penetration Test Reports"},
		},
		{
			Framework: FrameworkID, ControlID: "TOM-ORG-1.1",
			Title: "Security Awareness Training", Family: "Organizational Measures",
			Description:            "Provide mandatory security awareness and data protection training to all employees and contractors, with role-specific training for those handling personal data, and phishing simulation exercises.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-16"},
			References:             []grc.Reference{{Source: "GDPR Article 32(2)", URL: "https://gdpr-info.eu/art-32-gdpr/", Section: "Training"}, {Source: "ENISA Security Awareness", URL: "https://www.enisa.europa.eu/", Section: "Awareness"}},
			ImplementationGuidance: "Deliver annual security awareness training to all staff. Provide GDPR-specific training for data handlers. Conduct quarterly phishing simulations. Track completion rates. Update training annually.",
			AssessmentMethods:      []string{"Training Completion Reports", "Phishing Simulation Results", "Knowledge Assessment Scores"},
		},
		{
			Framework: FrameworkID, ControlID: "TOM-ORG-1.2",
			Title: "Information Security Policies", Family: "Organizational Measures",
			Description:            "Maintain a comprehensive set of information security policies covering data classification, acceptable use, access control, incident management, business continuity, and data protection, reviewed annually.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-16"},
			References:             []grc.Reference{{Source: "GDPR Article 32(1)(b)", URL: "https://gdpr-info.eu/art-32-gdpr/", Section: "Policies"}, {Source: "ISO 27001 A.5.1", URL: "https://www.iso.org/standard/27001", Section: "Policies"}},
			ImplementationGuidance: "Develop and maintain information security policy suite. Ensure policies are approved by management. Distribute to all employees. Require annual acknowledgment. Review and update policies at least annually.",
			AssessmentMethods:      []string{"Policy Review", "Acknowledgment Records", "Gap Analysis Against ISO 27001"},
		},
		{
			Framework: FrameworkID, ControlID: "TOM-ORG-1.3",
			Title: "Incident Response Plan", Family: "Organizational Measures",
			Description:            "Maintain a tested incident response plan with specific procedures for personal data breaches including notification timelines (72-hour GDPR notification), roles and responsibilities, and communication templates.",
			Level:                  "critical",
			RelatedCWEs:            []string{"CWE-778"},
			References:             []grc.Reference{{Source: "GDPR Article 33", URL: "https://gdpr-info.eu/art-33-gdpr/", Section: "Breach Notification"}, {Source: "GDPR Article 34", URL: "https://gdpr-info.eu/art-34-gdpr/", Section: "Data Subject Notification"}},
			ImplementationGuidance: "Document incident response procedures with clear roles. Include personal data breach playbook with 72-hour notification workflow. Pre-approve notification templates for supervisory authorities and data subjects. Test plan semi-annually.",
			AssessmentMethods:      []string{"Incident Response Plan Review", "Tabletop Exercise Results", "Breach Notification Timeline Test"},
		},
		{
			Framework: FrameworkID, ControlID: "TOM-ORG-1.4",
			Title: "Data Protection by Design and by Default", Family: "Organizational Measures",
			Description:            "Integrate data protection principles into the design and architecture of all systems and processes that process personal data, implementing privacy-by-design assessments for new projects.",
			Level:                  "critical",
			RelatedCWEs:            []string{"CWE-16"},
			References:             []grc.Reference{{Source: "GDPR Article 25", URL: "https://gdpr-info.eu/art-25-gdpr/", Section: "Data Protection by Design"}, {Source: "ICO PbD Guidance", URL: "https://ico.org.uk/for-organisations/guide-to-data-protection/guide-to-the-general-data-protection-regulation-gdpr/accountability-and-governance/", Section: "PbD"}},
			ImplementationGuidance: "Conduct privacy impact assessments for all new projects. Implement data minimization by default. Provide privacy settings at the most protective level by default. Document PbD decisions.",
			AssessmentMethods:      []string{"DPIA Register Review", "Architecture Privacy Review", "Manual Review"},
		},
		{
			Framework: FrameworkID, ControlID: "TOM-ORG-1.5",
			Title: "Data Protection Impact Assessment (DPIA)", Family: "Organizational Measures",
			Description:            "Conduct DPIAs for all processing activities likely to result in high risk to data subjects, including systematic profiling, large-scale processing, and new technologies.",
			Level:                  "critical",
			RelatedCWEs:            []string{"CWE-16"},
			References:             []grc.Reference{{Source: "GDPR Article 35", URL: "https://gdpr-info.eu/art-35-gdpr/", Section: "DPIA"}},
			ImplementationGuidance: "Establish DPIA process and templates. Identify high-risk processing activities. Conduct DPIA before processing commences. Consult DPO. Review DPIA when processing changes. Maintain DPIA register.",
			AssessmentMethods:      []string{"DPIA Register Audit", "DPO Consultation Records", "Risk Assessment Review"},
		},
		{
			Framework: FrameworkID, ControlID: "TOM-ORG-1.6",
			Title: "Vendor and Processor Management", Family: "Organizational Measures",
			Description:            "Maintain a vendor risk management program including security assessments, Data Processing Agreements (DPAs), sub-processor oversight, and regular audits of all processors handling personal data.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-359"},
			References:             []grc.Reference{{Source: "GDPR Article 28", URL: "https://gdpr-info.eu/art-28-gdpr/", Section: "Processor"}, {Source: "GDPR Article 28(3)", URL: "https://gdpr-info.eu/art-28-gdpr/", Section: "DPA Requirements"}},
			ImplementationGuidance: "Assess vendor security posture before engagement. Execute DPAs with all processors. Maintain processor register. Audit high-risk processors annually. Monitor sub-processor changes.",
			AssessmentMethods:      []string{"Vendor Risk Assessment Records", "DPA Register Review", "Audit Report Review"},
		},
		{
			Framework: FrameworkID, ControlID: "TOM-ORG-1.7",
			Title: "Periodic Access Review", Family: "Organizational Measures",
			Description:            "Conduct periodic reviews of access rights to personal data systems, ensuring that access is appropriate, up-to-date, and follows the principle of least privilege.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-284", "CWE-639"},
			References:             []grc.Reference{{Source: "GDPR Article 32(1)(b)", URL: "https://gdpr-info.eu/art-32-gdpr/", Section: "Access Control"}, {Source: "ISO 27001 A.9.2", URL: "https://www.iso.org/standard/27001", Section: "Access Review"}},
			ImplementationGuidance: "Schedule quarterly access reviews for privileged accounts and monthly for admin accounts. Use automated tools to identify dormant accounts. Require managers to certify team access. Track remediation.",
			AssessmentMethods:      []string{"Access Review Completion Reports", "Dormant Account Report", "Privileged Access Audit"},
		},
		{
			Framework: FrameworkID, ControlID: "TOM-ORG-1.8",
			Title: "Business Continuity and Disaster Recovery", Family: "Organizational Measures",
			Description:            "Maintain a business continuity plan (BCP) and disaster recovery plan (DRP) that ensure the availability and resilience of personal data processing systems, tested at least annually.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-24"},
			References:             []grc.Reference{{Source: "GDPR Article 32(1)(b)(c)", URL: "https://gdpr-info.eu/art-32-gdpr/", Section: "Resilience"}, {Source: "ISO 22301", URL: "https://www.iso.org/standard/22301", Section: "Business Continuity"}},
			ImplementationGuidance: "Develop BCP/DRP with defined RPO and RTO for personal data systems. Test DR annually with full failover. Document lessons learned. Update plans based on test results.",
			AssessmentMethods:      []string{"BCP/DRP Document Review", "DR Test Results", "RPO/RTO Achievement Analysis"},
		},
		{
			Framework: FrameworkID, ControlID: "TOM-ORG-1.9",
			Title: "Physical Security Controls", Family: "Organizational Measures",
			Description:            "Implement physical security controls for facilities housing personal data processing systems, including access control, surveillance, visitor management, and environmental protections.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-16"},
			References:             []grc.Reference{{Source: "GDPR Article 32(1)(b)", URL: "https://gdpr-info.eu/art-32-gdpr/", Section: "Physical Security"}, {Source: "ISO 27001 A.11", URL: "https://www.iso.org/standard/27001", Section: "Physical Security"}},
			ImplementationGuidance: "Control physical access with badges/biometrics. Implement visitor management. Deploy CCTV surveillance. Secure server rooms with environmental monitoring (fire, flood, temperature). Conduct physical security reviews.",
			AssessmentMethods:      []string{"Physical Security Audit", "Access Control Log Review", "Environmental Monitoring Report"},
		},
		{
			Framework: FrameworkID, ControlID: "TOM-ORG-1.10",
			Title: "Documentation and Records of Processing", Family: "Organizational Measures",
			Description:            "Maintain comprehensive documentation of all data processing activities, security measures, and compliance evidence, including the Record of Processing Activities (RoPA), DPIAs, and audit reports.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-16"},
			References:             []grc.Reference{{Source: "GDPR Article 30", URL: "https://gdpr-info.eu/art-30-gdpr/", Section: "Documentation"}, {Source: "GDPR Article 5(2)", URL: "https://gdpr-info.eu/art-5-gdpr/", Section: "Accountability"}},
			ImplementationGuidance: "Maintain RoPA as living document. Archive DPIA reports. Store audit reports with retention policies. Use a GRC platform for centralized documentation. Demonstrate accountability to supervisory authorities.",
			AssessmentMethods:      []string{"RoPA Completeness Review", "DPIA Register Audit", "Documentation Inventory"},
		},
	}
}
