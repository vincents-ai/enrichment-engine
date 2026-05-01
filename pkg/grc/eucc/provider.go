package eucc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"

	"github.com/vincents-ai/enrichment-engine/pkg/grc"
	"github.com/vincents-ai/enrichment-engine/pkg/storage"
)

const (
	FrameworkID = "EUCC_2024"
)

var CatalogURL = "https://raw.githubusercontent.com/eu-cloud-certification/eucc/main/controls.json"

// Provider fetches and parses EU Cybersecurity Certification for Cloud Services (EUCC) controls.
type Provider struct {
	store  storage.Backend
	logger *slog.Logger
}

// New creates a new EUCC provider.
func New(store storage.Backend, logger *slog.Logger) *Provider {
	return &Provider{
		store:  store,
		logger: logger,
	}
}

// Name returns the provider identifier.
func (p *Provider) Name() string {
	return "eucc"
}

// Run fetches the EUCC controls, parses them, and writes to storage.
func (p *Provider) Run(ctx context.Context) (int, error) {
	p.logger.Info("fetching EUCC cloud certification controls", "url", CatalogURL)

	f, err := os.CreateTemp("", "eucc_controls_*.json")
	if err != nil {
		return 0, fmt.Errorf("create temp file: %w", err)
	}
	destPath := f.Name()
	f.Close()
	defer os.Remove(destPath)
	if err := p.download(ctx, CatalogURL, destPath); err != nil {
		p.logger.Warn("download failed, falling back to embedded controls", "error", err)
		controls := p.generateEmbeddedControls()
		return p.writeControls(ctx, controls)
	}

	controls, err := p.parse(destPath)
	if err != nil {
		p.logger.Warn("parse failed, falling back to embedded controls", "error", err)
		controls = p.generateEmbeddedControls()
	}

	return p.writeControls(ctx, controls)
}

func (p *Provider) download(ctx context.Context, url, dest string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("%s download: %w", p.Name(), err)
	}

	resp, err := grc.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("%s download: %w", p.Name(), err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s download: unexpected status %d", p.Name(), resp.StatusCode)
	}

	f, err := os.Create(dest)
	if err != nil {
		return fmt.Errorf("%s download: %w", p.Name(), err)
	}
	defer f.Close()

	if _, err = io.Copy(f, resp.Body); err != nil {
		return fmt.Errorf("%s download: %w", p.Name(), err)
	}
	return nil
}

type euccCatalog struct {
	Controls []euccControl `json:"controls,omitempty"`
}

type euccControl struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Family      string `json:"family,omitempty"`
	Description string `json:"description"`
	Level       string `json:"level,omitempty"`
	Category    string `json:"category,omitempty"`
}

func (p *Provider) parse(path string) ([]grc.Control, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var catalog euccCatalog
	if err := json.NewDecoder(f).Decode(&catalog); err != nil {
		return nil, fmt.Errorf("decode EUCC catalog: %w", err)
	}

	var controls []grc.Control
	for _, ctrl := range catalog.Controls {
		controls = append(controls, p.buildControl(ctrl))
	}

	return controls, nil
}

func (p *Provider) buildControl(ctrl euccControl) grc.Control {
	return grc.Control{
		Framework:   FrameworkID,
		ControlID:   ctrl.ID,
		Title:       ctrl.Title,
		Family:      ctrl.Family,
		Description: ctrl.Description,
		Level:       ctrl.Level,
		References: []grc.Reference{
			{Source: "EUCC", URL: "https://digital-strategy.ec.europa.eu/en/policies/cloud-certification", Section: ctrl.Category},
		},
	}
}

func (p *Provider) writeControls(ctx context.Context, controls []grc.Control) (int, error) {
	p.logger.Info("parsed EUCC controls", "count", len(controls))

	count := 0
	for _, ctrl := range controls {
		id := fmt.Sprintf("%s/%s", FrameworkID, ctrl.ControlID)
		if err := p.store.WriteControl(ctx, id, ctrl); err != nil {
			p.logger.Warn("failed to write control", "id", id, "error", err)
			continue
		}
		count++
	}

	p.logger.Info("wrote EUCC controls to storage", "count", count)
	return count, nil
}

func (p *Provider) generateEmbeddedControls() []grc.Control {
	controls := []euccControl{
		{ID: "EUCC-001", Title: "Cloud Service Architecture Security", Family: "Architecture", Description: "Cloud service architecture shall implement defense-in-depth principles with multiple layers of security controls including network segmentation, isolation boundaries, and redundant security mechanisms across all service tiers.", Level: "critical", Category: "Architecture"},
		{ID: "EUCC-002", Title: "Multi-Tenant Isolation", Family: "Architecture", Description: "Cloud providers shall ensure strict logical and physical isolation between tenants through hypervisor security, container isolation, network segmentation, and storage encryption to prevent cross-tenant data access.", Level: "critical", Category: "Architecture"},
		{ID: "EUCC-003", Title: "Data Residency and Sovereignty", Family: "Data Protection", Description: "Cloud services shall support data residency requirements allowing customers to specify geographic locations for data storage and processing. Data shall not be transferred outside specified regions without explicit authorization.", Level: "critical", Category: "Data Protection"},
		{ID: "EUCC-004", Title: "Encryption at Rest", Family: "Data Protection", Description: "All customer data stored in cloud services shall be encrypted at rest using approved cryptographic algorithms. Encryption keys shall be managed separately from encrypted data with customer-controlled key options.", Level: "critical", Category: "Data Protection"},
		{ID: "EUCC-005", Title: "Encryption in Transit", Family: "Data Protection", Description: "All data transmitted between cloud service components, and between cloud services and customers, shall be encrypted using TLS 1.2 or higher with approved cipher suites. Internal service-to-service communication shall also be encrypted.", Level: "critical", Category: "Data Protection"},
		{ID: "EUCC-006", Title: "Identity and Access Management", Family: "Access Control", Description: "Cloud services shall provide comprehensive IAM capabilities including role-based access control, multi-factor authentication, privilege management, and integration with enterprise identity providers via SAML, OIDC, or SCIM.", Level: "high", Category: "Access Control"},
		{ID: "EUCC-007", Title: "Privileged Access Management", Family: "Access Control", Description: "Cloud provider privileged access to customer environments shall be strictly controlled, logged, and monitored. Just-in-time access, break-glass procedures, and customer approval workflows shall be implemented.", Level: "critical", Category: "Access Control"},
		{ID: "EUCC-008", Title: "API Security", Family: "Application Security", Description: "Cloud service APIs shall implement authentication, authorization, rate limiting, input validation, and output encoding. API security testing shall be conducted regularly with vulnerability remediation processes.", Level: "high", Category: "Application Security"},
		{ID: "EUCC-009", Title: "Secure Software Development", Family: "Application Security", Description: "Cloud service software shall be developed following secure development lifecycle practices including threat modelling, code review, static/dynamic analysis, and penetration testing before deployment.", Level: "high", Category: "Application Security"},
		{ID: "EUCC-010", Title: "Vulnerability Management", Family: "Vulnerability Handling", Description: "Cloud providers shall maintain continuous vulnerability scanning, assessment, and remediation programs. Critical vulnerabilities shall be patched within defined SLAs with customer notification procedures.", Level: "critical", Category: "Vulnerability Handling"},
		{ID: "EUCC-011", Title: "Security Monitoring and Logging", Family: "Monitoring", Description: "Cloud services shall provide comprehensive security monitoring including log collection, SIEM integration, anomaly detection, and real-time alerting. Logs shall be retained for minimum periods defined by regulation.", Level: "high", Category: "Monitoring"},
		{ID: "EUCC-012", Title: "Incident Response Capability", Family: "Incident Management", Description: "Cloud providers shall maintain documented incident response procedures including detection, analysis, containment, eradication, recovery, and post-incident review. Customer notification procedures shall be defined.", Level: "critical", Category: "Incident Management"},
		{ID: "EUCC-013", Title: "Business Continuity and Disaster Recovery", Family: "Resilience", Description: "Cloud services shall implement business continuity and disaster recovery plans with defined RTO and RPO objectives. Regular testing of recovery procedures and failover capabilities shall be conducted.", Level: "high", Category: "Resilience"},
		{ID: "EUCC-014", Title: "Backup and Data Recovery", Family: "Resilience", Description: "Cloud providers shall implement automated backup procedures with encrypted storage, integrity verification, and tested recovery processes. Customer data backup frequency and retention shall meet contractual requirements.", Level: "high", Category: "Resilience"},
		{ID: "EUCC-015", Title: "Physical Security", Family: "Physical Security", Description: "Cloud data centers shall implement layered physical security controls including perimeter protection, access control systems, surveillance, environmental controls, and protection against natural disasters.", Level: "high", Category: "Physical Security"},
		{ID: "EUCC-016", Title: "Supply Chain Security", Family: "Supply Chain", Description: "Cloud providers shall assess and monitor security of third-party suppliers, subcontractors, and service dependencies. Supply chain risk assessments and security requirements shall be documented and enforced.", Level: "high", Category: "Supply Chain"},
		{ID: "EUCC-017", Title: "Configuration Management", Family: "Operations", Description: "Cloud infrastructure configuration shall be managed through infrastructure-as-code with version control, change approval processes, and automated compliance checking. Configuration drift detection shall be implemented.", Level: "high", Category: "Operations"},
		{ID: "EUCC-018", Title: "Network Security Controls", Family: "Network Security", Description: "Cloud network security shall include firewalls, intrusion detection/prevention, DDoS protection, web application firewalls, and secure network architecture with zero-trust principles applied.", Level: "high", Category: "Network Security"},
		{ID: "EUCC-019", Title: "Container and Orchestration Security", Family: "Cloud Native", Description: "Container platforms and orchestration systems shall implement image scanning, runtime protection, network policies, secrets management, and pod security standards to secure containerized workloads.", Level: "high", Category: "Cloud Native"},
		{ID: "EUCC-020", Title: "Serverless Security", Family: "Cloud Native", Description: "Serverless computing platforms shall implement function-level isolation, secure deployment pipelines, dependency scanning, execution time limits, and protection against serverless-specific attack vectors.", Level: "high", Category: "Cloud Native"},
		{ID: "EUCC-021", Title: "Data Portability", Family: "Customer Rights", Description: "Cloud services shall support data portability allowing customers to export their data in standard formats without vendor lock-in. Migration assistance and data transfer tools shall be provided.", Level: "standard", Category: "Customer Rights"},
		{ID: "EUCC-022", Title: "Service Level Agreements", Family: "Customer Rights", Description: "Cloud providers shall define and maintain service level agreements covering availability, performance, security incident response times, and data recovery objectives with measurable metrics and reporting.", Level: "standard", Category: "Customer Rights"},
		{ID: "EUCC-023", Title: "Audit and Compliance Reporting", Family: "Compliance", Description: "Cloud providers shall undergo regular independent audits and provide compliance reports to customers. Audit scope shall cover security controls, data protection, and operational procedures.", Level: "high", Category: "Compliance"},
		{ID: "EUCC-024", Title: "GDPR Compliance Integration", Family: "Compliance", Description: "Cloud services shall support GDPR compliance including data processing agreements, data subject rights fulfillment, breach notification procedures, and data protection impact assessment support.", Level: "critical", Category: "Compliance"},
		{ID: "EUCC-025", Title: "Security Certification Maintenance", Family: "Certification", Description: "EUCC-certified cloud services shall maintain continuous compliance with certification requirements, undergo periodic reassessment, and notify certification bodies of significant changes to services or architecture.", Level: "critical", Category: "Certification"},
		{ID: "EUCC-026", Title: "Customer Security Responsibilities", Family: "Shared Responsibility", Description: "Cloud providers shall clearly define and document the shared responsibility model, specifying security responsibilities of the provider and customer for each service model (IaaS, PaaS, SaaS).", Level: "high", Category: "Shared Responsibility"},
		{ID: "EUCC-027", Title: "Secure Decommissioning", Family: "Lifecycle", Description: "Cloud providers shall implement secure data deletion and media sanitization procedures when customers terminate services or when hardware is decommissioned, using approved data destruction methods.", Level: "high", Category: "Lifecycle"},
		{ID: "EUCC-028", Title: "Threat Intelligence Integration", Family: "Threat Management", Description: "Cloud security operations shall integrate threat intelligence feeds, participate in information sharing communities, and use threat intelligence to enhance detection capabilities and security controls.", Level: "high", Category: "Threat Management"},
		{ID: "EUCC-029", Title: "Security Training and Awareness", Family: "Personnel Security", Description: "Cloud provider personnel shall receive regular security training appropriate to their roles, including secure development practices, incident response procedures, and data handling requirements.", Level: "standard", Category: "Personnel Security"},
		{ID: "EUCC-030", Title: "Background Screening", Family: "Personnel Security", Description: "Cloud provider shall conduct background checks on personnel with access to customer data or critical infrastructure, including criminal history verification and reference checks where legally permitted.", Level: "standard", Category: "Personnel Security"},
		{ID: "EUCC-031", Title: "Key Management Service Security", Family: "Cryptography", Description: "Cloud key management services shall implement hardware security modules (HSMs), key rotation policies, access controls, audit logging, and support for customer-managed encryption keys (BYOK/HYOK).", Level: "critical", Category: "Cryptography"},
		{ID: "EUCC-032", Title: "Secrets Management", Family: "Cryptography", Description: "Cloud services shall provide secure secrets management for API keys, passwords, certificates, and tokens with encryption, access controls, rotation policies, and integration with application deployment pipelines.", Level: "high", Category: "Cryptography"},
		{ID: "EUCC-033", Title: "Security Testing Requirements", Family: "Testing", Description: "Cloud services shall undergo regular security testing including penetration testing, red team exercises, vulnerability assessments, and application security testing with remediation tracking.", Level: "high", Category: "Testing"},
		{ID: "EUCC-034", Title: "Compliance Automation", Family: "Compliance", Description: "Cloud providers shall implement automated compliance monitoring and continuous control assessment capabilities, providing customers with real-time compliance dashboards and evidence collection.", Level: "high", Category: "Compliance"},
		{ID: "EUCC-035", Title: "Cross-Border Data Transfer Security", Family: "Data Protection", Description: "Cloud services shall implement appropriate safeguards for cross-border data transfers including standard contractual clauses, binding corporate rules, and encryption for data in transit between regions.", Level: "critical", Category: "Data Protection"},
		{ID: "EUCC-036", Title: "Service Dependency Management", Family: "Operations", Description: "Cloud providers shall identify, document, and manage dependencies on external services, APIs, and infrastructure. Dependency risk assessments and fallback procedures shall be maintained.", Level: "high", Category: "Operations"},
		{ID: "EUCC-037", Title: "Change Management Security", Family: "Operations", Description: "All changes to cloud infrastructure and services shall follow formal change management processes including risk assessment, approval workflows, testing requirements, rollback procedures, and documentation.", Level: "high", Category: "Operations"},
		{ID: "EUCC-038", Title: "Customer Data Segregation Verification", Family: "Architecture", Description: "Cloud providers shall implement and regularly verify technical controls ensuring customer data segregation through automated testing, independent audits, and customer-accessible verification mechanisms.", Level: "critical", Category: "Architecture"},
		{ID: "EUCC-039", Title: "Secure Customer Portal", Family: "Application Security", Description: "Cloud provider customer portals and management consoles shall implement secure authentication, session management, input validation, CSRF protection, and regular security assessments.", Level: "high", Category: "Application Security"},
		{ID: "EUCC-040", Title: "Telemetry and Metrics Security", Family: "Monitoring", Description: "Cloud telemetry and metrics collection shall be secured against tampering, unauthorized access, and data leakage. Sensitive information shall be excluded from logs and metrics through data classification.", Level: "high", Category: "Monitoring"},
		{ID: "EUCC-041", Title: "Zero Trust Architecture", Family: "Architecture", Description: "Cloud services shall implement zero trust architecture principles including continuous verification, least privilege access, micro-segmentation, and explicit trust evaluation for all access requests.", Level: "high", Category: "Architecture"},
		{ID: "EUCC-042", Title: "Cloud Workload Protection", Family: "Cloud Native", Description: "Cloud workloads shall be protected through runtime security monitoring, behavioral analysis, file integrity monitoring, and automated response to suspicious activities across all deployment models.", Level: "high", Category: "Cloud Native"},
		{ID: "EUCC-043", Title: "Data Classification and Handling", Family: "Data Protection", Description: "Cloud services shall support data classification labels and enforce handling requirements based on classification levels including encryption, access controls, retention policies, and disposal procedures.", Level: "high", Category: "Data Protection"},
		{ID: "EUCC-044", Title: "Security Orchestration and Automation", Family: "Operations", Description: "Cloud security operations shall implement security orchestration, automation, and response (SOAR) capabilities to streamline incident response, threat hunting, and security control management.", Level: "high", Category: "Operations"},
		{ID: "EUCC-045", Title: "Regulatory Compliance Mapping", Family: "Compliance", Description: "Cloud providers shall maintain mappings between EUCC controls and other applicable regulations (GDPR, NIS2, DORA, CRA) to support customers' multi-framework compliance requirements.", Level: "standard", Category: "Compliance"},
		{ID: "EUCC-046", Title: "Sub-processor Management", Family: "Supply Chain", Description: "Cloud providers shall maintain an approved list of sub-processors, conduct security assessments before engagement, and provide customers with notification and objection rights for new sub-processors.", Level: "high", Category: "Supply Chain"},
		{ID: "EUCC-047", Title: "Security Baseline Configuration", Family: "Operations", Description: "Cloud services shall be deployed using security baseline configurations aligned with industry benchmarks (CIS, DISA STIGs) with automated compliance checking and remediation of configuration drift.", Level: "high", Category: "Operations"},
		{ID: "EUCC-048", Title: "Customer Security Self-Assessment", Family: "Customer Rights", Description: "Cloud providers shall provide customers with security self-assessment tools, questionnaires, and documentation to support their own risk assessments and compliance verification activities.", Level: "standard", Category: "Customer Rights"},
		{ID: "EUCC-049", Title: "Security Advisory Notifications", Family: "Communication", Description: "Cloud providers shall maintain security advisory notification systems to inform customers of security vulnerabilities, threats, and recommended actions affecting cloud services or customer workloads.", Level: "high", Category: "Communication"},
		{ID: "EUCC-050", Title: "Certification Scheme Participation", Family: "Certification", Description: "Cloud service providers shall actively participate in the EUCC certification scheme, providing required documentation, evidence, and access to assessors for initial certification and ongoing surveillance.", Level: "critical", Category: "Certification"},
	}

	var result []grc.Control
	for _, ctrl := range controls {
		result = append(result, p.buildControl(ctrl))
	}

	return result
}
