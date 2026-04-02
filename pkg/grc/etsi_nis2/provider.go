package etsi_nis2

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"

	"github.com/shift/enrichment-engine/pkg/grc"
	"github.com/shift/enrichment-engine/pkg/storage"
)

const (
	FrameworkID = "ETSI_TR_104_168"
	CatalogURL  = "https://raw.githubusercontent.com/etsi-standards/nis2-controls/main/controls.json"
)

// Provider fetches and parses ETSI TR 104 168 NIS2 critical security controls.
type Provider struct {
	store  storage.Backend
	logger *slog.Logger
}

// New creates a new ETSI NIS2 Controls provider.
func New(store storage.Backend, logger *slog.Logger) *Provider {
	return &Provider{
		store:  store,
		logger: logger,
	}
}

// Name returns the provider identifier.
func (p *Provider) Name() string {
	return "etsi_nis2"
}

// Run fetches the NIS2 controls, parses them, and writes to storage.
func (p *Provider) Run(ctx context.Context) (int, error) {
	p.logger.Info("fetching ETSI NIS2 critical security controls", "url", CatalogURL)

	f, err := os.CreateTemp("", "etsi_nis2_controls_*.json")
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

type nis2Catalog struct {
	Controls []nis2Control `json:"controls,omitempty"`
}

type nis2Control struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Family      string `json:"family,omitempty"`
	Description string `json:"description"`
	Level       string `json:"level,omitempty"`
	NIS2Article string `json:"nis2_article,omitempty"`
}

func (p *Provider) parse(path string) ([]grc.Control, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var catalog nis2Catalog
	if err := json.NewDecoder(f).Decode(&catalog); err != nil {
		return nil, fmt.Errorf("decode NIS2 catalog: %w", err)
	}

	var controls []grc.Control
	for _, ctrl := range catalog.Controls {
		controls = append(controls, p.buildControl(ctrl))
	}

	return controls, nil
}

func (p *Provider) buildControl(ctrl nis2Control) grc.Control {
	return grc.Control{
		Framework:              FrameworkID,
		ControlID:              ctrl.ID,
		Title:                  ctrl.Title,
		Family:                 ctrl.Family,
		Description:            ctrl.Description,
		Level:                  ctrl.Level,
		ImplementationGuidance: fmt.Sprintf("NIS2 Directive Article %s", ctrl.NIS2Article),
		References: []grc.Reference{
			{Source: "ETSI TR 104 168", URL: "https://www.etsi.org/deliver/etsi_tr/104100_104199/104168", Section: ctrl.NIS2Article},
		},
	}
}

func (p *Provider) writeControls(ctx context.Context, controls []grc.Control) (int, error) {
	p.logger.Info("parsed ETSI NIS2 controls", "count", len(controls))

	count := 0
	for _, ctrl := range controls {
		id := fmt.Sprintf("%s/%s", FrameworkID, ctrl.ControlID)
		if err := p.store.WriteControl(ctx, id, ctrl); err != nil {
			p.logger.Warn("failed to write control", "id", id, "error", err)
			continue
		}
		count++
	}

	p.logger.Info("wrote ETSI NIS2 controls to storage", "count", count)
	return count, nil
}

func (p *Provider) generateEmbeddedControls() []grc.Control {
	controls := []nis2Control{
		{ID: "NIS2-01", Title: "Risk Analysis and Information System Security Policies", Family: "Risk Management", Description: "Entities shall implement risk analysis processes and establish information system security policies covering all aspects of information security including asset management, access control, cryptography, and incident management.", Level: "critical", NIS2Article: "21(2)(a)"},
		{ID: "NIS2-02", Title: "Incident Handling", Family: "Incident Management", Description: "Entities shall establish incident handling procedures including detection, analysis, containment, eradication, and recovery. Incident response plans shall be tested regularly and updated based on lessons learned.", Level: "critical", NIS2Article: "21(2)(b)"},
		{ID: "NIS2-03", Title: "Business Continuity and Crisis Management", Family: "Business Continuity", Description: "Entities shall implement business continuity management including backup management, disaster recovery, and crisis management procedures. Critical functions shall be identified with defined recovery time objectives.", Level: "critical", NIS2Article: "21(2)(c)"},
		{ID: "NIS2-04", Title: "Supply Chain Security", Family: "Supply Chain", Description: "Entities shall address security of their supply chain and relationships with direct suppliers including assessment of supplier security practices, contractual security requirements, and continuous monitoring.", Level: "high", NIS2Article: "21(2)(d)"},
		{ID: "NIS2-05", Title: "Security in Network and Information Systems Acquisition", Family: "Acquisition Security", Description: "Entities shall implement security requirements in the acquisition, development, and maintenance of network and information systems including security-by-design and security-by-default principles.", Level: "high", NIS2Article: "21(2)(e)"},
		{ID: "NIS2-06", Title: "Policies and Procedures for Cryptography", Family: "Cryptography", Description: "Entities shall establish policies and procedures for the effective use of cryptography and encryption including algorithm selection, key management, and cryptographic module validation.", Level: "high", NIS2Article: "21(2)(f)"},
		{ID: "NIS2-07", Title: "Human Resources Security and Access Control", Family: "Access Control", Description: "Entities shall implement human resources security policies including background checks, security awareness training, and role-based access control policies with principle of least privilege enforcement.", Level: "high", NIS2Article: "21(2)(g)"},
		{ID: "NIS2-08", Title: "Asset Management and Classification", Family: "Asset Management", Description: "Entities shall maintain comprehensive inventories of information assets and associated processing systems. Assets shall be classified according to sensitivity and criticality with appropriate protection measures.", Level: "high", NIS2Article: "21(2)(a)"},
		{ID: "NIS2-09", Title: "Multi-Factor Authentication", Family: "Access Control", Description: "Entities shall implement multi-factor authentication for access to critical systems, remote access, and privileged accounts. Continuous or step-up authentication shall be considered for high-risk transactions.", Level: "critical", NIS2Article: "21(2)(g)"},
		{ID: "NIS2-10", Title: "Vulnerability Handling and Disclosure", Family: "Vulnerability Management", Description: "Entities shall implement vulnerability management processes including regular scanning, assessment, prioritization, and remediation. Coordinated vulnerability disclosure policies shall be established.", Level: "critical", NIS2Article: "21(2)(b)"},
		{ID: "NIS2-11", Title: "Basic Computer Hygiene and Patch Management", Family: "Vulnerability Management", Description: "Entities shall maintain basic computer hygiene practices including regular patching, software updates, configuration management, and removal of unsupported systems from production environments.", Level: "critical", NIS2Article: "21(2)(e)"},
		{ID: "NIS2-12", Title: "Incident Notification Requirements", Family: "Incident Management", Description: "Entities shall notify competent authorities of significant incidents without undue delay and within 24 hours of becoming aware. Early warning, incident notification, and final reports shall be submitted as required.", Level: "critical", NIS2Article: "23"},
		{ID: "NIS2-13", Title: "Early Warning Notification", Family: "Incident Management", Description: "Entities shall provide an early warning notification within 24 hours of becoming aware of a significant incident, including initial assessment and indicators of compromise where available.", Level: "high", NIS2Article: "23(3)(a)"},
		{ID: "NIS2-14", Title: "Incident Notification Details", Family: "Incident Management", Description: "Entities shall submit detailed incident notifications within 72 hours including severity assessment, indicators of compromise, impact assessment, and mitigation measures already applied.", Level: "high", NIS2Article: "23(3)(b)"},
		{ID: "NIS2-15", Title: "Final Incident Report", Family: "Incident Management", Description: "Entities shall submit final incident reports within one month including detailed description of the incident, root cause analysis, impact assessment, and applied and planned mitigation measures.", Level: "high", NIS2Article: "23(3)(c)"},
		{ID: "NIS2-16", Title: "Security Awareness and Training", Family: "Personnel Security", Description: "Entities shall provide regular cybersecurity awareness training and specialized training for personnel with access to critical systems. Training shall cover threat recognition, incident reporting, and secure practices.", Level: "high", NIS2Article: "21(2)(g)"},
		{ID: "NIS2-17", Title: "Management Body Accountability", Family: "Governance", Description: "The management body of the entity shall approve cybersecurity risk management measures and oversee their implementation. Management body members shall receive regular training on cybersecurity risks.", Level: "critical", NIS2Article: "20"},
		{ID: "NIS2-18", Title: "Security Testing and Assessment", Family: "Testing", Description: "Entities shall conduct regular security testing including vulnerability assessments, penetration testing, and security audits. Testing frequency shall be proportionate to the entity's risk profile and criticality.", Level: "high", NIS2Article: "21(2)(b)"},
		{ID: "NIS2-19", Title: "Encryption of Data at Rest and in Transit", Family: "Cryptography", Description: "Entities shall encrypt sensitive data both at rest and in transit using approved cryptographic algorithms and protocols. Key management shall follow established standards for generation, storage, and rotation.", Level: "critical", NIS2Article: "21(2)(f)"},
		{ID: "NIS2-20", Title: "Network Segmentation", Family: "Network Security", Description: "Entities shall implement network segmentation to isolate critical systems and limit lateral movement in case of compromise. Network boundaries shall be monitored and controlled with appropriate security controls.", Level: "high", NIS2Article: "21(2)(a)"},
		{ID: "NIS2-21", Title: "Logging and Monitoring", Family: "Monitoring", Description: "Entities shall implement comprehensive logging and monitoring of security events including authentication attempts, configuration changes, and anomalous activities. Logs shall be protected and retained for forensic analysis.", Level: "high", NIS2Article: "21(2)(b)"},
		{ID: "NIS2-22", Title: "Backup Management", Family: "Business Continuity", Description: "Entities shall implement regular backup procedures for critical data and systems with encrypted storage, integrity verification, and tested recovery processes. Backups shall be stored separately from primary systems.", Level: "high", NIS2Article: "21(2)(c)"},
		{ID: "NIS2-23", Title: "Third-Party Risk Management", Family: "Supply Chain", Description: "Entities shall assess and manage cybersecurity risks from third-party service providers including cloud services, managed security providers, and critical suppliers through contractual requirements and monitoring.", Level: "high", NIS2Article: "21(2)(d)"},
		{ID: "NIS2-24", Title: "Secure Development Practices", Family: "Acquisition Security", Description: "Entities developing software shall implement secure development lifecycle practices including threat modelling, code review, security testing, and vulnerability management throughout the development process.", Level: "high", NIS2Article: "21(2)(e)"},
		{ID: "NIS2-25", Title: "Security Information Sharing", Family: "Cooperation", Description: "Entities shall participate in information sharing arrangements such as ISACs to receive and contribute threat intelligence, best practices, and lessons learned to improve collective cybersecurity posture.", Level: "standard", NIS2Article: "29"},
		{ID: "NIS2-26", Title: "Physical Security Controls", Family: "Physical Security", Description: "Entities shall implement physical security controls for critical infrastructure including access control systems, surveillance, environmental monitoring, and protection against natural disasters and physical tampering.", Level: "high", NIS2Article: "21(2)(a)"},
		{ID: "NIS2-27", Title: "Remote Access Security", Family: "Access Control", Description: "Remote access to critical systems shall be secured through multi-factor authentication, encrypted connections, session monitoring, and time-limited access grants. Privileged remote access shall require additional controls.", Level: "critical", NIS2Article: "21(2)(g)"},
		{ID: "NIS2-28", Title: "Endpoint Protection", Family: "Endpoint Security", Description: "Entities shall deploy endpoint protection solutions including antivirus, host-based firewalls, application whitelisting, and device control on all endpoints accessing critical systems and networks.", Level: "high", NIS2Article: "21(2)(e)"},
		{ID: "NIS2-29", Title: "Security Architecture Review", Family: "Architecture", Description: "Entities shall conduct regular reviews of their security architecture to ensure alignment with business requirements, threat landscape evolution, and regulatory obligations. Architecture changes shall follow change management processes.", Level: "high", NIS2Article: "21(2)(a)"},
		{ID: "NIS2-30", Title: "Compliance Monitoring and Reporting", Family: "Compliance", Description: "Entities shall implement continuous compliance monitoring to verify adherence to NIS2 requirements and national implementing measures. Regular compliance reports shall be provided to management and supervisory authorities.", Level: "high", NIS2Article: "21"},
		{ID: "NIS2-31", Title: "Email Security", Family: "Network Security", Description: "Entities shall implement email security controls including spam filtering, phishing detection, attachment scanning, URL filtering, and email authentication (SPF, DKIM, DMARC) to prevent email-based attacks.", Level: "high", NIS2Article: "21(2)(e)"},
		{ID: "NIS2-32", Title: "DNS Security", Family: "Network Security", Description: "Entities shall implement DNS security measures including DNSSEC validation, DNS filtering for malicious domains, monitoring for DNS anomalies, and protection against DNS-based attacks such as tunneling and amplification.", Level: "high", NIS2Article: "21(2)(e)"},
		{ID: "NIS2-33", Title: "Privileged Access Management", Family: "Access Control", Description: "Entities shall implement privileged access management including just-in-time access, session recording, approval workflows, and separation of duties for administrative accounts with elevated privileges.", Level: "critical", NIS2Article: "21(2)(g)"},
		{ID: "NIS2-34", Title: "Security Metrics and KPIs", Family: "Governance", Description: "Entities shall define and track security metrics and key performance indicators to measure the effectiveness of cybersecurity risk management measures and demonstrate compliance to supervisory authorities.", Level: "standard", NIS2Article: "21"},
		{ID: "NIS2-35", Title: "Threat Intelligence Integration", Family: "Threat Management", Description: "Entities shall integrate threat intelligence into security operations including threat feeds, vulnerability databases, and sector-specific threat information to enhance detection and response capabilities.", Level: "high", NIS2Article: "21(2)(b)"},
		{ID: "NIS2-36", Title: "Security Orchestration and Automation", Family: "Operations", Description: "Entities shall implement security orchestration and automation to streamline incident response, vulnerability management, and compliance monitoring processes while reducing manual effort and response times.", Level: "high", NIS2Article: "21(2)(b)"},
		{ID: "NIS2-37", Title: "Data Loss Prevention", Family: "Data Protection", Description: "Entities shall implement data loss prevention controls including content inspection, endpoint DLP, network DLP, and cloud DLP to prevent unauthorized exfiltration of sensitive and regulated data.", Level: "high", NIS2Article: "21(2)(f)"},
		{ID: "NIS2-38", Title: "Security Governance Framework", Family: "Governance", Description: "Entities shall establish a comprehensive security governance framework including policies, standards, procedures, and guidelines aligned with recognized frameworks and tailored to the entity's risk profile.", Level: "high", NIS2Article: "21"},
		{ID: "NIS2-39", Title: "Penetration Testing Requirements", Family: "Testing", Description: "Entities shall conduct regular penetration testing of critical systems and networks by qualified independent assessors. Penetration testing scope shall cover external and internal attack vectors with remediation tracking.", Level: "high", NIS2Article: "21(2)(b)"},
		{ID: "NIS2-40", Title: "Regulatory Cooperation and Supervision", Family: "Compliance", Description: "Entities shall cooperate with competent authorities and CSIRTs including providing requested information, participating in supervisory activities, and implementing corrective measures within specified timeframes.", Level: "high", NIS2Article: "32"},
	}

	var result []grc.Control
	for _, ctrl := range controls {
		result = append(result, p.buildControl(ctrl))
	}

	return result
}
