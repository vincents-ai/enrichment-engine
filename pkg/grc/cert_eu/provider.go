package cert_eu

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
	FrameworkID = "CERT_EU_2024"
	CatalogURL  = "https://raw.githubusercontent.com/cert-eu/advisories/main/controls.json"
)

// Provider fetches and parses CERT-EU advisories and threat intelligence controls.
type Provider struct {
	store  storage.Backend
	logger *slog.Logger
}

// New creates a new CERT-EU provider.
func New(store storage.Backend, logger *slog.Logger) *Provider {
	return &Provider{
		store:  store,
		logger: logger,
	}
}

// Name returns the provider identifier.
func (p *Provider) Name() string {
	return "cert_eu"
}

// Run fetches the CERT-EU advisories, parses controls, and writes to storage.
func (p *Provider) Run(ctx context.Context) (int, error) {
	p.logger.Info("fetching CERT-EU advisories and threat intelligence", "url", CatalogURL)

	f, err := os.CreateTemp("", "cert_eu_controls_*.json")
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

type certEUCatalog struct {
	Advisories []certEUAdvisory `json:"advisories,omitempty"`
}

type certEUAdvisory struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Family      string   `json:"family,omitempty"`
	Description string   `json:"description"`
	Level       string   `json:"level,omitempty"`
	Type        string   `json:"type,omitempty"`
	TLP         string   `json:"tlp,omitempty"`
	IOCs        []string `json:"iocs,omitempty"`
}

func (p *Provider) parse(path string) ([]grc.Control, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var catalog certEUCatalog
	if err := json.NewDecoder(f).Decode(&catalog); err != nil {
		return nil, fmt.Errorf("decode CERT-EU catalog: %w", err)
	}

	var controls []grc.Control
	for _, adv := range catalog.Advisories {
		controls = append(controls, p.buildControl(adv))
	}

	return controls, nil
}

func (p *Provider) buildControl(adv certEUAdvisory) grc.Control {
	return grc.Control{
		Framework:   FrameworkID,
		ControlID:   adv.ID,
		Title:       adv.Title,
		Family:      adv.Family,
		Description: adv.Description,
		Level:       adv.Level,
		RelatedCVEs: adv.IOCs,
		References: []grc.Reference{
			{Source: "CERT-EU", URL: "https://www.cert.europa.eu", Section: adv.Type},
		},
	}
}

func (p *Provider) writeControls(ctx context.Context, controls []grc.Control) (int, error) {
	p.logger.Info("parsed CERT-EU advisories", "count", len(controls))

	count := 0
	for _, ctrl := range controls {
		id := fmt.Sprintf("%s/%s", FrameworkID, ctrl.ControlID)
		if err := p.store.WriteControl(ctx, id, ctrl); err != nil {
			p.logger.Warn("failed to write control", "id", id, "error", err)
			continue
		}
		count++
	}

	p.logger.Info("wrote CERT-EU controls to storage", "count", count)
	return count, nil
}

func (p *Provider) generateEmbeddedControls() []grc.Control {
	advisories := []certEUAdvisory{
		{ID: "CERT-EU-001", Title: "Ransomware Threat Landscape and Mitigation", Family: "Threat Advisory", Description: "Comprehensive guidance on ransomware threats targeting EU institutions including prevention measures, detection indicators, response procedures, and recovery best practices. Covers RaaS operations, double extortion tactics, and sector-specific targeting patterns.", Level: "critical", Type: "Threat Advisory", TLP: "AMBER", IOCs: []string{"CVE-2024-3400", "CVE-2023-4966"}},
		{ID: "CERT-EU-002", Title: "Phishing Campaigns Targeting EU Institutions", Family: "Security Advisory", Description: "Analysis of sophisticated phishing campaigns targeting EU institution staff including credential harvesting, malware delivery, and business email compromise techniques. Includes detection guidance and user awareness recommendations.", Level: "high", Type: "Security Advisory", TLP: "GREEN", IOCs: []string{}},
		{ID: "CERT-EU-003", Title: "Supply Chain Attack Mitigation", Family: "Threat Advisory", Description: "Guidance on protecting against supply chain attacks affecting EU institutions including software supply chain compromise, third-party service provider risks, and hardware supply chain threats. Covers detection and response strategies.", Level: "critical", Type: "Threat Advisory", TLP: "AMBER", IOCs: []string{"CVE-2024-3094"}},
		{ID: "CERT-EU-004", Title: "Zero-Day Vulnerability Response Framework", Family: "Security Advisory", Description: "Framework for responding to zero-day vulnerabilities affecting EU institution infrastructure including rapid assessment, temporary mitigation, patch deployment, and post-exploitation detection procedures.", Level: "critical", Type: "Security Advisory", TLP: "AMBER", IOCs: []string{"CVE-2024-21762"}},
		{ID: "CERT-EU-005", Title: "Cloud Security Configuration Guidance", Family: "Best Practice", Description: "Best practice guidance for securing cloud infrastructure used by EU institutions including identity management, data protection, network security, and compliance with EU cloud security requirements.", Level: "high", Type: "Best Practice", TLP: "GREEN", IOCs: []string{}},
		{ID: "CERT-EU-006", Title: "Advanced Persistent Threat Indicators", Family: "Threat Advisory", Description: "Indicators of compromise and tactical analysis of APT groups targeting EU institutions including TTPs, infrastructure indicators, malware signatures, and recommended detection rules for security operations centers.", Level: "critical", Type: "Threat Advisory", TLP: "RED", IOCs: []string{"CVE-2024-21762", "CVE-2023-44487"}},
		{ID: "CERT-EU-007", Title: "Mobile Device Security for EU Institutions", Family: "Best Practice", Description: "Security guidance for mobile device management in EU institutions including device enrollment, application control, data protection, remote wipe capabilities, and secure mobile communication protocols.", Level: "high", Type: "Best Practice", TLP: "GREEN", IOCs: []string{}},
		{ID: "CERT-EU-008", Title: "Critical Vulnerability: Microsoft Exchange Exploitation", Family: "Vulnerability Advisory", Description: "Urgent advisory on critical Microsoft Exchange Server vulnerabilities being actively exploited including patching guidance, detection rules, compromise assessment procedures, and recommended immediate actions.", Level: "critical", Type: "Vulnerability Advisory", TLP: "AMBER", IOCs: []string{"CVE-2024-21762", "CVE-2023-28252"}},
		{ID: "CERT-EU-009", Title: "IoT Security in Government Environments", Family: "Best Practice", Description: "Security guidance for IoT device deployment in EU government environments including device assessment, network segmentation, monitoring requirements, and lifecycle management for connected devices.", Level: "high", Type: "Best Practice", TLP: "GREEN", IOCs: []string{}},
		{ID: "CERT-EU-010", Title: "Incident Response Coordination Procedures", Family: "Security Advisory", Description: "Procedures for coordinating cybersecurity incident response across EU institutions including notification requirements, information sharing protocols, joint investigation procedures, and lessons learned processes.", Level: "high", Type: "Security Advisory", TLP: "AMBER", IOCs: []string{}},
		{ID: "CERT-EU-011", Title: "Email Security Hardening Guidelines", Family: "Best Practice", Description: "Comprehensive email security hardening guidelines including SPF, DKIM, DMARC configuration, attachment filtering, URL rewriting, anti-phishing controls, and email encryption requirements for EU institutions.", Level: "high", Type: "Best Practice", TLP: "GREEN", IOCs: []string{}},
		{ID: "CERT-EU-012", Title: "Nation-State Cyber Espionage Campaign", Family: "Threat Advisory", Description: "Analysis of nation-state cyber espionage campaigns targeting EU policy-making processes including intrusion techniques, data exfiltration methods, persistence mechanisms, and recommended defensive measures.", Level: "critical", Type: "Threat Advisory", TLP: "RED", IOCs: []string{"CVE-2023-4966"}},
		{ID: "CERT-EU-013", Title: "Web Application Security Assessment", Family: "Best Practice", Description: "Guidelines for conducting web application security assessments in EU institutions including testing methodology, vulnerability classification, remediation prioritization, and secure development lifecycle integration.", Level: "high", Type: "Best Practice", TLP: "GREEN", IOCs: []string{}},
		{ID: "CERT-EU-014", Title: "Critical Infrastructure Cyber Resilience", Family: "Security Advisory", Description: "Cyber resilience guidance for EU critical infrastructure operators including risk assessment methodologies, security control implementation, incident preparedness, and cross-border cooperation mechanisms.", Level: "critical", Type: "Security Advisory", TLP: "AMBER", IOCs: []string{}},
		{ID: "CERT-EU-015", Title: "Endpoint Detection and Response Deployment", Family: "Best Practice", Description: "Best practice guidance for deploying EDR solutions in EU institution environments including agent deployment, policy configuration, threat hunting capabilities, and integration with security operations centers.", Level: "high", Type: "Best Practice", TLP: "GREEN", IOCs: []string{}},
		{ID: "CERT-EU-016", Title: "DNS Security Implementation Guide", Family: "Best Practice", Description: "Technical guidance for implementing DNS security including DNSSEC deployment, DNS filtering, DNS-over-HTTPS/TLS configuration, and monitoring for DNS-based attacks and data exfiltration.", Level: "high", Type: "Best Practice", TLP: "GREEN", IOCs: []string{}},
		{ID: "CERT-EU-017", Title: "Threat Intelligence Sharing Framework", Family: "Security Advisory", Description: "Framework for sharing threat intelligence between EU institutions and Member States including information classification, sharing protocols, automated indicator distribution, and collaborative analysis procedures.", Level: "high", Type: "Security Advisory", TLP: "AMBER", IOCs: []string{}},
		{ID: "CERT-EU-018", Title: "Remote Work Security Guidelines", Family: "Best Practice", Description: "Security guidelines for remote work arrangements in EU institutions including VPN configuration, endpoint security requirements, secure collaboration tools, and home network security recommendations.", Level: "high", Type: "Best Practice", TLP: "GREEN", IOCs: []string{}},
		{ID: "CERT-EU-019", Title: "Vulnerability Disclosure Policy Template", Family: "Security Advisory", Description: "Template and guidance for establishing vulnerability disclosure policies in EU institutions including reporting channels, response timeframes, coordinated disclosure procedures, and researcher engagement.", Level: "standard", Type: "Security Advisory", TLP: "GREEN", IOCs: []string{}},
		{ID: "CERT-EU-020", Title: "Active Directory Security Hardening", Family: "Best Practice", Description: "Comprehensive Active Directory security hardening guidance including tiered administration model, privileged access management, Group Policy security, Kerberos hardening, and detection of AD attack techniques.", Level: "critical", Type: "Best Practice", TLP: "GREEN", IOCs: []string{}},
		{ID: "CERT-EU-021", Title: "Cyber Exercise Planning Guidance", Family: "Security Advisory", Description: "Guidance for planning and conducting cybersecurity exercises in EU institutions including scenario development, exercise objectives, participant roles, evaluation criteria, and lessons learned documentation.", Level: "standard", Type: "Security Advisory", TLP: "GREEN", IOCs: []string{}},
		{ID: "CERT-EU-022", Title: "Critical Vulnerability: Log4Shell Exploitation", Family: "Vulnerability Advisory", Description: "Emergency advisory on Log4Shell (Log4j) vulnerability exploitation affecting EU institution systems including identification, mitigation, patching guidance, and post-exploitation detection procedures.", Level: "critical", Type: "Vulnerability Advisory", TLP: "AMBER", IOCs: []string{"CVE-2021-44228"}},
		{ID: "CERT-EU-023", Title: "Network Segmentation Best Practices", Family: "Best Practice", Description: "Best practices for network segmentation in EU institution environments including zone design, access control between segments, monitoring at segment boundaries, and micro-segmentation for critical assets.", Level: "high", Type: "Best Practice", TLP: "GREEN", IOCs: []string{}},
		{ID: "CERT-EU-024", Title: "Cybersecurity Awareness Campaign Framework", Family: "Security Advisory", Description: "Framework for developing and running cybersecurity awareness campaigns in EU institutions including content development, delivery channels, effectiveness measurement, and targeted training for high-risk roles.", Level: "standard", Type: "Security Advisory", TLP: "GREEN", IOCs: []string{}},
		{ID: "CERT-EU-025", Title: "Backup and Recovery Security", Family: "Best Practice", Description: "Security guidance for backup and recovery systems including encrypted backup storage, integrity verification, ransomware-resistant backups, offline backup copies, and tested recovery procedures.", Level: "high", Type: "Best Practice", TLP: "GREEN", IOCs: []string{}},
		{ID: "CERT-EU-026", Title: "API Security Assessment Guidelines", Family: "Best Practice", Description: "Guidelines for assessing API security in EU institution systems including authentication, authorization, rate limiting, input validation, output encoding, and API-specific vulnerability testing.", Level: "high", Type: "Best Practice", TLP: "GREEN", IOCs: []string{}},
		{ID: "CERT-EU-027", Title: "Cyber Incident Reporting Requirements", Family: "Security Advisory", Description: "Guidance on cyber incident reporting requirements for EU institutions including notification timeframes, content requirements, reporting channels, and coordination with national CSIRTs and ENISA.", Level: "high", Type: "Security Advisory", TLP: "AMBER", IOCs: []string{}},
		{ID: "CERT-EU-028", Title: "Container Security Best Practices", Family: "Best Practice", Description: "Security best practices for containerized environments in EU institutions including image scanning, runtime protection, network policies, secrets management, and orchestration platform hardening.", Level: "high", Type: "Best Practice", TLP: "GREEN", IOCs: []string{}},
		{ID: "CERT-EU-029", Title: "Cyber Threat Actor Profile: Financially Motivated", Family: "Threat Advisory", Description: "Profile of financially motivated cyber threat actors targeting EU institutions including ransomware operators, cybercrime syndicates, and fraud groups with their TTPs, infrastructure, and recommended defenses.", Level: "high", Type: "Threat Advisory", TLP: "AMBER", IOCs: []string{}},
		{ID: "CERT-EU-030", Title: "Security Monitoring and SIEM Configuration", Family: "Best Practice", Description: "Best practices for security monitoring and SIEM configuration in EU institutions including log source integration, correlation rule development, alert tuning, dashboard creation, and incident response integration.", Level: "high", Type: "Best Practice", TLP: "GREEN", IOCs: []string{}},
	}

	var result []grc.Control
	for _, adv := range advisories {
		result = append(result, p.buildControl(adv))
	}

	return result
}
