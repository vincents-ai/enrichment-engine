package cen_cenelec_cyber

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
	FrameworkID = "CEN_CENELEC_Cyber_2024"
)

var CatalogURL = "https://raw.githubusercontent.com/cen-cenelec/cybersecurity-standards/main/controls.json"

// Provider fetches and parses CEN-CENELEC cybersecurity standards controls.
type Provider struct {
	store  storage.Backend
	logger *slog.Logger
}

// New creates a new CEN-CENELEC Cybersecurity Standards provider.
func New(store storage.Backend, logger *slog.Logger) *Provider {
	return &Provider{
		store:  store,
		logger: logger,
	}
}

// Name returns the provider identifier.
func (p *Provider) Name() string {
	return "cen_cenelec_cyber"
}

// Run fetches the cybersecurity standards, parses controls, and writes to storage.
func (p *Provider) Run(ctx context.Context) (int, error) {
	p.logger.Info("fetching CEN-CENELEC cybersecurity standards", "url", CatalogURL)

	f, err := os.CreateTemp("", "cen_cenelec_cyber_*.json")
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

type cyberStdCatalog struct {
	Standards []cyberStd `json:"standards,omitempty"`
}

type cyberStd struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Family      string `json:"family,omitempty"`
	Description string `json:"description"`
	Level       string `json:"level,omitempty"`
	StdRef      string `json:"standard_ref,omitempty"`
}

func (p *Provider) parse(path string) ([]grc.Control, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var catalog cyberStdCatalog
	if err := json.NewDecoder(f).Decode(&catalog); err != nil {
		return nil, fmt.Errorf("decode CEN-CENELEC cyber catalog: %w", err)
	}

	var controls []grc.Control
	for _, std := range catalog.Standards {
		controls = append(controls, p.buildControl(std))
	}

	return controls, nil
}

func (p *Provider) buildControl(std cyberStd) grc.Control {
	return grc.Control{
		Framework:   FrameworkID,
		ControlID:   std.ID,
		Title:       std.Title,
		Family:      std.Family,
		Description: std.Description,
		Level:       std.Level,
		References: []grc.Reference{
			{Source: "CEN-CENELEC", URL: "https://standards.cencenelec.eu", Section: std.StdRef},
		},
	}
}

func (p *Provider) writeControls(ctx context.Context, controls []grc.Control) (int, error) {
	p.logger.Info("parsed CEN-CENELEC cyber controls", "count", len(controls))

	count := 0
	for _, ctrl := range controls {
		id := fmt.Sprintf("%s/%s", FrameworkID, ctrl.ControlID)
		if err := p.store.WriteControl(ctx, id, ctrl); err != nil {
			p.logger.Warn("failed to write control", "id", id, "error", err)
			continue
		}
		count++
	}

	p.logger.Info("wrote CEN-CENELEC cyber controls to storage", "count", count)
	return count, nil
}

func (p *Provider) generateEmbeddedControls() []grc.Control {
	standards := []cyberStd{
		{ID: "CC-CYB-01", Title: "Information Security Management System", Family: "EN ISO/IEC 27001 - ISMS", Description: "Requirements for establishing, implementing, maintaining, and continually improving an information security management system (ISMS) within the context of the organization including risk assessment and treatment processes.", Level: "critical", StdRef: "EN ISO/IEC 27001, Clause 4-10"},
		{ID: "CC-CYB-02", Title: "Organizational Context and Leadership", Family: "EN ISO/IEC 27001 - ISMS", Description: "Requirements for understanding organizational context, identifying interested parties, defining ISMS scope, and demonstrating leadership commitment to information security management.", Level: "high", StdRef: "EN ISO/IEC 27001, Clause 4-5"},
		{ID: "CC-CYB-03", Title: "Information Security Risk Assessment", Family: "EN ISO/IEC 27001 - ISMS", Description: "Requirements for systematic information security risk assessment including risk identification, analysis, evaluation, and treatment planning aligned with organizational risk criteria.", Level: "critical", StdRef: "EN ISO/IEC 27001, Clause 6.1.2"},
		{ID: "CC-CYB-04", Title: "Information Security Controls", Family: "EN ISO/IEC 27001 Annex A", Description: "Implementation of information security controls covering organizational, people, physical, and technological aspects including access control, cryptography, operations security, and communications security.", Level: "critical", StdRef: "EN ISO/IEC 27001, Annex A"},
		{ID: "CC-CYB-05", Title: "Risk Management Guidelines", Family: "EN ISO 31000 - Risk Management", Description: "Guidelines for risk management including principles, framework, and process for managing risks faced by organizations. Applicable to cybersecurity risk management within the broader organizational risk context.", Level: "high", StdRef: "EN ISO 31000, Clause 5-7"},
		{ID: "CC-CYB-06", Title: "Cybersecurity Risk Assessment Methodology", Family: "EN ISO/IEC 27005 - Cyber Risk", Description: "Guidelines for information security risk management providing a structured approach to identifying, analyzing, evaluating, and treating information security risks in organizations.", Level: "critical", StdRef: "EN ISO/IEC 27005, Clause 6-8"},
		{ID: "CC-CYB-07", Title: "Incident Management Process", Family: "EN ISO/IEC 27035 - Incident Management", Description: "Requirements for information security incident management including incident detection, reporting, assessment, response, learning, and improvement processes aligned with organizational objectives.", Level: "critical", StdRef: "EN ISO/IEC 27035, Part 1"},
		{ID: "CC-CYB-08", Title: "Digital Forensics Guidelines", Family: "EN ISO/IEC 27037 - Digital Evidence", Description: "Guidelines for identification, collection, acquisition, and preservation of digital evidence ensuring integrity and admissibility in legal proceedings following cybersecurity incidents.", Level: "high", StdRef: "EN ISO/IEC 27037, Clause 6-8"},
		{ID: "CC-CYB-09", Title: "Business Continuity Management", Family: "EN ISO 22301 - BCM", Description: "Requirements for establishing, implementing, and maintaining a business continuity management system to prepare for, respond to, and recover from disruptive incidents affecting critical operations.", Level: "critical", StdRef: "EN ISO 22301, Clause 4-10"},
		{ID: "CC-CYB-10", Title: "IT Service Continuity", Family: "EN ISO/IEC 20000-1 - IT Service", Description: "Requirements for IT service management including service continuity management, availability management, and capacity management to ensure IT services meet business requirements during disruptions.", Level: "high", StdRef: "EN ISO/IEC 20000-1, Clause 8.6"},
		{ID: "CC-CYB-11", Title: "Privacy by Design", Family: "EN ISO/IEC 27701 - Privacy", Description: "Requirements for extending ISMS to include privacy information management, implementing privacy by design and by default principles, and demonstrating GDPR compliance through certified management systems.", Level: "critical", StdRef: "EN ISO/IEC 27701, Clause 6-7"},
		{ID: "CC-CYB-12", Title: "Cloud Service Security", Family: "EN ISO/IEC 27017 - Cloud Security", Description: "Code of practice for information security controls specific to cloud services, providing additional guidance on implementing ISO/IEC 27002 controls in cloud computing environments.", Level: "high", StdRef: "EN ISO/IEC 27017, Clause 7-14"},
		{ID: "CC-CYB-13", Title: "PII Protection in Cloud Services", Family: "EN ISO/IEC 27018 - Cloud Privacy", Description: "Code of practice for protecting personally identifiable information (PII) in public cloud computing environments, providing guidance for cloud service providers acting as PII processors.", Level: "high", StdRef: "EN ISO/IEC 27018, Clause 7-11"},
		{ID: "CC-CYB-14", Title: "Application Security Requirements", Family: "EN ISO/IEC 27034 - Application Security", Description: "Framework for managing application security including security requirements definition, security control selection, implementation verification, and ongoing security monitoring throughout the application lifecycle.", Level: "high", StdRef: "EN ISO/IEC 27034, Part 1"},
		{ID: "CC-CYB-15", Title: "Secure Software Development", Family: "EN ISO/IEC 27034 - Application Security", Description: "Guidelines for integrating security into the software development lifecycle including secure coding practices, security testing, code review, and vulnerability management during development.", Level: "high", StdRef: "EN ISO/IEC 27034, Part 2"},
		{ID: "CC-CYB-16", Title: "Network Security Architecture", Family: "EN ISO/IEC 27011 - Telecom Security", Description: "Information security management guidelines for telecommunications organizations including network security architecture, service security, and protection of telecommunications infrastructure.", Level: "high", StdRef: "EN ISO/IEC 27011, Clause 7-10"},
		{ID: "CC-CYB-17", Title: "Supply Chain Security Management", Family: "EN ISO/IEC 27036 - Supplier Security", Description: "Guidelines for information security for supplier relationships including security requirements for suppliers, risk assessment of supplier relationships, and ongoing monitoring of supplier security posture.", Level: "high", StdRef: "EN ISO/IEC 27036, Part 1-4"},
		{ID: "CC-CYB-18", Title: "ICT Supply Chain Risk Management", Family: "EN ISO/IEC 27036-4 - Cloud Suppliers", Description: "Specific guidelines for security of cloud service supplier relationships including assessment of cloud providers, contractual security requirements, and ongoing monitoring of cloud service security.", Level: "high", StdRef: "EN ISO/IEC 27036-4, Clause 6-9"},
		{ID: "CC-CYB-19", Title: "Security Testing Methodology", Family: "EN ISO/IEC 29119 - Software Testing", Description: "Software testing standards including security testing processes, documentation, and techniques for identifying vulnerabilities and verifying security controls in software applications.", Level: "high", StdRef: "EN ISO/IEC 29119, Part 4"},
		{ID: "CC-CYB-20", Title: "Vulnerability Disclosure Framework", Family: "EN ISO/IEC 29147 - Vulnerability Disclosure", Description: "Framework for vulnerability disclosure providing guidance on establishing vulnerability handling processes, coordinated disclosure procedures, and communication with vulnerability finders.", Level: "high", StdRef: "EN ISO/IEC 29147, Clause 5-7"},
		{ID: "CC-CYB-21", Title: "Vulnerability Handling Process", Family: "EN ISO/IEC 30111 - Vulnerability Handling", Description: "Process for handling reported vulnerabilities including triage, analysis, remediation development, testing, and coordinated release of patches and security advisories.", Level: "critical", StdRef: "EN ISO/IEC 30111, Clause 5-8"},
		{ID: "CC-CYB-22", Title: "Penetration Testing Requirements", Family: "EN ISO/IEC 29119-4 - Penetration Testing", Description: "Requirements for penetration testing including test planning, execution methodology, reporting, and remediation verification. Covers both internal and external penetration testing approaches.", Level: "high", StdRef: "EN ISO/IEC 29119-4, Clause 6-8"},
		{ID: "CC-CYB-23", Title: "Privacy Impact Assessment", Family: "EN ISO/IEC 29134 - PIA Guidelines", Description: "Guidelines for conducting privacy impact assessments including identification of privacy risks, assessment of risk likelihood and impact, and selection of privacy controls to mitigate identified risks.", Level: "high", StdRef: "EN ISO/IEC 29134, Clause 6-8"},
		{ID: "CC-CYB-24", Title: "Anonymization and Pseudonymization", Family: "EN ISO/IEC 20889 - Privacy Enhancing", Description: "Framework for privacy-enhancing technologies including anonymization and pseudonymization techniques, re-identification risk assessment, and selection of appropriate privacy protection methods.", Level: "high", StdRef: "EN ISO/IEC 20889, Clause 5-7"},
		{ID: "CC-CYB-25", Title: "Security Metrics and Measurement", Family: "EN ISO/IEC 27004 - Security Measurement", Description: "Guidelines for monitoring, measuring, analyzing, and evaluating the information security management system and controls to determine effectiveness and support continual improvement.", Level: "standard", StdRef: "EN ISO/IEC 27004, Clause 6-8"},
		{ID: "CC-CYB-26", Title: "Security Awareness and Training", Family: "EN ISO/IEC 27002 - Security Controls", Description: "Implementation guidance for security awareness, training, and education programs including role-based training requirements, effectiveness measurement, and ongoing awareness campaign management.", Level: "high", StdRef: "EN ISO/IEC 27002, Clause 6.3"},
		{ID: "CC-CYB-27", Title: "Cryptographic Controls", Family: "EN ISO/IEC 27002 - Cryptography", Description: "Implementation guidance for cryptographic controls including encryption key management, cryptographic algorithm selection, use of digital signatures, and protection of cryptographic keys.", Level: "critical", StdRef: "EN ISO/IEC 27002, Clause 8.24"},
		{ID: "CC-CYB-28", Title: "Secure System Architecture", Family: "EN ISO/IEC 27002 - Architecture", Description: "Implementation guidance for secure system architecture including security engineering principles, secure development environments, system hardening, and secure configuration management.", Level: "high", StdRef: "EN ISO/IEC 27002, Clause 8"},
		{ID: "CC-CYB-29", Title: "Threat Intelligence Sharing", Family: "EN ISO/IEC 27035-3 - Threat Intel", Description: "Guidelines for operational threat intelligence including collection, analysis, and sharing of threat information to support incident detection, response, and prevention activities.", Level: "high", StdRef: "EN ISO/IEC 27035-3, Clause 5-7"},
		{ID: "CC-CYB-30", Title: "Security Governance Framework", Family: "EN ISO/IEC 38505 - IT Governance", Description: "Guidelines for governance of IT security including principles for directing, evaluating, and monitoring information security management to achieve organizational objectives and regulatory compliance.", Level: "high", StdRef: "EN ISO/IEC 38505, Clause 5-7"},
	}

	var controls []grc.Control
	for _, std := range standards {
		controls = append(controls, p.buildControl(std))
	}

	return controls
}
