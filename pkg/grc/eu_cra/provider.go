package eu_cra

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"

	"github.com/shift/enrichment-engine/pkg/grc"
	"github.com/shift/enrichment-engine/pkg/storage"
)

const (
	FrameworkID = "EU_CRA_2024_2847"
	CatalogURL  = "https://raw.githubusercontent.com/eu-cra/cyber-resilience-act/main/requirements.json"
)

// Provider fetches and parses EU Cyber Resilience Act (CRA) requirements.
type Provider struct {
	store  storage.Backend
	logger *slog.Logger
}

// New creates a new EU CRA provider.
func New(store storage.Backend, logger *slog.Logger) *Provider {
	return &Provider{
		store:  store,
		logger: logger,
	}
}

// Name returns the provider identifier.
func (p *Provider) Name() string {
	return "eu_cra"
}

// Run fetches the CRA requirements, parses controls, and writes them to storage.
func (p *Provider) Run(ctx context.Context) (int, error) {
	p.logger.Info("fetching EU Cyber Resilience Act requirements", "url", CatalogURL)

	destPath := filepath.Join(os.TempDir(), "eu_cra_requirements.json")
	if err := p.download(ctx, CatalogURL, destPath); err != nil {
		p.logger.Warn("download failed, falling back to embedded requirements", "error", err)
		controls := p.generateEmbeddedControls()
		return p.writeControls(ctx, controls)
	}
	defer os.Remove(destPath)

	controls, err := p.parse(destPath)
	if err != nil {
		p.logger.Warn("parse failed, falling back to embedded requirements", "error", err)
		controls = p.generateEmbeddedControls()
	}

	return p.writeControls(ctx, controls)
}

func (p *Provider) download(ctx context.Context, url, dest string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = io.Copy(f, resp.Body)
	return err
}

type craCatalog struct {
	Requirements []craRequirement `json:"requirements,omitempty"`
	AnnexI       []craRequirement `json:"annex_i,omitempty"`
	AnnexII      []craRequirement `json:"annex_ii,omitempty"`
}

type craRequirement struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Family      string `json:"family,omitempty"`
	Description string `json:"description"`
	Level       string `json:"level,omitempty"`
	Annex       string `json:"annex,omitempty"`
	Category    string `json:"category,omitempty"`
}

func (p *Provider) parse(path string) ([]grc.Control, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var catalog craCatalog
	if err := json.NewDecoder(f).Decode(&catalog); err != nil {
		return nil, fmt.Errorf("decode CRA catalog: %w", err)
	}

	var controls []grc.Control
	for _, req := range catalog.Requirements {
		controls = append(controls, p.buildControl(req))
	}
	for _, req := range catalog.AnnexI {
		req.Family = "Annex I - Essential Requirements"
		controls = append(controls, p.buildControl(req))
	}
	for _, req := range catalog.AnnexII {
		req.Family = "Annex II - Critical Categories"
		controls = append(controls, p.buildControl(req))
	}

	return controls, nil
}

func (p *Provider) buildControl(req craRequirement) grc.Control {
	level := req.Level
	if level == "" {
		switch req.Annex {
		case "II":
			level = "critical"
		default:
			level = "high"
		}
	}

	return grc.Control{
		Framework:   FrameworkID,
		ControlID:   req.ID,
		Title:       req.Title,
		Family:      req.Family,
		Description: req.Description,
		Level:       level,
		References: []grc.Reference{
			{Source: "EU CRA", URL: "https://digital-strategy.ec.europa.eu/en/policies/cyber-resilience-act", Section: fmt.Sprintf("Annex %s", req.Annex)},
		},
	}
}

func (p *Provider) writeControls(ctx context.Context, controls []grc.Control) (int, error) {
	p.logger.Info("parsed CRA requirements", "count", len(controls))

	count := 0
	for _, ctrl := range controls {
		id := fmt.Sprintf("%s/%s", FrameworkID, ctrl.ControlID)
		if err := p.store.WriteControl(ctx, id, ctrl); err != nil {
			p.logger.Warn("failed to write control", "id", id, "error", err)
			continue
		}
		count++
	}

	p.logger.Info("wrote CRA controls to storage", "count", count)
	return count, nil
}

func (p *Provider) generateEmbeddedControls() []grc.Control {
	requirements := []craRequirement{
		{ID: "A1-1", Title: "Secure by Design", Family: "Annex I - Essential Requirements", Description: "Products with digital elements shall be designed, developed, and produced in a manner that ensures an appropriate level of cybersecurity based on the risks. Security shall be integrated from the earliest design and development stages, following security-by-design principles.", Level: "critical", Annex: "I"},
		{ID: "A1-2", Title: "Secure by Default", Family: "Annex I - Essential Requirements", Description: "Products with digital elements shall be made available on the market without any known exploitable vulnerabilities. Default configurations shall be secure, and users shall not be required to change settings to achieve a secure baseline.", Level: "critical", Annex: "I"},
		{ID: "A1-3", Title: "Access Control Mechanisms", Family: "Annex I - Essential Requirements", Description: "Products shall implement appropriate access control mechanisms to prevent unauthorized access to data, functions, and system resources. Authentication shall be required for privileged operations and sensitive data access.", Level: "high", Annex: "I"},
		{ID: "A1-4", Title: "Data Protection", Family: "Annex I - Essential Requirements", Description: "Products shall protect stored, transmitted, and processed data against unauthorized access, modification, and destruction. Encryption shall be applied to sensitive data at rest and in transit using industry-standard algorithms.", Level: "critical", Annex: "I"},
		{ID: "A1-5", Title: "Vulnerability Handling", Family: "Annex I - Essential Requirements", Description: "Manufacturers shall establish and maintain a vulnerability handling process including identification, tracking, and remediation of security vulnerabilities. A coordinated vulnerability disclosure policy shall be implemented.", Level: "high", Annex: "I"},
		{ID: "A1-6", Title: "Security Updates", Family: "Annex I - Essential Requirements", Description: "Manufacturers shall provide security updates for the expected product lifetime or a minimum of five years. Updates shall be delivered in a secure and timely manner, with clear documentation of addressed vulnerabilities.", Level: "critical", Annex: "I"},
		{ID: "A1-7", Title: "Integrity Verification", Family: "Annex I - Essential Requirements", Description: "Products shall verify the integrity of firmware, software, and configuration data before execution. Tamper detection mechanisms shall be implemented to identify unauthorized modifications.", Level: "high", Annex: "I"},
		{ID: "A1-8", Title: "Logging and Monitoring", Family: "Annex I - Essential Requirements", Description: "Products shall record security-relevant events including authentication attempts, configuration changes, and detected anomalies. Logs shall be protected against unauthorized modification and accessible for forensic analysis.", Level: "high", Annex: "I"},
		{ID: "A1-9", Title: "Network Security", Family: "Annex I - Essential Requirements", Description: "Products connected to networks shall implement appropriate network security controls including firewalls, intrusion detection, and secure communication protocols. Network segmentation shall be supported.", Level: "high", Annex: "I"},
		{ID: "A1-10", Title: "Cryptographic Requirements", Family: "Annex I - Essential Requirements", Description: "Products shall use cryptographic algorithms and protocols that are recognized as secure by current standards. Key management shall follow established best practices for generation, storage, rotation, and destruction.", Level: "critical", Annex: "I"},
		{ID: "A2-1", Title: "Risk Assessment", Family: "Annex I - Essential Requirements", Description: "Manufacturers shall conduct a cybersecurity risk assessment for each product with digital elements, identifying threats, vulnerabilities, and potential impacts. Risk assessments shall be updated throughout the product lifecycle.", Level: "high", Annex: "I"},
		{ID: "A2-2", Title: "Security Documentation", Family: "Annex I - Essential Requirements", Description: "Manufacturers shall provide comprehensive security documentation including security architecture, threat model, security features, and user guidance. Documentation shall be kept current with product updates.", Level: "standard", Annex: "I"},
		{ID: "A2-3", Title: "Supply Chain Security", Family: "Annex I - Essential Requirements", Description: "Manufacturers shall ensure cybersecurity throughout the supply chain, including assessment of third-party components, software bill of materials (SBOM), and supplier security requirements.", Level: "high", Annex: "I"},
		{ID: "B1-1", Title: "Operating Systems", Family: "Annex II - Critical Categories", Description: "General-purpose and real-time operating systems shall implement mandatory access controls, memory protection, secure boot, and isolated execution environments. Kernel-level security controls shall be enforced.", Level: "critical", Annex: "II"},
		{ID: "B1-2", Title: "Identity Management Systems", Family: "Annex II - Critical Categories", Description: "Identity and access management systems shall support multi-factor authentication, federated identity, privilege management, and secure credential storage. Integration with enterprise directory services shall be supported.", Level: "critical", Annex: "II"},
		{ID: "B1-3", Title: "Firewalls and IDS/IPS", Family: "Annex II - Critical Categories", Description: "Network security devices including firewalls, intrusion detection, and intrusion prevention systems shall provide deep packet inspection, threat intelligence integration, and automated response capabilities.", Level: "critical", Annex: "II"},
		{ID: "B1-4", Title: "Physical Access Control", Family: "Annex II - Critical Categories", Description: "Physical and electronic access control systems shall implement multi-factor authentication, audit logging, and tamper detection. Integration with identity management systems shall be supported.", Level: "high", Annex: "II"},
		{ID: "B1-5", Title: "Smart Card and Secure Elements", Family: "Annex II - Critical Categories", Description: "Smart cards, secure elements, and trusted platform modules shall provide hardware-based cryptographic operations, secure key storage, and tamper-resistant execution environments.", Level: "critical", Annex: "II"},
		{ID: "B1-6", Title: "Virtualization and Container Security", Family: "Annex II - Critical Categories", Description: "Virtualization platforms and container runtimes shall provide isolation between workloads, secure image verification, runtime protection, and compliance with cloud security standards.", Level: "high", Annex: "II"},
		{ID: "B1-7", Title: "Encryption Solutions", Family: "Annex II - Critical Categories", Description: "Encryption products and solutions shall implement approved cryptographic algorithms, secure key management, and protection against side-channel attacks. Post-quantum cryptographic readiness shall be considered.", Level: "critical", Annex: "II"},
		{ID: "B1-8", Title: "Industrial Control Systems", Family: "Annex II - Critical Categories", Description: "Industrial control systems and SCADA systems shall implement network segmentation, secure remote access, protocol validation, and real-time monitoring for operational technology environments.", Level: "critical", Annex: "II"},
		{ID: "B1-9", Title: "Medical Device Security", Family: "Annex II - Critical Categories", Description: "Medical devices with digital elements shall implement patient data protection, secure software updates, clinical safety integration, and compliance with medical device cybersecurity guidance.", Level: "critical", Annex: "II"},
		{ID: "B1-10", Title: "Automotive Cybersecurity", Family: "Annex II - Critical Categories", Description: "Automotive systems shall implement vehicle network security, secure over-the-air updates, intrusion detection, and compliance with UN R155 and ISO/SAE 21434 standards.", Level: "critical", Annex: "II"},
		{ID: "B2-1", Title: "Microprocessor Security", Family: "Annex II - Critical Categories", Description: "Microprocessors shall implement hardware-based security features including secure boot, trusted execution environments, memory protection, and side-channel attack mitigations.", Level: "critical", Annex: "II"},
		{ID: "B2-2", Title: "Router and Modem Security", Family: "Annex II - Critical Categories", Description: "Routers, modems, and network switches shall implement secure management interfaces, firmware verification, network segmentation, and protection against common network attacks.", Level: "high", Annex: "II"},
		{ID: "B2-3", Title: "IoT Device Security", Family: "Annex II - Critical Categories", Description: "Internet of Things devices shall implement secure provisioning, device authentication, encrypted communications, secure update mechanisms, and protection against common IoT attack vectors.", Level: "high", Annex: "II"},
		{ID: "B2-4", Title: "Cloud Service Security", Family: "Annex II - Critical Categories", Description: "Cloud services shall implement tenant isolation, data encryption, secure APIs, identity federation, and compliance with EU cloud security certification schemes.", Level: "critical", Annex: "II"},
		{ID: "B2-5", Title: "Backup and Recovery Systems", Family: "Annex II - Critical Categories", Description: "Backup and recovery solutions shall implement encrypted storage, integrity verification, ransomware protection, and tested recovery procedures to ensure business continuity.", Level: "high", Annex: "II"},
		{ID: "B2-6", Title: "Endpoint Detection and Response", Family: "Annex II - Critical Categories", Description: "Endpoint security solutions shall provide real-time threat detection, behavioral analysis, automated response capabilities, and integration with security information and event management systems.", Level: "high", Annex: "II"},
		{ID: "B2-7", Title: "Security Information and Event Management", Family: "Annex II - Critical Categories", Description: "SIEM solutions shall provide centralized log collection, correlation analysis, threat intelligence integration, automated alerting, and compliance reporting capabilities.", Level: "high", Annex: "II"},
	}

	var controls []grc.Control
	for _, req := range requirements {
		controls = append(controls, p.buildControl(req))
	}

	return controls
}
