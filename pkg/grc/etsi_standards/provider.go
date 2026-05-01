package etsi_standards

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
	FrameworkID = "ETSI_Cybersecurity_2024"
)

var CatalogURL = "https://raw.githubusercontent.com/etsi-standards/cybersecurity/main/controls.json"

// Provider fetches and parses ETSI cybersecurity standards controls.
type Provider struct {
	store  storage.Backend
	logger *slog.Logger
}

// New creates a new ETSI Standards provider.
func New(store storage.Backend, logger *slog.Logger) *Provider {
	return &Provider{
		store:  store,
		logger: logger,
	}
}

// Name returns the provider identifier.
func (p *Provider) Name() string {
	return "etsi_standards"
}

// Run fetches the ETSI standards, parses controls, and writes them to storage.
func (p *Provider) Run(ctx context.Context) (int, error) {
	p.logger.Info("fetching ETSI cybersecurity standards", "url", CatalogURL)

	f, err := os.CreateTemp("", "etsi_standards_*.json")
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

type etsiCatalog struct {
	Standards []etsiStandard `json:"standards,omitempty"`
}

type etsiStandard struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Family      string `json:"family,omitempty"`
	Description string `json:"description"`
	Level       string `json:"level,omitempty"`
	StdRef      string `json:"standard_reference,omitempty"`
}

func (p *Provider) parse(path string) ([]grc.Control, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var catalog etsiCatalog
	if err := json.NewDecoder(f).Decode(&catalog); err != nil {
		return nil, fmt.Errorf("decode ETSI catalog: %w", err)
	}

	var controls []grc.Control
	for _, std := range catalog.Standards {
		controls = append(controls, p.buildControl(std))
	}

	return controls, nil
}

func (p *Provider) buildControl(std etsiStandard) grc.Control {
	return grc.Control{
		Framework:   FrameworkID,
		ControlID:   std.ID,
		Title:       std.Title,
		Family:      std.Family,
		Description: std.Description,
		Level:       std.Level,
		References: []grc.Reference{
			{Source: "ETSI", URL: "https://www.etsi.org/cybersecurity", Section: std.StdRef},
		},
	}
}

func (p *Provider) writeControls(ctx context.Context, controls []grc.Control) (int, error) {
	p.logger.Info("parsed ETSI standards controls", "count", len(controls))

	count := 0
	for _, ctrl := range controls {
		id := fmt.Sprintf("%s/%s", FrameworkID, ctrl.ControlID)
		if err := p.store.WriteControl(ctx, id, ctrl); err != nil {
			p.logger.Warn("failed to write control", "id", id, "error", err)
			continue
		}
		count++
	}

	p.logger.Info("wrote ETSI controls to storage", "count", count)
	return count, nil
}

func (p *Provider) generateEmbeddedControls() []grc.Control {
	standards := []etsiStandard{
		{ID: "ETSI-001", Title: "No Universal Default Passwords", Family: "ETSI EN 303 645 - Consumer IoT", Description: "Consumer IoT devices shall not use universal default passwords. Each device shall have a unique password or require the user to set a strong password during initial setup. Default credentials shall not be guessable or publicly documented.", Level: "critical", StdRef: "ETSI EN 303 645, Provision 5.1"},
		{ID: "ETSI-002", Title: "Vulnerability Disclosure Policy", Family: "ETSI EN 303 645 - Consumer IoT", Description: "Manufacturers shall implement a vulnerability disclosure policy providing a public point of contact for security researchers to report vulnerabilities. A coordinated disclosure process shall be established with defined response timeframes.", Level: "high", StdRef: "ETSI EN 303 645, Provision 5.2"},
		{ID: "ETSI-003", Title: "Secure Update Mechanisms", Family: "ETSI EN 303 645 - Consumer IoT", Description: "IoT devices shall implement secure software update mechanisms with integrity verification, authenticity checking, and rollback protection. Updates shall be delivered over secure channels and installed automatically or with clear user notification.", Level: "critical", StdRef: "ETSI EN 303 645, Provision 5.3"},
		{ID: "ETSI-004", Title: "Secure Storage of Sensitive Data", Family: "ETSI EN 303 645 - Consumer IoT", Description: "Sensitive security parameters including passwords, cryptographic keys, and personal data shall be stored securely using hardware-backed protection where available. Data shall be encrypted at rest with appropriate key management.", Level: "high", StdRef: "ETSI EN 303 645, Provision 5.4"},
		{ID: "ETSI-005", Title: "Secure Communication", Family: "ETSI EN 303 645 - Consumer IoT", Description: "All network communications from IoT devices shall use encrypted protocols with proper certificate validation. Insecure protocols such as plain HTTP, Telnet, and unencrypted MQTT shall not be used for sensitive data transmission.", Level: "critical", StdRef: "ETSI EN 303 645, Provision 5.5"},
		{ID: "ETSI-006", Title: "Minimize Attack Surface", Family: "ETSI EN 303 645 - Consumer IoT", Description: "IoT devices shall minimize exposed attack surfaces by disabling unnecessary services, closing unused ports, and removing debug interfaces from production firmware. Only required functionality shall be enabled by default.", Level: "high", StdRef: "ETSI EN 303 645, Provision 5.6"},
		{ID: "ETSI-007", Title: "Software Integrity Verification", Family: "ETSI EN 303 645 - Consumer IoT", Description: "IoT device software shall verify its own integrity before execution using cryptographic checksums or digital signatures. Tampering with firmware or configuration shall be detected and appropriate countermeasures shall be triggered.", Level: "high", StdRef: "ETSI EN 303 645, Provision 5.7"},
		{ID: "ETSI-008", Title: "Personal Data Protection", Family: "ETSI EN 303 645 - Consumer IoT", Description: "IoT devices shall protect personal data through encryption, access controls, and data minimization. Users shall be informed about data collection practices and have control over their personal data in accordance with GDPR.", Level: "high", StdRef: "ETSI EN 303 645, Provision 5.8"},
		{ID: "ETSI-009", Title: "System Resilience", Family: "ETSI EN 303 645 - Consumer IoT", Description: "IoT devices shall maintain essential functionality during adverse conditions including network disruption, power fluctuations, and attempted attacks. Graceful degradation and recovery mechanisms shall be implemented.", Level: "standard", StdRef: "ETSI EN 303 645, Provision 5.9"},
		{ID: "ETSI-010", Title: "Input and Output Validation", Family: "ETSI EN 303 645 - Consumer IoT", Description: "IoT devices shall validate all input data from users, networks, and sensors to prevent injection attacks, buffer overflows, and malformed data exploitation. Output data shall be sanitized to prevent information leakage.", Level: "high", StdRef: "ETSI EN 303 645, Provision 5.10"},
		{ID: "ETSI-011", Title: "Security Telemetry Data", Family: "ETSI EN 303 645 - Consumer IoT", Description: "IoT devices shall collect and transmit security-relevant telemetry data including authentication events, configuration changes, and error conditions. Telemetry data shall be protected and not contain sensitive information.", Level: "standard", StdRef: "ETSI EN 303 645, Provision 5.11"},
		{ID: "ETSI-012", Title: "Easy Data Deletion on Disposal", Family: "ETSI EN 303 645 - Consumer IoT", Description: "IoT devices shall provide mechanisms for users to easily delete personal data and security credentials when disposing of or transferring the device. Factory reset procedures shall securely erase all sensitive data.", Level: "standard", StdRef: "ETSI EN 303 645, Provision 5.12"},
		{ID: "ETSI-013", Title: "Installation and Maintenance", Family: "ETSI EN 303 645 - Consumer IoT", Description: "IoT devices shall be designed for easy and secure installation by consumers. Security configuration shall be straightforward, and devices shall guide users through secure setup processes without requiring technical expertise.", Level: "standard", StdRef: "ETSI EN 303 645, Provision 5.13"},
		{ID: "ETSI-014", Title: "Input Data Validation for Web Services", Family: "ETSI TS 103 701 - Web Services", Description: "Web services shall validate all input data including HTTP parameters, headers, body content, and file uploads to prevent injection attacks, cross-site scripting, and server-side request forgery.", Level: "high", StdRef: "ETSI TS 103 701, Section 6.1"},
		{ID: "ETSI-015", Title: "Authentication for Web Services", Family: "ETSI TS 103 701 - Web Services", Description: "Web services shall implement strong authentication mechanisms including multi-factor authentication for administrative access, session management controls, and protection against credential stuffing attacks.", Level: "high", StdRef: "ETSI TS 103 701, Section 6.2"},
		{ID: "ETSI-016", Title: "Authorization Controls", Family: "ETSI TS 103 701 - Web Services", Description: "Web services shall enforce authorization controls at every level ensuring users can only access resources and perform actions for which they have explicit permission. Role-based access control shall be implemented.", Level: "high", StdRef: "ETSI TS 103 701, Section 6.3"},
		{ID: "ETSI-017", Title: "5G Network Security - Authentication", Family: "ETSI TS 133 501 - 5G Security", Description: "5G network elements shall implement mutual authentication between user equipment and network, subscription identifier protection (SUCI), and enhanced authentication and key agreement (5G-AKA) procedures.", Level: "critical", StdRef: "ETSI TS 133 501, Section 6.1"},
		{ID: "ETSI-018", Title: "5G Network Slicing Security", Family: "ETSI TS 133 501 - 5G Security", Description: "5G network slices shall be isolated from each other with independent security policies, access controls, and monitoring. Cross-slice communication shall be controlled and audited to prevent lateral movement.", Level: "critical", StdRef: "ETSI TS 133 501, Section 6.2"},
		{ID: "ETSI-019", Title: "5G Service-Based Architecture Security", Family: "ETSI TS 133 501 - 5G Security", Description: "5G core network service-based interfaces shall implement mutual TLS authentication, authorization tokens, and protection against replay attacks. Network function registration and discovery shall be secured.", Level: "critical", StdRef: "ETSI TS 133 501, Section 6.3"},
		{ID: "ETSI-020", Title: "Quantum Key Distribution Security", Family: "ETSI GS QKD - Quantum Security", Description: "Quantum key distribution systems shall implement secure key generation, distribution, and storage with protection against photon number splitting attacks, Trojan horse attacks, and detector blinding attacks.", Level: "critical", StdRef: "ETSI GS QKD 014, Section 5"},
		{ID: "ETSI-021", Title: "QKD Network Security Requirements", Family: "ETSI GS QKD - Quantum Security", Description: "QKD networks shall implement trusted node security, key management protocol security, and protection against denial-of-service attacks on quantum channels. Key relay protocols shall be authenticated and encrypted.", Level: "high", StdRef: "ETSI GS QKD 011, Section 5"},
		{ID: "ETSI-022", Title: "Machine Learning Security - Data Protection", Family: "ETSI SGR SEC ML - ML Security", Description: "Machine learning systems shall protect training data integrity, prevent data poisoning attacks, and ensure model confidentiality. Training data shall be validated for quality and freedom from adversarial manipulation.", Level: "high", StdRef: "ETSI SGR SEC ML 001, Section 6.1"},
		{ID: "ETSI-023", Title: "ML Model Security and Robustness", Family: "ETSI SGR SEC ML - ML Security", Description: "ML models shall be tested for robustness against adversarial examples, model inversion attacks, and membership inference attacks. Model outputs shall be monitored for anomalous behavior indicating compromise.", Level: "high", StdRef: "ETSI SGR SEC ML 001, Section 6.2"},
		{ID: "ETSI-024", Title: "Smart City Security Framework", Family: "ETSI TS 103 740 - Smart Cities", Description: "Smart city infrastructure shall implement centralized security management, cross-domain security policies, and coordinated incident response. IoT device onboarding and lifecycle management shall be secured.", Level: "high", StdRef: "ETSI TS 103 740, Section 7"},
		{ID: "ETSI-025", Title: "Smart City Data Privacy", Family: "ETSI TS 103 740 - Smart Cities", Description: "Smart city systems shall implement privacy-by-design principles including data anonymization, purpose limitation, and user consent management. Citizen data shall be protected in accordance with GDPR requirements.", Level: "high", StdRef: "ETSI TS 103 740, Section 8"},
		{ID: "ETSI-026", Title: "NFV Security - Virtualization", Family: "ETSI GS NFV-SEC 013 - NFV Security", Description: "Network function virtualization infrastructure shall provide secure virtualization with hypervisor hardening, VM isolation, secure image management, and protection against VM escape and side-channel attacks.", Level: "critical", StdRef: "ETSI GS NFV-SEC 013, Section 5"},
		{ID: "ETSI-027", Title: "NFV Security - Management Orchestration", Family: "ETSI GS NFV-SEC 013 - NFV Security", Description: "NFV management and orchestration systems shall implement secure API access, role-based administration, audit logging, and protection against unauthorized VNF lifecycle operations and resource manipulation.", Level: "high", StdRef: "ETSI GS NFV-SEC 013, Section 6"},
		{ID: "ETSI-028", Title: "V2X Communication Security", Family: "ETSI TS 103 097 - V2X Security", Description: "Vehicle-to-everything communications shall use PKI-based message authentication, pseudonym certificates for privacy, and secure message formats to prevent spoofing, replay, and manipulation of safety-critical messages.", Level: "critical", StdRef: "ETSI TS 103 097, Section 6"},
		{ID: "ETSI-029", Title: "Critical Communications Security", Family: "ETSI TS 133 180 - Critical Communications", Description: "Mission-critical communication systems shall implement end-to-end encryption, priority-based access control, group communication security, and resilience against jamming and interference attacks.", Level: "critical", StdRef: "ETSI TS 133 180, Section 5"},
		{ID: "ETSI-030", Title: "Post-Quantum Cryptography Migration", Family: "ETSI GR QSC - Quantum-Safe Crypto", Description: "Organizations shall assess cryptographic systems for quantum vulnerability and develop migration plans to post-quantum cryptographic algorithms. Hybrid approaches combining classical and PQC algorithms shall be considered.", Level: "high", StdRef: "ETSI GR QSC 001, Section 7"},
	}

	var controls []grc.Control
	for _, std := range standards {
		controls = append(controls, p.buildControl(std))
	}

	return controls
}
