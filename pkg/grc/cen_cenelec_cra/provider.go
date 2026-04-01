package cen_cenelec_cra

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
	FrameworkID = "CEN_CENELEC_CRA_2024"
	CatalogURL  = "https://raw.githubusercontent.com/cen-cenelec/cra-standards/main/controls.json"
)

// Provider fetches and parses CEN-CENELEC CRA harmonised standards controls.
type Provider struct {
	store  storage.Backend
	logger *slog.Logger
}

// New creates a new CEN-CENELEC CRA Standards provider.
func New(store storage.Backend, logger *slog.Logger) *Provider {
	return &Provider{
		store:  store,
		logger: logger,
	}
}

// Name returns the provider identifier.
func (p *Provider) Name() string {
	return "cen_cenelec_cra"
}

// Run fetches the CRA standards, parses controls, and writes them to storage.
func (p *Provider) Run(ctx context.Context) (int, error) {
	p.logger.Info("fetching CEN-CENELEC CRA harmonised standards", "url", CatalogURL)

	destPath := filepath.Join(os.TempDir(), "cen_cenelec_cra.json")
	if err := p.download(ctx, CatalogURL, destPath); err != nil {
		p.logger.Warn("download failed, falling back to embedded controls", "error", err)
		controls := p.generateEmbeddedControls()
		return p.writeControls(ctx, controls)
	}
	defer os.Remove(destPath)

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

type craStdCatalog struct {
	Standards []craStd `json:"standards,omitempty"`
}

type craStd struct {
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

	var catalog craStdCatalog
	if err := json.NewDecoder(f).Decode(&catalog); err != nil {
		return nil, fmt.Errorf("decode CEN-CENELEC CRA catalog: %w", err)
	}

	var controls []grc.Control
	for _, std := range catalog.Standards {
		controls = append(controls, p.buildControl(std))
	}

	return controls, nil
}

func (p *Provider) buildControl(std craStd) grc.Control {
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
	p.logger.Info("parsed CEN-CENELEC CRA controls", "count", len(controls))

	count := 0
	for _, ctrl := range controls {
		id := fmt.Sprintf("%s/%s", FrameworkID, ctrl.ControlID)
		if err := p.store.WriteControl(ctx, id, ctrl); err != nil {
			p.logger.Warn("failed to write control", "id", id, "error", err)
			continue
		}
		count++
	}

	p.logger.Info("wrote CEN-CENELEC CRA controls to storage", "count", count)
	return count, nil
}

func (p *Provider) generateEmbeddedControls() []grc.Control {
	standards := []craStd{
		{ID: "CC-CRA-01", Title: "Security-by-Design Framework", Family: "EN 18031-1 - Horizontal", Description: "General product cybersecurity requirements establishing security-by-design principles including threat modelling, security architecture, and secure development lifecycle integration for all products with digital elements.", Level: "critical", StdRef: "EN 18031-1, Clause 5"},
		{ID: "CC-CRA-02", Title: "Secure Development Lifecycle", Family: "EN 18031-1 - Horizontal", Description: "Requirements for integrating security activities throughout the product development lifecycle including security requirements engineering, design reviews, security testing, and release criteria definition.", Level: "critical", StdRef: "EN 18031-1, Clause 5.1"},
		{ID: "CC-CRA-03", Title: "Threat and Risk Assessment", Family: "EN 18031-1 - Horizontal", Description: "Systematic threat identification and risk assessment methodology for products with digital elements including asset identification, threat modelling, vulnerability analysis, and risk treatment planning.", Level: "critical", StdRef: "EN 18031-1, Clause 5.2"},
		{ID: "CC-CRA-04", Title: "Security Architecture Design", Family: "EN 18031-1 - Horizontal", Description: "Requirements for security architecture design including defense-in-depth principles, security domain separation, trust boundaries, and security control selection based on risk assessment outcomes.", Level: "critical", StdRef: "EN 18031-1, Clause 5.3"},
		{ID: "CC-CRA-05", Title: "Secure Default Configuration", Family: "EN 18031-1 - Horizontal", Description: "Requirements ensuring products are shipped with secure default configurations including disabled unnecessary services, strong default credentials, and minimum necessary functionality enabled.", Level: "critical", StdRef: "EN 18031-1, Clause 6"},
		{ID: "CC-CRA-06", Title: "Authentication and Access Control", Family: "EN 18031-1 - Horizontal", Description: "Requirements for authentication mechanisms and access control implementation including multi-factor authentication support, privilege separation, session management, and authorization enforcement.", Level: "high", StdRef: "EN 18031-1, Clause 7"},
		{ID: "CC-CRA-07", Title: "Data Protection and Privacy", Family: "EN 18031-1 - Horizontal", Description: "Requirements for protecting personal and sensitive data including encryption at rest and in transit, data minimization, purpose limitation, and alignment with GDPR data protection principles.", Level: "critical", StdRef: "EN 18031-1, Clause 8"},
		{ID: "CC-CRA-08", Title: "Vulnerability Management Process", Family: "EN 18031-1 - Horizontal", Description: "Requirements for establishing and maintaining vulnerability management processes including vulnerability identification, assessment, tracking, remediation, and coordinated disclosure procedures.", Level: "high", StdRef: "EN 18031-1, Clause 9"},
		{ID: "CC-CRA-09", Title: "Security Update Delivery", Family: "EN 18031-1 - Horizontal", Description: "Requirements for secure delivery of security updates including update signing, integrity verification, secure transport, rollback protection, and user notification mechanisms.", Level: "critical", StdRef: "EN 18031-1, Clause 10"},
		{ID: "CC-CRA-10", Title: "Integrity and Tamper Protection", Family: "EN 18031-1 - Horizontal", Description: "Requirements for ensuring product integrity including secure boot, firmware verification, configuration integrity checking, and tamper detection and response mechanisms.", Level: "high", StdRef: "EN 18031-1, Clause 11"},
		{ID: "CC-CRA-11", Title: "Security Logging and Monitoring", Family: "EN 18031-1 - Horizontal", Description: "Requirements for security event logging including event identification, log format standardization, log protection, retention periods, and support for security monitoring and forensic analysis.", Level: "high", StdRef: "EN 18031-1, Clause 12"},
		{ID: "CC-CRA-12", Title: "Network Communication Security", Family: "EN 18031-1 - Horizontal", Description: "Requirements for securing network communications including protocol security, encryption of sensitive communications, certificate validation, and protection against network-based attacks.", Level: "high", StdRef: "EN 18031-1, Clause 13"},
		{ID: "CC-CRA-13", Title: "Cryptographic Requirements", Family: "EN 18031-1 - Horizontal", Description: "Requirements for cryptographic implementation including approved algorithms, key management lifecycle, cryptographic module security, and preparation for post-quantum cryptographic migration.", Level: "critical", StdRef: "EN 18031-1, Clause 14"},
		{ID: "CC-CRA-14", Title: "Operating System Security Requirements", Family: "EN 18031-2 - Vertical", Description: "Product-specific security requirements for operating systems including mandatory access control, memory protection, process isolation, secure boot chains, and kernel hardening measures.", Level: "critical", StdRef: "EN 18031-2, Clause 5"},
		{ID: "CC-CRA-15", Title: "Identity Management System Security", Family: "EN 18031-2 - Vertical", Description: "Product-specific security requirements for identity management systems including credential management, federation security, directory service protection, and identity lifecycle management.", Level: "critical", StdRef: "EN 18031-2, Clause 6"},
		{ID: "CC-CRA-16", Title: "Network Security Device Requirements", Family: "EN 18031-2 - Vertical", Description: "Product-specific security requirements for firewalls, IDS/IPS, and network security appliances including deep packet inspection, threat intelligence integration, and automated response capabilities.", Level: "critical", StdRef: "EN 18031-2, Clause 7"},
		{ID: "CC-CRA-17", Title: "Smart Card and Secure Element Security", Family: "EN 18031-2 - Vertical", Description: "Product-specific security requirements for smart cards, secure elements, and TPMs including hardware security evaluation, side-channel resistance, and secure key storage mechanisms.", Level: "critical", StdRef: "EN 18031-2, Clause 9"},
		{ID: "CC-CRA-18", Title: "Virtualization Platform Security", Family: "EN 18031-2 - Vertical", Description: "Product-specific security requirements for virtualization platforms including hypervisor isolation, VM escape prevention, secure image management, and container runtime security.", Level: "high", StdRef: "EN 18031-2, Clause 10"},
		{ID: "CC-CRA-19", Title: "Industrial Control System Security", Family: "EN 18031-2 - Vertical", Description: "Product-specific security requirements for industrial control systems and SCADA including protocol validation, network segmentation for OT, real-time monitoring, and safety-security integration.", Level: "critical", StdRef: "EN 18031-2, Clause 12"},
		{ID: "CC-CRA-20", Title: "Medical Device Cybersecurity", Family: "EN 18031-2 - Vertical", Description: "Product-specific security requirements for medical devices including patient data protection, clinical safety integration, secure software updates, and compliance with medical device cybersecurity guidance.", Level: "critical", StdRef: "EN 18031-2, Clause 13"},
		{ID: "CC-CRA-21", Title: "Automotive System Cybersecurity", Family: "EN 18031-2 - Vertical", Description: "Product-specific security requirements for automotive systems including vehicle network security, secure OTA updates, intrusion detection, and alignment with UN R155 and ISO/SAE 21434.", Level: "critical", StdRef: "EN 18031-2, Clause 14"},
		{ID: "CC-CRA-22", Title: "SBOM Requirements", Family: "EN 18031-1 - Horizontal", Description: "Requirements for software bill of materials (SBOM) generation and maintenance including component identification, version tracking, vulnerability correlation, and supply chain transparency.", Level: "high", StdRef: "EN 18031-1, Clause 15"},
		{ID: "CC-CRA-23", Title: "Third-Party Component Assessment", Family: "EN 18031-1 - Horizontal", Description: "Requirements for assessing third-party components and dependencies including security evaluation, vulnerability tracking, license compliance, and ongoing monitoring of component security posture.", Level: "high", StdRef: "EN 18031-1, Clause 15.1"},
		{ID: "CC-CRA-24", Title: "Product End-of-Life Management", Family: "EN 18031-1 - Horizontal", Description: "Requirements for managing product end-of-life including end-of-support notification, final security updates, secure decommissioning procedures, and customer migration guidance.", Level: "high", StdRef: "EN 18031-1, Clause 10.2"},
		{ID: "CC-CRA-25", Title: "Security Documentation Requirements", Family: "EN 18031-1 - Horizontal", Description: "Requirements for security documentation including security architecture documentation, user security guidance, administrator guides, and vulnerability handling documentation for products with digital elements.", Level: "standard", StdRef: "EN 18031-1, Clause 16"},
		{ID: "CC-CRA-26", Title: "Testing and Validation Requirements", Family: "EN 18031-1 - Horizontal", Description: "Requirements for security testing and validation including functional testing, penetration testing, fuzzing, code analysis, and validation of security controls against specified requirements.", Level: "high", StdRef: "EN 18031-1, Clause 17"},
		{ID: "CC-CRA-27", Title: "Conformity Assessment Procedures", Family: "EN 18031-1 - Horizontal", Description: "Procedures for assessing conformity with CRA requirements including internal control procedures, type examination by notified bodies, and full quality assurance assessment options.", Level: "critical", StdRef: "EN 18031-1, Clause 18"},
		{ID: "CC-CRA-28", Title: "CE Marking Requirements", Family: "EN 18031-1 - Horizontal", Description: "Requirements for CE marking of products with digital elements including declaration of conformity, technical documentation maintenance, and market surveillance cooperation obligations.", Level: "high", StdRef: "EN 18031-1, Clause 19"},
		{ID: "CC-CRA-29", Title: "Post-Market Surveillance", Family: "EN 18031-1 - Horizontal", Description: "Requirements for post-market surveillance of products including vulnerability monitoring, incident tracking, customer feedback analysis, and proactive security posture assessment throughout product lifetime.", Level: "high", StdRef: "EN 18031-1, Clause 20"},
		{ID: "CC-CRA-30", Title: "Reporting Obligations", Family: "EN 18031-1 - Horizontal", Description: "Requirements for reporting actively exploited vulnerabilities and significant cybersecurity incidents to ENISA and relevant authorities within defined timeframes with specified content requirements.", Level: "critical", StdRef: "EN 18031-1, Clause 21"},
		{ID: "CC-CRA-31", Title: "Hardware Security Requirements", Family: "EN 18031-2 - Vertical", Description: "Product-specific security requirements for hardware components including microprocessor security features, hardware root of trust, side-channel attack mitigation, and physical tamper resistance.", Level: "critical", StdRef: "EN 18031-2, Clause 8"},
		{ID: "CC-CRA-32", Title: "Router and Network Equipment Security", Family: "EN 18031-2 - Vertical", Description: "Product-specific security requirements for routers, modems, and network switches including secure management interfaces, firmware verification, and protection against common network attacks.", Level: "high", StdRef: "EN 18031-2, Clause 11"},
		{ID: "CC-CRA-33", Title: "IoT Device Security Baseline", Family: "EN 18031-2 - Vertical", Description: "Product-specific security requirements for IoT devices including secure provisioning, device authentication, encrypted communications, secure update mechanisms, and IoT-specific attack vector protection.", Level: "high", StdRef: "EN 18031-2, Clause 15"},
		{ID: "CC-CRA-34", Title: "Cloud Service Security Requirements", Family: "EN 18031-2 - Vertical", Description: "Product-specific security requirements for cloud services including tenant isolation, data encryption, secure APIs, identity federation, and alignment with EU cloud security certification schemes.", Level: "critical", StdRef: "EN 18031-2, Clause 16"},
		{ID: "CC-CRA-35", Title: "Security Evaluation Methodology", Family: "EN 18031-1 - Horizontal", Description: "Methodology for evaluating product security including test case development, evaluation criteria, pass/fail thresholds, and evidence requirements for demonstrating compliance with CRA essential requirements.", Level: "high", StdRef: "EN 18031-1, Clause 17.1"},
	}

	var controls []grc.Control
	for _, std := range standards {
		controls = append(controls, p.buildControl(std))
	}

	return controls
}
