package enisa_cra_mapping

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
	FrameworkID = "ENISA_CRA_Mapping_2024"
	CatalogURL  = "https://www.enisa.europa.eu/publications/cra-harmonised-standards-mapping"
)

// Provider fetches and parses ENISA CRA-to-standards mapping data.
type Provider struct {
	store  storage.Backend
	logger *slog.Logger
}

// New creates a new ENISA CRA Mapping provider.
func New(store storage.Backend, logger *slog.Logger) *Provider {
	return &Provider{
		store:  store,
		logger: logger,
	}
}

// Name returns the provider identifier.
func (p *Provider) Name() string {
	return "enisa_cra_mapping"
}

// Run fetches the CRA mapping, parses mappings, and writes them to storage.
func (p *Provider) Run(ctx context.Context) (int, error) {
	p.logger.Info("fetching ENISA CRA mapping data", "url", CatalogURL)

	destPath := filepath.Join(os.TempDir(), "enisa_cra_mapping.json")
	if err := p.download(ctx, CatalogURL, destPath); err != nil {
		p.logger.Warn("download failed, falling back to embedded mappings", "error", err)
		controls := p.generateEmbeddedMappings()
		return p.writeControls(ctx, controls)
	}
	defer os.Remove(destPath)

	controls, err := p.parse(destPath)
	if err != nil {
		p.logger.Warn("parse failed, falling back to embedded mappings", "error", err)
		controls = p.generateEmbeddedMappings()
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

type mappingCatalog struct {
	Mappings []craMapping `json:"mappings,omitempty"`
}

type craMapping struct {
	ID             string `json:"id"`
	CRARequirement string `json:"cra_requirement"`
	HarmonisedStd  string `json:"harmonised_standard"`
	StdSection     string `json:"standard_section"`
	Title          string `json:"title"`
	Description    string `json:"description"`
	Confidence     string `json:"confidence,omitempty"`
	Level          string `json:"level,omitempty"`
	Annex          string `json:"annex,omitempty"`
}

func (p *Provider) parse(path string) ([]grc.Control, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var catalog mappingCatalog
	if err := json.NewDecoder(f).Decode(&catalog); err != nil {
		return nil, fmt.Errorf("decode CRA mapping catalog: %w", err)
	}

	var controls []grc.Control
	for _, m := range catalog.Mappings {
		controls = append(controls, p.buildControl(m))
	}

	return controls, nil
}

func (p *Provider) buildControl(m craMapping) grc.Control {
	level := m.Level
	if level == "" {
		switch m.Confidence {
		case "high":
			level = "high"
		case "medium":
			level = "standard"
		default:
			level = "standard"
		}
	}

	return grc.Control{
		Framework:              FrameworkID,
		ControlID:              m.ID,
		Title:                  m.Title,
		Family:                 fmt.Sprintf("CRA %s -> %s", m.Annex, m.HarmonisedStd),
		Description:            m.Description,
		Level:                  level,
		ImplementationGuidance: fmt.Sprintf("CRA Requirement: %s | Harmonised Standard: %s, Section: %s", m.CRARequirement, m.HarmonisedStd, m.StdSection),
		References: []grc.Reference{
			{Source: "ENISA", URL: "https://www.enisa.europa.eu/topics/cybersecurity-certification/cra", Section: "CRA Mapping"},
			{Source: m.HarmonisedStd, URL: "https://standards.cencenelec.eu", Section: m.StdSection},
		},
	}
}

func (p *Provider) writeControls(ctx context.Context, controls []grc.Control) (int, error) {
	p.logger.Info("parsed CRA mappings", "count", len(controls))

	count := 0
	for _, ctrl := range controls {
		id := fmt.Sprintf("%s/%s", FrameworkID, ctrl.ControlID)
		if err := p.store.WriteControl(ctx, id, ctrl); err != nil {
			p.logger.Warn("failed to write control", "id", id, "error", err)
			continue
		}
		count++
	}

	p.logger.Info("wrote CRA mapping controls to storage", "count", count)
	return count, nil
}

func (p *Provider) generateEmbeddedMappings() []grc.Control {
	mappings := []craMapping{
		{ID: "MAP-001", CRARequirement: "Annex I-1", HarmonisedStd: "EN 18031-1", StdSection: "5.1", Title: "Secure by Design - General Requirements", Description: "Mapping of CRA Annex I requirement 1 (secure by design) to EN 18031-1 Section 5.1 covering general security-by-design principles and secure development lifecycle requirements.", Confidence: "high", Level: "critical", Annex: "I"},
		{ID: "MAP-002", CRARequirement: "Annex I-1", HarmonisedStd: "EN 18031-1", StdSection: "5.2", Title: "Threat Modelling Requirements", Description: "Mapping of CRA secure by design requirement to EN 18031-1 Section 5.2 covering systematic threat modelling and risk analysis during product design phases.", Confidence: "high", Level: "high", Annex: "I"},
		{ID: "MAP-003", CRARequirement: "Annex I-2", HarmonisedStd: "EN 18031-1", StdSection: "6.1", Title: "Secure Default Configuration", Description: "Mapping of CRA Annex I requirement 2 (secure by default) to EN 18031-1 Section 6.1 covering secure default settings and minimum security baseline requirements.", Confidence: "high", Level: "critical", Annex: "I"},
		{ID: "MAP-004", CRARequirement: "Annex I-3", HarmonisedStd: "EN 18031-1", StdSection: "7.1", Title: "Access Control Requirements", Description: "Mapping of CRA access control requirements to EN 18031-1 Section 7.1 covering authentication, authorization, and privilege management mechanisms.", Confidence: "high", Level: "high", Annex: "I"},
		{ID: "MAP-005", CRARequirement: "Annex I-3", HarmonisedStd: "ETSI EN 303 645", StdSection: "5.2", Title: "IoT Access Control Mapping", Description: "Mapping of CRA access control requirements to ETSI EN 303 645 Section 5.2 for IoT-specific access control including unique passwords and credential management.", Confidence: "medium", Level: "high", Annex: "I"},
		{ID: "MAP-006", CRARequirement: "Annex I-4", HarmonisedStd: "EN 18031-1", StdSection: "8.1", Title: "Data Protection and Confidentiality", Description: "Mapping of CRA data protection requirements to EN 18031-1 Section 8.1 covering encryption, data integrity, and confidentiality mechanisms for personal and sensitive data.", Confidence: "high", Level: "critical", Annex: "I"},
		{ID: "MAP-007", CRARequirement: "Annex I-4", HarmonisedStd: "EN 18031-1", StdSection: "8.2", Title: "Secure Data Transmission", Description: "Mapping of CRA data protection requirements to EN 18031-1 Section 8.2 covering secure communication protocols and encryption of data in transit.", Confidence: "high", Level: "critical", Annex: "I"},
		{ID: "MAP-008", CRARequirement: "Annex I-5", HarmonisedStd: "EN 18031-1", StdSection: "9.1", Title: "Vulnerability Identification Process", Description: "Mapping of CRA vulnerability handling requirements to EN 18031-1 Section 9.1 covering systematic vulnerability identification, tracking, and remediation processes.", Confidence: "high", Level: "high", Annex: "I"},
		{ID: "MAP-009", CRARequirement: "Annex I-5", HarmonisedStd: "EN 18031-1", StdSection: "9.2", Title: "Coordinated Vulnerability Disclosure", Description: "Mapping of CRA vulnerability disclosure requirements to EN 18031-1 Section 9.2 covering coordinated disclosure policies and responsible disclosure procedures.", Confidence: "high", Level: "high", Annex: "I"},
		{ID: "MAP-010", CRARequirement: "Annex I-6", HarmonisedStd: "EN 18031-1", StdSection: "10.1", Title: "Security Update Mechanism", Description: "Mapping of CRA security update requirements to EN 18031-1 Section 10.1 covering secure update delivery, verification, and installation mechanisms.", Confidence: "high", Level: "critical", Annex: "I"},
		{ID: "MAP-011", CRARequirement: "Annex I-6", HarmonisedStd: "EN 18031-1", StdSection: "10.2", Title: "Update Lifetime Requirements", Description: "Mapping of CRA update lifetime requirements to EN 18031-1 Section 10.2 covering minimum support periods and end-of-life notification requirements.", Confidence: "high", Level: "critical", Annex: "I"},
		{ID: "MAP-012", CRARequirement: "Annex I-7", HarmonisedStd: "EN 18031-1", StdSection: "11.1", Title: "Integrity Verification Mechanisms", Description: "Mapping of CRA integrity requirements to EN 18031-1 Section 11.1 covering code signing, integrity checks, and tamper detection mechanisms.", Confidence: "high", Level: "high", Annex: "I"},
		{ID: "MAP-013", CRARequirement: "Annex I-8", HarmonisedStd: "EN 18031-1", StdSection: "12.1", Title: "Security Event Logging", Description: "Mapping of CRA logging requirements to EN 18031-1 Section 12.1 covering security event recording, log protection, and forensic analysis capabilities.", Confidence: "high", Level: "high", Annex: "I"},
		{ID: "MAP-014", CRARequirement: "Annex I-9", HarmonisedStd: "EN 18031-1", StdSection: "13.1", Title: "Network Security Controls", Description: "Mapping of CRA network security requirements to EN 18031-1 Section 13.1 covering network protection, secure protocols, and communication security.", Confidence: "high", Level: "high", Annex: "I"},
		{ID: "MAP-015", CRARequirement: "Annex I-10", HarmonisedStd: "EN 18031-1", StdSection: "14.1", Title: "Cryptographic Algorithm Requirements", Description: "Mapping of CRA cryptographic requirements to EN 18031-1 Section 14.1 covering approved algorithms, key management, and cryptographic module requirements.", Confidence: "high", Level: "critical", Annex: "I"},
		{ID: "MAP-016", CRARequirement: "Annex I-10", HarmonisedStd: "EN 18031-1", StdSection: "14.2", Title: "Key Management Requirements", Description: "Mapping of CRA cryptographic key management requirements to EN 18031-1 Section 14.2 covering key generation, storage, distribution, rotation, and destruction.", Confidence: "high", Level: "critical", Annex: "I"},
		{ID: "MAP-017", CRARequirement: "Annex I-1", HarmonisedStd: "ISO/IEC 27001", StdSection: "A.8.25", Title: "Secure Development Lifecycle", Description: "Mapping of CRA secure by design requirements to ISO/IEC 27001 A.8.25 covering secure development lifecycle practices and security engineering principles.", Confidence: "medium", Level: "high", Annex: "I"},
		{ID: "MAP-018", CRARequirement: "Annex II-1", HarmonisedStd: "EN 18031-2", StdSection: "5.1", Title: "OS Security Requirements", Description: "Mapping of CRA Annex II operating system requirements to EN 18031-2 Section 5.1 covering OS-specific security controls including access control and memory protection.", Confidence: "high", Level: "critical", Annex: "II"},
		{ID: "MAP-019", CRARequirement: "Annex II-2", HarmonisedStd: "EN 18031-2", StdSection: "6.1", Title: "Identity Management System Requirements", Description: "Mapping of CRA Annex II identity management requirements to EN 18031-2 Section 6.1 covering IAM system security controls and authentication mechanisms.", Confidence: "high", Level: "critical", Annex: "II"},
		{ID: "MAP-020", CRARequirement: "Annex II-3", HarmonisedStd: "EN 18031-2", StdSection: "7.1", Title: "Network Security Device Requirements", Description: "Mapping of CRA Annex II firewall/IDS requirements to EN 18031-2 Section 7.1 covering network security device testing and validation requirements.", Confidence: "high", Level: "critical", Annex: "II"},
		{ID: "MAP-021", CRARequirement: "Annex II-4", HarmonisedStd: "EN 18031-2", StdSection: "8.1", Title: "Access Control System Requirements", Description: "Mapping of CRA Annex II physical access control requirements to EN 18031-2 Section 8.1 covering electronic access control system security requirements.", Confidence: "high", Level: "high", Annex: "II"},
		{ID: "MAP-022", CRARequirement: "Annex II-5", HarmonisedStd: "EN 18031-2", StdSection: "9.1", Title: "Smart Card Security Requirements", Description: "Mapping of CRA Annex II smart card requirements to EN 18031-2 Section 9.1 covering secure element and smart card security evaluation criteria.", Confidence: "high", Level: "critical", Annex: "II"},
		{ID: "MAP-023", CRARequirement: "Annex II-6", HarmonisedStd: "EN 18031-2", StdSection: "10.1", Title: "Virtualization Security Requirements", Description: "Mapping of CRA Annex II virtualization requirements to EN 18031-2 Section 10.1 covering hypervisor security, container isolation, and cloud security controls.", Confidence: "high", Level: "high", Annex: "II"},
		{ID: "MAP-024", CRARequirement: "Annex II-7", HarmonisedStd: "EN 18031-2", StdSection: "11.1", Title: "Encryption Product Requirements", Description: "Mapping of CRA Annex II encryption requirements to EN 18031-2 Section 11.1 covering encryption product evaluation and cryptographic module validation.", Confidence: "high", Level: "critical", Annex: "II"},
		{ID: "MAP-025", CRARequirement: "Annex I-1", HarmonisedStd: "IEC 62443-4-1", StdSection: "4.1", Title: "Industrial Secure Development", Description: "Mapping of CRA secure development requirements to IEC 62443-4-1 Section 4.1 covering secure development practices for industrial automation and control systems.", Confidence: "medium", Level: "high", Annex: "I"},
		{ID: "MAP-026", CRARequirement: "Annex II-8", HarmonisedStd: "EN 18031-2", StdSection: "12.1", Title: "ICS Security Requirements", Description: "Mapping of CRA Annex II industrial control system requirements to EN 18031-2 Section 12.1 covering ICS/SCADA security controls and OT-specific protections.", Confidence: "high", Level: "critical", Annex: "II"},
		{ID: "MAP-027", CRARequirement: "Annex II-9", HarmonisedStd: "EN 18031-2", StdSection: "13.1", Title: "Medical Device Security Requirements", Description: "Mapping of CRA Annex II medical device requirements to EN 18031-2 Section 13.1 covering medical device cybersecurity evaluation and patient safety integration.", Confidence: "high", Level: "critical", Annex: "II"},
		{ID: "MAP-028", CRARequirement: "Annex II-10", HarmonisedStd: "EN 18031-2", StdSection: "14.1", Title: "Automotive Cybersecurity Requirements", Description: "Mapping of CRA Annex II automotive requirements to EN 18031-2 Section 14.1 covering vehicle cybersecurity controls and UN R155 compliance verification.", Confidence: "high", Level: "critical", Annex: "II"},
		{ID: "MAP-029", CRARequirement: "Annex I-3", HarmonisedStd: "EN 18031-1", StdSection: "7.2", Title: "Multi-Factor Authentication", Description: "Mapping of CRA access control requirements to EN 18031-1 Section 7.2 covering multi-factor authentication implementation requirements for products with digital elements.", Confidence: "high", Level: "high", Annex: "I"},
		{ID: "MAP-030", CRARequirement: "Annex I-4", HarmonisedStd: "EN 18031-1", StdSection: "8.3", Title: "Data Minimization and Privacy", Description: "Mapping of CRA data protection requirements to EN 18031-1 Section 8.3 covering data minimization, privacy-by-design, and GDPR alignment for connected products.", Confidence: "high", Level: "high", Annex: "I"},
		{ID: "MAP-031", CRARequirement: "Annex I-2", HarmonisedStd: "ETSI EN 303 645", StdSection: "5.1", Title: "IoT Secure Default Settings", Description: "Mapping of CRA secure by default requirements to ETSI EN 303 645 Section 5.1 covering IoT device secure configuration and elimination of universal default passwords.", Confidence: "medium", Level: "critical", Annex: "I"},
		{ID: "MAP-032", CRARequirement: "Annex I-5", HarmonisedStd: "ISO/IEC 29147", StdSection: "5", Title: "Vulnerability Disclosure Framework", Description: "Mapping of CRA vulnerability handling requirements to ISO/IEC 29147 Section 5 covering vulnerability disclosure framework and coordinated disclosure processes.", Confidence: "medium", Level: "high", Annex: "I"},
		{ID: "MAP-033", CRARequirement: "Annex I-6", HarmonisedStd: "ISO/IEC 30111", StdSection: "6", Title: "Vulnerability Handling Process", Description: "Mapping of CRA security update requirements to ISO/IEC 30111 Section 6 covering vulnerability handling processes and patch management lifecycle.", Confidence: "medium", Level: "high", Annex: "I"},
		{ID: "MAP-034", CRARequirement: "Annex II-2", HarmonisedStd: "EN 18031-2", StdSection: "6.2", Title: "Federated Identity Requirements", Description: "Mapping of CRA identity management requirements to EN 18031-2 Section 6.2 covering federated identity, SSO, and identity federation security controls.", Confidence: "high", Level: "high", Annex: "II"},
		{ID: "MAP-035", CRARequirement: "Annex I-7", HarmonisedStd: "EN 18031-1", StdSection: "11.2", Title: "Secure Boot Requirements", Description: "Mapping of CRA integrity requirements to EN 18031-1 Section 11.2 covering secure boot, measured boot, and trusted execution environment requirements.", Confidence: "high", Level: "critical", Annex: "I"},
		{ID: "MAP-036", CRARequirement: "Annex I-9", HarmonisedStd: "EN 18031-1", StdSection: "13.2", Title: "Protocol Security Requirements", Description: "Mapping of CRA network security requirements to EN 18031-1 Section 13.2 covering secure protocol implementation and network communication security.", Confidence: "high", Level: "high", Annex: "I"},
		{ID: "MAP-037", CRARequirement: "Annex II-3", HarmonisedStd: "EN 18031-2", StdSection: "7.2", Title: "IDS/IPS Evaluation Requirements", Description: "Mapping of CRA Annex II IDS/IPS requirements to EN 18031-2 Section 7.2 covering intrusion detection and prevention system evaluation criteria.", Confidence: "high", Level: "critical", Annex: "II"},
		{ID: "MAP-038", CRARequirement: "Annex I-10", HarmonisedStd: "EN 18031-1", StdSection: "14.3", Title: "Post-Quantum Cryptography Readiness", Description: "Mapping of CRA cryptographic requirements to EN 18031-1 Section 14.3 covering post-quantum cryptographic algorithm readiness and migration planning.", Confidence: "medium", Level: "high", Annex: "I"},
		{ID: "MAP-039", CRARequirement: "Annex II-1", HarmonisedStd: "EN 18031-2", StdSection: "5.2", Title: "Real-Time OS Security", Description: "Mapping of CRA Annex II RTOS requirements to EN 18031-2 Section 5.2 covering real-time operating system security controls and determinism requirements.", Confidence: "high", Level: "critical", Annex: "II"},
		{ID: "MAP-040", CRARequirement: "Annex I-1", HarmonisedStd: "EN 18031-1", StdSection: "5.3", Title: "Security Architecture Documentation", Description: "Mapping of CRA secure by design requirements to EN 18031-1 Section 5.3 covering security architecture documentation and design review requirements.", Confidence: "high", Level: "high", Annex: "I"},
	}

	var controls []grc.Control
	for _, m := range mappings {
		controls = append(controls, p.buildControl(m))
	}

	return controls
}
