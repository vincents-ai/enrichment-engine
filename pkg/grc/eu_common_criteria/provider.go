package eu_common_criteria

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
	FrameworkID = "EU_Common_Criteria_2024"
)

var CatalogURL = "https://raw.githubusercontent.com/eu-common-criteria/certification/main/controls.json"

// Provider fetches and parses EU Common Criteria certification controls.
type Provider struct {
	store  storage.Backend
	logger *slog.Logger
}

// New creates a new EU Common Criteria provider.
func New(store storage.Backend, logger *slog.Logger) *Provider {
	return &Provider{
		store:  store,
		logger: logger,
	}
}

// Name returns the provider identifier.
func (p *Provider) Name() string {
	return "eu_common_criteria"
}

// Run fetches the Common Criteria controls, parses them, and writes to storage.
func (p *Provider) Run(ctx context.Context) (int, error) {
	p.logger.Info("fetching EU Common Criteria certification controls", "url", CatalogURL)

	f, err := os.CreateTemp("", "eu_common_criteria_*.json")
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

type ccCatalog struct {
	Controls []ccControl `json:"controls,omitempty"`
}

type ccControl struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Family      string `json:"family,omitempty"`
	Description string `json:"description"`
	Level       string `json:"level,omitempty"`
	EAL         string `json:"eal_level,omitempty"`
}

func (p *Provider) parse(path string) ([]grc.Control, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var catalog ccCatalog
	if err := json.NewDecoder(f).Decode(&catalog); err != nil {
		return nil, fmt.Errorf("decode Common Criteria catalog: %w", err)
	}

	var controls []grc.Control
	for _, ctrl := range catalog.Controls {
		controls = append(controls, p.buildControl(ctrl))
	}

	return controls, nil
}

func (p *Provider) buildControl(ctrl ccControl) grc.Control {
	return grc.Control{
		Framework:   FrameworkID,
		ControlID:   ctrl.ID,
		Title:       ctrl.Title,
		Family:      ctrl.Family,
		Description: ctrl.Description,
		Level:       ctrl.Level,
		References: []grc.Reference{
			{Source: "Common Criteria", URL: "https://www.commoncriteriaportal.org", Section: ctrl.EAL},
		},
	}
}

func (p *Provider) writeControls(ctx context.Context, controls []grc.Control) (int, error) {
	p.logger.Info("parsed Common Criteria controls", "count", len(controls))

	count := 0
	for _, ctrl := range controls {
		id := fmt.Sprintf("%s/%s", FrameworkID, ctrl.ControlID)
		if err := p.store.WriteControl(ctx, id, ctrl); err != nil {
			p.logger.Warn("failed to write control", "id", id, "error", err)
			continue
		}
		count++
	}

	p.logger.Info("wrote Common Criteria controls to storage", "count", count)
	return count, nil
}

func (p *Provider) generateEmbeddedControls() []grc.Control {
	controls := []ccControl{
		{ID: "CC-001", Title: "Security Target Definition", Family: "ISO/IEC 15408-1 - Introduction", Description: "Definition of the Security Target (ST) document specifying security requirements for the Target of Evaluation (TOE) including security problem definition, security objectives, and security requirements.", Level: "critical", EAL: "All EALs"},
		{ID: "CC-002", Title: "Target of Evaluation Description", Family: "ISO/IEC 15408-1 - Introduction", Description: "Comprehensive description of the Target of Evaluation including TOE type, functionality, physical scope, logical scope, and operational environment in which the TOE is intended to operate securely.", Level: "high", EAL: "All EALs"},
		{ID: "CC-003", Title: "Security Problem Definition", Family: "ISO/IEC 15408-1 - Introduction", Description: "Identification and description of threats, organizational security policies, and assumptions that the TOE is designed to counter, forming the basis for deriving security objectives and requirements.", Level: "critical", EAL: "All EALs"},
		{ID: "CC-004", Title: "Security Objectives", Family: "ISO/IEC 15408-1 - Introduction", Description: "Definition of security objectives for the TOE and its operational environment, addressing identified threats and organizational security policies with clear traceability to security requirements.", Level: "critical", EAL: "All EALs"},
		{ID: "CC-005", Title: "Security Functional Requirements", Family: "ISO/IEC 15408-2 - Functional Requirements", Description: "Specification of security functional requirements (SFRs) from Part 2 catalog covering security audit, communication, cryptographic support, user data protection, identification and authentication, and security management.", Level: "critical", EAL: "All EALs"},
		{ID: "CC-006", Title: "Security Audit Functions", Family: "ISO/IEC 15408-2 - FAU Class", Description: "Requirements for automatic audit generation, audit storage protection, audit review, and audit event selection to support security monitoring and forensic analysis of the TOE.", Level: "high", EAL: "EAL2+"},
		{ID: "CC-007", Title: "Cryptographic Support Requirements", Family: "ISO/IEC 15408-2 - FCS Class", Description: "Requirements for cryptographic key generation, distribution, access, destruction, and cryptographic operation execution using approved algorithms and key sizes.", Level: "critical", EAL: "EAL2+"},
		{ID: "CC-008", Title: "User Data Protection", Family: "ISO/IEC 15408-2 - FDP Class", Description: "Requirements for user data access control, data authentication, data integrity, data export/import control, and residual information protection to prevent unauthorized data access.", Level: "critical", EAL: "EAL2+"},
		{ID: "CC-009", Title: "Identification and Authentication", Family: "ISO/IEC 15408-2 - FIA Class", Description: "Requirements for user identification, authentication, credential management, authentication feedback, and single sign-on to ensure only authorized users access TOE functions.", Level: "critical", EAL: "EAL2+"},
		{ID: "CC-010", Title: "Security Management Functions", Family: "ISO/IEC 15408-2 - FMT Class", Description: "Requirements for security attribute management, role-based access control management, TSF data management, and specification of management functions to control TOE security behavior.", Level: "high", EAL: "EAL2+"},
		{ID: "CC-011", Title: "Protection of the TSF", Family: "ISO/IEC 15408-2 - FPT Class", Description: "Requirements for protection of TSF data, TSF execution integrity, reliable time stamps, and inter-TSF basic TSF data consistency to protect the security functions themselves.", Level: "critical", EAL: "EAL3+"},
		{ID: "CC-012", Title: "TOE Access Requirements", Family: "ISO/IEC 15408-2 - FTA Class", Description: "Requirements for TSF-initiated and user-initiated sessions, session locking, and termination to control access to the TOE and manage session lifecycle securely.", Level: "high", EAL: "EAL2+"},
		{ID: "CC-013", Title: "Trusted Path/Channel", Family: "ISO/IEC 15408-2 - FTP Class", Description: "Requirements for trusted path between users and the TSF, and trusted channel between separated TOEs to protect communications against interception and modification.", Level: "high", EAL: "EAL3+"},
		{ID: "CC-014", Title: "Security Assurance Requirements", Family: "ISO/IEC 15408-3 - Assurance Requirements", Description: "Specification of security assurance requirements (SARs) from Part 3 catalog covering development, guidance documents, life cycle support, tests, vulnerability assessment, and security target evaluation.", Level: "critical", EAL: "All EALs"},
		{ID: "CC-015", Title: "Development Assurance", Family: "ISO/IEC 15408-3 - ADV Class", Description: "Requirements for functional specification, security architecture, internal structure representation, and formal verification of the TOE design and implementation.", Level: "critical", EAL: "EAL1-EAL7"},
		{ID: "CC-016", Title: "Guidance Document Requirements", Family: "ISO/IEC 15408-3 - AGD Class", Description: "Requirements for operational user guidance and preparative procedures documentation ensuring users and administrators can configure and operate the TOE securely.", Level: "standard", EAL: "All EALs"},
		{ID: "CC-017", Title: "Life Cycle Support", Family: "ISO/IEC 15408-3 - ALC Class", Description: "Requirements for configuration management, delivery procedures, development security, life cycle model definition, tools and CM automation, and problem tracking throughout the TOE lifecycle.", Level: "high", EAL: "EAL2-EAL7"},
		{ID: "CC-018", Title: "Testing Requirements", Family: "ISO/IEC 15408-3 - ATE Class", Description: "Requirements for independent testing of the TSF including test coverage, test depth, functional testing, and independent sample testing to verify security function implementation.", Level: "high", EAL: "EAL1-EAL7"},
		{ID: "CC-019", Title: "Vulnerability Assessment", Family: "ISO/IEC 15408-3 - AVA Class", Description: "Requirements for vulnerability analysis including identification of potential vulnerabilities, penetration testing, and assessment of resistance to identified attack vectors.", Level: "critical", EAL: "EAL2-EAL7"},
		{ID: "CC-020", Title: "Evaluation Assurance Level 4", Family: "ISO/IEC 15408-3 - EAL4", Description: "EAL4 represents methodical design, testing, and review providing moderate to high level of independently assured security. Suitable for conventional commodity TOEs requiring rigorous development practices.", Level: "critical", EAL: "EAL4"},
		{ID: "CC-021", Title: "Evaluation Assurance Level 5", Family: "ISO/IEC 15408-3 - EAL5", Description: "EAL5 represents semi-formally designed and tested TOEs providing high level of independently assured security. Requires rigorous development environment and specialized security engineering techniques.", Level: "critical", EAL: "EAL5"},
		{ID: "CC-022", Title: "Protection Profile Compliance", Family: "ISO/IEC 15408-1 - Protection Profiles", Description: "Requirements for conformance to Protection Profiles (PPs) defining implementation-independent security requirements for a category of TOEs with specific security purposes.", Level: "critical", EAL: "All EALs"},
		{ID: "CC-023", Title: "Mutual Recognition Agreement", Family: "CCRA - Mutual Recognition", Description: "Requirements for certificates issued under the Common Criteria Recognition Arrangement (CCRA) to be mutually recognized by participating nations, ensuring international validity of evaluations.", Level: "high", EAL: "All EALs"},
		{ID: "CC-024", Title: "Certification Body Requirements", Family: "CCRA - Certification", Description: "Requirements for certification bodies conducting Common Criteria evaluations including accreditation, technical competence, independence, and adherence to certification methodology and schemes.", Level: "high", EAL: "All EALs"},
		{ID: "CC-025", Title: "Maintenance of Certification", Family: "CCRA - Maintenance", Description: "Requirements for maintaining Common Criteria certification including handling of TOE modifications, security updates, vulnerability reports, and periodic surveillance to ensure continued compliance.", Level: "high", EAL: "All EALs"},
	}

	var result []grc.Control
	for _, ctrl := range controls {
		result = append(result, p.buildControl(ctrl))
	}

	return result
}
