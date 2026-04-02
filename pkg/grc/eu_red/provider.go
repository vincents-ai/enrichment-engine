package eu_red

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
	FrameworkID = "EU_RED_Delegated_Act_2022"
	CatalogURL  = "https://raw.githubusercontent.com/eu-red/cybersecurity/main/controls.json"
)

// Provider fetches and parses EU Radio Equipment Directive cybersecurity requirements.
type Provider struct {
	store  storage.Backend
	logger *slog.Logger
}

// New creates a new EU RED Delegated Act provider.
func New(store storage.Backend, logger *slog.Logger) *Provider {
	return &Provider{
		store:  store,
		logger: logger,
	}
}

// Name returns the provider identifier.
func (p *Provider) Name() string {
	return "eu_red"
}

// Run fetches the RED requirements, parses controls, and writes to storage.
func (p *Provider) Run(ctx context.Context) (int, error) {
	p.logger.Info("fetching EU RED Delegated Act requirements", "url", CatalogURL)

	f, err := os.CreateTemp("", "eu_red_controls_*.json")
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

type redCatalog struct {
	Requirements []redRequirement `json:"requirements,omitempty"`
}

type redRequirement struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Family      string `json:"family,omitempty"`
	Description string `json:"description"`
	Level       string `json:"level,omitempty"`
	Article     string `json:"article,omitempty"`
}

func (p *Provider) parse(path string) ([]grc.Control, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var catalog redCatalog
	if err := json.NewDecoder(f).Decode(&catalog); err != nil {
		return nil, fmt.Errorf("decode RED catalog: %w", err)
	}

	var controls []grc.Control
	for _, req := range catalog.Requirements {
		controls = append(controls, p.buildControl(req))
	}

	return controls, nil
}

func (p *Provider) buildControl(req redRequirement) grc.Control {
	return grc.Control{
		Framework:   FrameworkID,
		ControlID:   req.ID,
		Title:       req.Title,
		Family:      req.Family,
		Description: req.Description,
		Level:       req.Level,
		References: []grc.Reference{
			{Source: "EU RED", URL: "https://digital-strategy.ec.europa.eu/en/policies/radio-equipment-directive", Section: req.Article},
		},
	}
}

func (p *Provider) writeControls(ctx context.Context, controls []grc.Control) (int, error) {
	p.logger.Info("parsed RED requirements", "count", len(controls))

	count := 0
	for _, ctrl := range controls {
		id := fmt.Sprintf("%s/%s", FrameworkID, ctrl.ControlID)
		if err := p.store.WriteControl(ctx, id, ctrl); err != nil {
			p.logger.Warn("failed to write control", "id", id, "error", err)
			continue
		}
		count++
	}

	p.logger.Info("wrote RED controls to storage", "count", count)
	return count, nil
}

func (p *Provider) generateEmbeddedControls() []grc.Control {
	requirements := []redRequirement{
		{ID: "RED-01", Title: "Network Protection", Family: "Article 3(3)(d) - Network Protection", Description: "Radio equipment shall incorporate safeguards to ensure that the network is not harmed, including measures to prevent the equipment from accessing or manipulating network resources in unauthorized ways that could degrade service or compromise network integrity.", Level: "critical", Article: "3(3)(d)"},
		{ID: "RED-02", Title: "Personal Data and Privacy Protection", Family: "Article 3(3)(e) - Privacy", Description: "Radio equipment shall incorporate safeguards to ensure protection of personal data and privacy of the user and of the subscriber, including encryption of personal data, protection against unauthorized data collection, and compliance with GDPR data protection principles.", Level: "critical", Article: "3(3)(e)"},
		{ID: "RED-03", Title: "Fraud Prevention", Family: "Article 3(3)(f) - Fraud Prevention", Description: "Radio equipment shall incorporate safeguards to ensure support of features to protect against fraud, including authentication mechanisms, secure transaction processing, and protection against unauthorized use of billing or payment functions.", Level: "high", Article: "3(3)(f)"},
		{ID: "RED-04", Title: "Secure Software Updates", Family: "Article 3(3)(d) - Network Protection", Description: "Radio equipment shall support secure software update mechanisms with integrity verification, authenticity checking, and protection against malicious firmware. Updates shall be delivered over secure channels with rollback protection.", Level: "critical", Article: "3(3)(d)"},
		{ID: "RED-05", Title: "Secure Default Configuration", Family: "Article 3(3)(d) - Network Protection", Description: "Radio equipment shall be placed on the market with secure default configurations including strong default credentials or user-defined passwords during setup, disabled unnecessary services, and minimum necessary network exposure.", Level: "critical", Article: "3(3)(d)"},
		{ID: "RED-06", Title: "Access Control for Radio Equipment", Family: "Article 3(3)(d) - Network Protection", Description: "Radio equipment shall implement access control mechanisms to prevent unauthorized access to device functions, configuration settings, and connected network resources. Authentication shall be required for administrative access.", Level: "high", Article: "3(3)(d)"},
		{ID: "RED-07", Title: "Encryption of Wireless Communications", Family: "Article 3(3)(e) - Privacy", Description: "Radio equipment shall encrypt wireless communications to protect data confidentiality and integrity during transmission. Approved cryptographic protocols shall be used for all wireless data exchanges including Wi-Fi, Bluetooth, and cellular communications.", Level: "critical", Article: "3(3)(e)"},
		{ID: "RED-08", Title: "Protection Against Unauthorized Access", Family: "Article 3(3)(d) - Network Protection", Description: "Radio equipment shall implement technical measures to prevent unauthorized access including brute force protection, account lockout mechanisms, and protection against common wireless attack vectors.", Level: "high", Article: "3(3)(d)"},
		{ID: "RED-09", Title: "Data Minimization in Radio Equipment", Family: "Article 3(3)(e) - Privacy", Description: "Radio equipment shall collect and process only the minimum personal data necessary for its intended function. Data collection purposes shall be clearly defined, and unnecessary data collection features shall be disabled by default.", Level: "high", Article: "3(3)(e)"},
		{ID: "RED-10", Title: "Secure Pairing and Connection", Family: "Article 3(3)(d) - Network Protection", Description: "Radio equipment shall implement secure pairing and connection establishment procedures for wireless protocols including Bluetooth pairing, Wi-Fi Protected Setup, and NFC connections with protection against man-in-the-middle attacks.", Level: "high", Article: "3(3)(d)"},
		{ID: "RED-11", Title: "Vulnerability Management for Radio Equipment", Family: "Article 3(3)(d) - Network Protection", Description: "Manufacturers of radio equipment shall establish vulnerability management processes including vulnerability identification, assessment, remediation, and disclosure. Security updates shall be provided for the expected product lifetime.", Level: "high", Article: "3(3)(d)"},
		{ID: "RED-12", Title: "Radio Interface Security", Family: "Article 3(3)(d) - Network Protection", Description: "Radio equipment shall secure its radio interface against unauthorized use including protection against rogue base stations, signal jamming detection, and secure authentication to legitimate network infrastructure.", Level: "high", Article: "3(3)(d)"},
		{ID: "RED-13", Title: "User Consent for Data Processing", Family: "Article 3(3)(e) - Privacy", Description: "Radio equipment shall obtain explicit user consent before collecting, processing, or transmitting personal data. Users shall be informed about data processing activities and have the ability to withdraw consent at any time.", Level: "high", Article: "3(3)(e)"},
		{ID: "RED-14", Title: "Secure Storage of Credentials", Family: "Article 3(3)(d) - Network Protection", Description: "Radio equipment shall securely store credentials, cryptographic keys, and sensitive configuration data using hardware-backed protection where available. Credentials shall not be stored in plaintext or easily extractable formats.", Level: "critical", Article: "3(3)(d)"},
		{ID: "RED-15", Title: "Protection of Payment Data", Family: "Article 3(3)(f) - Fraud Prevention", Description: "Radio equipment handling payment data shall comply with payment card industry security requirements including encryption of payment data, secure payment processing, and protection against skimming and replay attacks.", Level: "critical", Article: "3(3)(f)"},
		{ID: "RED-16", Title: "Logging and Audit Capabilities", Family: "Article 3(3)(d) - Network Protection", Description: "Radio equipment shall maintain security-relevant logs including authentication events, configuration changes, and detected security anomalies. Logs shall be protected against unauthorized modification and accessible for security analysis.", Level: "standard", Article: "3(3)(d)"},
		{ID: "RED-17", Title: "Secure Decommissioning", Family: "Article 3(3)(e) - Privacy", Description: "Radio equipment shall provide mechanisms for secure data deletion when the device is disposed of or transferred to another user. Factory reset procedures shall securely erase all personal data and security credentials.", Level: "high", Article: "3(3)(e)"},
		{ID: "RED-18", Title: "Interference Protection", Family: "Article 3(3)(d) - Network Protection", Description: "Radio equipment shall incorporate measures to protect against electromagnetic interference that could affect security functions, and shall not cause harmful interference to other equipment or network infrastructure.", Level: "standard", Article: "3(3)(d)"},
		{ID: "RED-19", Title: "Security Documentation for Users", Family: "Article 3(3)(d) - Network Protection", Description: "Manufacturers shall provide clear security documentation with radio equipment including secure setup instructions, security feature descriptions, and guidance for maintaining security throughout the product lifetime.", Level: "standard", Article: "3(3)(d)"},
		{ID: "RED-20", Title: "Conformity Assessment for RED Cybersecurity", Family: "Article 3(3) - Conformity", Description: "Radio equipment shall undergo conformity assessment demonstrating compliance with cybersecurity requirements under Article 3(3)(d), (e), and (f) before being placed on the EU market, with appropriate technical documentation and CE marking.", Level: "critical", Article: "3(3)"},
	}

	var controls []grc.Control
	for _, req := range requirements {
		controls = append(controls, p.buildControl(req))
	}

	return controls
}
