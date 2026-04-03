package eu_cybersecurity_act

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
	FrameworkID = "EU_Cybersecurity_Act_2019_881"
)

var CatalogURL = "https://raw.githubusercontent.com/eu-cybersecurity-act/certification/main/requirements.json"

// Provider fetches and parses EU Cybersecurity Act certification framework requirements.
type Provider struct {
	store  storage.Backend
	logger *slog.Logger
}

// New creates a new EU Cybersecurity Act provider.
func New(store storage.Backend, logger *slog.Logger) *Provider {
	return &Provider{
		store:  store,
		logger: logger,
	}
}

// Name returns the provider identifier.
func (p *Provider) Name() string {
	return "eu_cybersecurity_act"
}

// Run fetches the certification requirements, parses controls, and writes them to storage.
func (p *Provider) Run(ctx context.Context) (int, error) {
	p.logger.Info("fetching EU Cybersecurity Act requirements", "url", CatalogURL)

	f, err := os.CreateTemp("", "eu_cybersecurity_act_*.json")
	if err != nil {
		return 0, fmt.Errorf("create temp file: %w", err)
	}
	destPath := f.Name()
	f.Close()
	defer os.Remove(destPath)
	if err := p.download(ctx, CatalogURL, destPath); err != nil {
		p.logger.Warn("download failed, falling back to embedded requirements", "error", err)
		controls := p.generateEmbeddedControls()
		return p.writeControls(ctx, controls)
	}

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

type csaCatalog struct {
	Requirements []csaRequirement `json:"requirements,omitempty"`
}

type csaRequirement struct {
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

	var catalog csaCatalog
	if err := json.NewDecoder(f).Decode(&catalog); err != nil {
		return nil, fmt.Errorf("decode CSA catalog: %w", err)
	}

	var controls []grc.Control
	for _, req := range catalog.Requirements {
		controls = append(controls, p.buildControl(req))
	}

	return controls, nil
}

func (p *Provider) buildControl(req csaRequirement) grc.Control {
	return grc.Control{
		Framework:   FrameworkID,
		ControlID:   req.ID,
		Title:       req.Title,
		Family:      req.Family,
		Description: req.Description,
		Level:       req.Level,
		References: []grc.Reference{
			{Source: "EU Cybersecurity Act", URL: "https://digital-strategy.ec.europa.eu/en/policies/cybersecurity-certification", Section: req.Category},
		},
	}
}

func (p *Provider) writeControls(ctx context.Context, controls []grc.Control) (int, error) {
	p.logger.Info("parsed CSA requirements", "count", len(controls))

	count := 0
	for _, ctrl := range controls {
		id := fmt.Sprintf("%s/%s", FrameworkID, ctrl.ControlID)
		if err := p.store.WriteControl(ctx, id, ctrl); err != nil {
			p.logger.Warn("failed to write control", "id", id, "error", err)
			continue
		}
		count++
	}

	p.logger.Info("wrote CSA controls to storage", "count", count)
	return count, nil
}

func (p *Provider) generateEmbeddedControls() []grc.Control {
	requirements := []csaRequirement{
		{ID: "CSA-01", Title: "EU Certification Scheme Governance", Family: "Governance Framework", Description: "Establishment of European cybersecurity certification schemes under Regulation (EU) 2019/881. ENISA shall prepare candidate schemes and the European Cybersecurity Certification Group shall provide oversight and guidance.", Level: "high", Category: "Governance"},
		{ID: "CSA-02", Title: "Assurance Levels Definition", Family: "Certification Levels", Description: "Definition of three assurance levels (substantial, high, comprehensive) for ICT product certification. Each level specifies increasing rigor of evaluation, testing, and ongoing surveillance requirements.", Level: "critical", Category: "Assurance"},
		{ID: "CSA-03", Title: "Conformity Assessment Bodies", Family: "Accreditation", Description: "Requirements for conformity assessment bodies (CABs) performing cybersecurity certification assessments. CABs must be accredited by national accreditation bodies and demonstrate technical competence.", Level: "high", Category: "Accreditation"},
		{ID: "CSA-04", Title: "National Certification Authorities", Family: "Governance Framework", Description: "Member States shall designate national cybersecurity certification authorities responsible for overseeing certification schemes, monitoring certified products, and enforcing compliance requirements.", Level: "high", Category: "Governance"},
		{ID: "CSA-05", Title: "EU-Wide Certificate Recognition", Family: "Mutual Recognition", Description: "Certificates issued under EU cybersecurity certification schemes shall be recognized across all Member States without additional national requirements, ensuring a single market for certified ICT products.", Level: "high", Category: "Mutual Recognition"},
		{ID: "CSA-06", Title: "Technical Documentation Requirements", Family: "Documentation", Description: "Manufacturers shall maintain comprehensive technical documentation including security architecture, threat analysis, test results, and evidence of compliance with certification scheme requirements.", Level: "standard", Category: "Documentation"},
		{ID: "CSA-07", Title: "Vulnerability Management Obligations", Family: "Vulnerability Handling", Description: "Certificate holders shall establish vulnerability management processes including identification, assessment, remediation, and disclosure of security vulnerabilities throughout the certificate validity period.", Level: "critical", Category: "Vulnerability"},
		{ID: "CSA-08", Title: "Certificate Validity and Renewal", Family: "Certification Lifecycle", Description: "Cybersecurity certificates shall have defined validity periods with requirements for renewal assessment. Changes to certified products may require re-certification or supplementary assessment.", Level: "standard", Category: "Lifecycle"},
		{ID: "CSA-09", Title: "Market Surveillance Requirements", Family: "Enforcement", Description: "National authorities shall conduct market surveillance of certified ICT products to verify ongoing compliance with certification requirements and take corrective action for non-compliant products.", Level: "high", Category: "Enforcement"},
		{ID: "CSA-10", Title: "Peer Evaluation Mechanism", Family: "Quality Assurance", Description: "ENISA shall organize peer evaluations of conformity assessment bodies to ensure consistent application of certification requirements and maintain confidence in the certification framework.", Level: "high", Category: "Quality Assurance"},
		{ID: "CSA-11", Title: "Security Functional Requirements", Family: "Technical Requirements", Description: "Certified ICT products shall implement security functions including access control, authentication, encryption, audit logging, and secure communication protocols appropriate to the assurance level.", Level: "critical", Category: "Technical"},
		{ID: "CSA-12", Title: "Security Assurance Requirements", Family: "Technical Requirements", Description: "Evaluation of development processes, life cycle support, vulnerability assessment, and testing rigor. Higher assurance levels require more rigorous development controls and independent testing.", Level: "critical", Category: "Technical"},
		{ID: "CSA-13", Title: "Incident Reporting Obligations", Family: "Incident Management", Description: "Certificate holders shall report significant cybersecurity incidents affecting certified products to the relevant national certification authority and ENISA within defined timeframes.", Level: "high", Category: "Incident"},
		{ID: "CSA-14", Title: "Certificate Suspension and Withdrawal", Family: "Certification Lifecycle", Description: "Procedures for suspension, restriction, or withdrawal of certificates when products no longer meet certification requirements, including notification obligations and market recall procedures.", Level: "high", Category: "Lifecycle"},
		{ID: "CSA-15", Title: "Use of Certification Marks", Family: "Marking", Description: "Rules for the use of EU cybersecurity certification marks on certified products, packaging, and documentation. Marks shall clearly indicate the assurance level and validity period.", Level: "standard", Category: "Marking"},
		{ID: "CSA-16", Title: "Evaluation Methodology Standards", Family: "Technical Requirements", Description: "Certification schemes shall specify evaluation methodologies including testing methods, vulnerability assessment approaches, and penetration testing requirements aligned with international standards.", Level: "high", Category: "Technical"},
		{ID: "CSA-17", Title: "Supply Chain Security Assessment", Family: "Supply Chain", Description: "Assessment of supply chain security including third-party component evaluation, software bill of materials verification, and supplier security requirement compliance for certified products.", Level: "high", Category: "Supply Chain"},
		{ID: "CSA-18", Title: "Cross-Border Cooperation", Family: "Governance Framework", Description: "Mechanisms for cooperation between national certification authorities, ENISA, and the European Cybersecurity Certification Group to ensure consistent implementation across the EU.", Level: "standard", Category: "Governance"},
		{ID: "CSA-19", Title: "International Recognition Agreements", Family: "Mutual Recognition", Description: "Framework for mutual recognition agreements with non-EU countries for cybersecurity certificates, subject to adequacy assessments and Commission approval.", Level: "standard", Category: "Mutual Recognition"},
		{ID: "CSA-20", Title: "Public Certificate Registry", Family: "Transparency", Description: "ENISA shall maintain a public registry of EU cybersecurity certificates including certificate details, validity periods, assurance levels, and any restrictions or suspensions.", Level: "standard", Category: "Transparency"},
		{ID: "CSA-21", Title: "Penetration Testing Requirements", Family: "Technical Requirements", Description: "Requirements for independent penetration testing of certified products, including scope definition, testing methodologies, vulnerability exploitation assessment, and remediation verification.", Level: "high", Category: "Technical"},
		{ID: "CSA-22", Title: "Source Code Review Requirements", Family: "Technical Requirements", Description: "Requirements for source code review and analysis as part of comprehensive assurance level certification, including static analysis, manual review, and secure coding standard compliance.", Level: "high", Category: "Technical"},
		{ID: "CSA-23", Title: "Cryptographic Module Validation", Family: "Technical Requirements", Description: "Requirements for cryptographic module validation within certification schemes, including algorithm approval, key management assessment, and side-channel attack resistance evaluation.", Level: "critical", Category: "Technical"},
		{ID: "CSA-24", Title: "Ongoing Surveillance Requirements", Family: "Certification Lifecycle", Description: "Requirements for ongoing surveillance of certified products including periodic audits, vulnerability monitoring, change notification, and compliance verification throughout certificate validity.", Level: "high", Category: "Lifecycle"},
		{ID: "CSA-25", Title: "Stakeholder Consultation Process", Family: "Governance Framework", Description: "Requirements for stakeholder consultation during development of certification schemes, including industry, academia, civil society, and Member State input through ENISA advisory processes.", Level: "standard", Category: "Governance"},
	}

	var controls []grc.Control
	for _, req := range requirements {
		controls = append(controls, p.buildControl(req))
	}

	return controls
}
