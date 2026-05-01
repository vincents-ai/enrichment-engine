package pci_dss

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/vincents-ai/enrichment-engine/pkg/grc"
	"github.com/vincents-ai/enrichment-engine/pkg/storage"
)

const (
	FrameworkID = "PCI_DSS_v4"
)

var CatalogURL = "https://raw.githubusercontent.com/pci-dss/controls/main/pci_dss_v4_controls.json"

// Provider fetches and parses PCI DSS v4.0 controls.
type Provider struct {
	store  storage.Backend
	logger *slog.Logger
}

// New creates a new PCI DSS provider.
func New(store storage.Backend, logger *slog.Logger) *Provider {
	return &Provider{
		store:  store,
		logger: logger,
	}
}

// Name returns the provider identifier.
func (p *Provider) Name() string {
	return "pci_dss"
}

// Run fetches the PCI DSS controls catalog, parses controls, and writes them to storage.
func (p *Provider) Run(ctx context.Context) (int, error) {
	p.logger.Info("fetching PCI DSS v4.0 controls catalog", "url", CatalogURL)

	f, err := os.CreateTemp("", "pci_dss_catalog_*.json")
	if err != nil {
		return 0, fmt.Errorf("create temp file: %w", err)
	}
	destPath := f.Name()
	f.Close()
	defer os.Remove(destPath)
	if err := p.download(ctx, CatalogURL, destPath); err != nil {
		p.logger.Warn("failed to download catalog, using embedded fallback", "error", err)
		return p.writeEmbeddedControls(ctx)
	}

	controls, err := p.parse(destPath)
	if err != nil {
		p.logger.Warn("failed to parse catalog, using embedded fallback", "error", err)
		return p.writeEmbeddedControls(ctx)
	}

	p.logger.Info("parsed PCI DSS controls", "count", len(controls))

	count := 0
	for _, ctrl := range controls {
		id := fmt.Sprintf("%s/%s", FrameworkID, ctrl.ControlID)
		if err := p.store.WriteControl(ctx, id, ctrl); err != nil {
			p.logger.Warn("failed to write control", "id", id, "error", err)
			continue
		}
		count++
	}

	p.logger.Info("wrote PCI DSS controls to storage", "count", count)
	return count, nil
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

type pciCatalog struct {
	Controls []pciControl `json:"controls"`
	Groups   []pciGroup   `json:"groups,omitempty"`
}

type pciGroup struct {
	ID          string       `json:"id"`
	Requirement string       `json:"requirement"`
	Title       string       `json:"title"`
	Controls    []pciControl `json:"controls"`
}

type pciControl struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
	Requirement string `json:"requirement,omitempty"`
	Level       string `json:"level,omitempty"`
}

func (p *Provider) parse(path string) ([]grc.Control, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var catalog pciCatalog
	if err := json.NewDecoder(f).Decode(&catalog); err != nil {
		return nil, fmt.Errorf("decode PCI DSS catalog: %w", err)
	}

	var controls []grc.Control

	for _, group := range catalog.Groups {
		for _, ctrl := range group.Controls {
			controls = append(controls, p.toControl(ctrl, group.Title, group.Requirement))
		}
	}

	if len(controls) == 0 {
		for _, ctrl := range catalog.Controls {
			controls = append(controls, p.toControl(ctrl, ctrl.Requirement, ctrl.Requirement))
		}
	}

	return controls, nil
}

func (p *Provider) toControl(ctrl pciControl, family, requirement string) grc.Control {
	level := "standard"
	if ctrl.Level != "" {
		level = strings.ToLower(ctrl.Level)
	}

	return grc.Control{
		Framework:   FrameworkID,
		ControlID:   ctrl.ID,
		Title:       ctrl.Title,
		Family:      family,
		Description: ctrl.Description,
		Level:       level,
		RelatedCWEs: pciCWEs(ctrl.ID),
		References: []grc.Reference{
			{
				Source:  "PCI DSS v4.0",
				Section: requirement,
			},
		},
	}
}

func (p *Provider) writeEmbeddedControls(ctx context.Context) (int, error) {
	p.logger.Info("using embedded PCI DSS v4.0 controls")

	controls := embeddedControls()
	count := 0
	for _, ctrl := range controls {
		id := fmt.Sprintf("%s/%s", FrameworkID, ctrl.ControlID)
		if err := p.store.WriteControl(ctx, id, ctrl); err != nil {
			p.logger.Warn("failed to write control", "id", id, "error", err)
			continue
		}
		count++
	}

	p.logger.Info("wrote embedded PCI DSS controls to storage", "count", count)
	return count, nil
}

var pciCWEMap = map[string][]string{
	"1.1":  {"CWE-284", "CWE-668"},
	"1.2":  {"CWE-284", "CWE-668"},
	"1.3":  {"CWE-284", "CWE-668"},
	"1.4":  {"CWE-16", "CWE-1188"},
	"1.5":  {"CWE-1104", "CWE-937"},
	"2.1":  {"CWE-798", "CWE-254", "CWE-521"},
	"2.2":  {"CWE-16", "CWE-1188"},
	"2.3":  {"CWE-311", "CWE-320", "CWE-326"},
	"2.4":  {"CWE-16", "CWE-1188"},
	"3.1":  {"CWE-200", "CWE-212"},
	"3.2":  {"CWE-312", "CWE-311", "CWE-200"},
	"3.3":  {"CWE-200", "CWE-359"},
	"3.4":  {"CWE-311", "CWE-312", "CWE-316"},
	"3.5":  {"CWE-320", "CWE-326", "CWE-311"},
	"4.1":  {"CWE-319", "CWE-326"},
	"4.2":  {"CWE-319", "CWE-200"},
	"4.3":  {"CWE-319", "CWE-326"},
	"5.1":  {"CWE-94", "CWE-506"},
	"5.2":  {"CWE-94", "CWE-506"},
	"5.3":  {"CWE-94", "CWE-506"},
	"6.1":  {"CWE-1104", "CWE-937"},
	"6.2":  {"CWE-94", "CWE-95", "CWE-1336", "CWE-502"},
	"6.3":  {"CWE-16", "CWE-494"},
	"6.4":  {"CWE-79", "CWE-89", "CWE-78", "CWE-102", "CWE-306", "CWE-94"},
	"6.5":  {"CWE-94", "CWE-78", "CWE-1059", "CWE-693", "CWE-119", "CWE-502", "CWE-22"},
	"7.1":  {"CWE-284", "CWE-285", "CWE-862"},
	"7.2":  {"CWE-284", "CWE-285", "CWE-862"},
	"7.3":  {"CWE-284", "CWE-285", "CWE-862"},
	"8.1":  {"CWE-287", "CWE-798"},
	"8.2":  {"CWE-287", "CWE-308", "CWE-522"},
	"8.3":  {"CWE-521", "CWE-265"},
	"8.4":  {"CWE-287", "CWE-308"},
	"8.5":  {"CWE-798", "CWE-287"},
	"8.6":  {"CWE-287", "CWE-522"},
	"10.1": {"CWE-778"},
	"10.2": {"CWE-778"},
	"10.3": {"CWE-778"},
	"10.4": {"CWE-311", "CWE-312"},
	"10.5": {"CWE-778", "CWE-693"},
	"10.6": {"CWE-778"},
	"10.7": {"CWE-778", "CWE-693"},
	"11.1": {"CWE-778", "CWE-693"},
	"11.2": {"CWE-1104", "CWE-937"},
	"11.3": {"CWE-1104", "CWE-937"},
	"11.4": {"CWE-778", "CWE-693"},
	"11.5": {"CWE-778", "CWE-693"},
	"11.6": {"CWE-778", "CWE-693"},
	"12.1": {"CWE-16", "CWE-1188"},
	"12.2": {"CWE-1104", "CWE-937"},
	"12.3": {"CWE-16", "CWE-1188"},
	"12.5": {"CWE-919", "CWE-937"},
	"12.6": {"CWE-778", "CWE-693"},
	"12.7": {"CWE-798", "CWE-287"},
	"12.8": {"CWE-1104", "CWE-937"},
}

func pciCWEs(controlID string) []string {
	return pciCWEMap[controlID]
}

func embeddedControls() []grc.Control {
	controls := []grc.Control{}

	req1 := []struct{ id, title, desc string }{
		{"1.1", "Network security controls defined", "Network security controls (NSCs) are defined and implemented to protect the cardholder data environment (CDE) from unauthorized access."},
		{"1.2", "Network segmentation", "Network segmentation is implemented to isolate the CDE from other networks, reducing the scope of PCI DSS assessment."},
		{"1.3", "Direct public access restrictions", "Direct public access between the internet and the CDE is prohibited through proper firewall and router configurations."},
		{"1.4", "NSC configuration standards", "Configuration standards are defined and implemented for all NSCs to ensure secure operation."},
		{"1.5", "Risk identification and mitigation", "Risks to the CDE are identified, evaluated, and managed through regular risk assessments and mitigation activities."},
	}

	req2 := []struct{ id, title, desc string }{
		{"2.1", "Vendor defaults changed", "All vendor-supplied default accounts, passwords, and security parameters are changed before systems are installed on the network."},
		{"2.2", "System hardening", "System configuration standards are implemented to harden all system components against known vulnerabilities."},
		{"2.3", "Secure cryptographic key management", "Cryptographic keys are managed securely throughout their lifecycle, including generation, distribution, storage, and destruction."},
		{"2.4", "Security policies and standards", "An information security policy is established, published, maintained, and disseminated to all relevant personnel."},
	}

	req3 := []struct{ id, title, desc string }{
		{"3.1", "Cardholder data retention limits", "Cardholder data retention is limited to what is necessary for legal, regulatory, or business requirements."},
		{"3.2", "Sensitive authentication data storage prohibited", "Sensitive authentication data (SAD) is not stored after authorization, even if encrypted."},
		{"3.3", "Primary account number masking", "The primary account number (PAN) is masked when displayed, with only the first six and last four digits visible."},
		{"3.4", "PAN encryption at rest", "Rendered PAN unreadable anywhere it is stored through strong cryptography, truncation, hashing, or tokenization."},
		{"3.5", "Cryptographic key management processes", "Procedures are implemented for managing cryptographic keys used for rendering stored cardholder data unreadable."},
	}

	req4 := []struct{ id, title, desc string }{
		{"4.1", "Strong cryptography for transmission", "Strong cryptography and security protocols are used to safeguard sensitive cardholder data during transmission over open, public networks."},
		{"4.2", "PAN protection during transmission", "The PAN is rendered unreadable or protected with strong cryptography whenever it is sent via end-user messaging technologies."},
		{"4.3", "Cryptographic protocol validation", "Cryptographic protocols are validated to ensure they are implemented correctly and securely."},
	}

	req5 := []struct{ id, title, desc string }{
		{"5.1", "Malicious software detection", "Anti-malware mechanisms are deployed on all system components to detect and protect against malicious software."},
		{"5.2", "Anti-malware processes", "Anti-malware processes and mechanisms are kept current, actively running, and cannot be disabled by users."},
		{"5.3", "Anti-malware effectiveness", "Anti-malware mechanisms are evaluated for effectiveness and updated as needed to address emerging threats."},
	}

	req6 := []struct{ id, title, desc string }{
		{"6.1", "Vulnerability identification", "Security vulnerabilities are identified and managed using industry-recognized sources and risk assessment processes."},
		{"6.2", "Secure software development", "Software development practices incorporate secure coding techniques and address common software vulnerabilities."},
		{"6.3", "Change control processes", "Changes to all system components are managed through formal change control processes."},
		{"6.4", "Public-facing web application protection", "Public-facing web applications are protected against known attacks through secure development, WAF deployment, or both."},
		{"6.5", "Software development lifecycle", "A secure software development lifecycle is implemented for custom software and applications."},
	}

	req7 := []struct{ id, title, desc string }{
		{"7.1", "Access control requirements", "Access to system components and cardholder data is restricted based on need to know and job function."},
		{"7.2", "Access control system", "An access control system is implemented for all system components that restricts access based on a user's need to know."},
		{"7.3", "Access control configuration", "Access control systems are configured to enforce least privilege access to system components and data."},
	}

	req8 := []struct{ id, title, desc string }{
		{"8.1", "User identification", "All users are assigned a unique ID before access to system components or cardholder data is allowed."},
		{"8.2", "Authentication mechanisms", "Strong authentication mechanisms are implemented, including multi-factor authentication for all access to the CDE."},
		{"8.3", "Password policy", "Strong passwords and passphrases are enforced through policy and technical controls."},
		{"8.4", "Multi-factor authentication", "Multi-factor authentication is implemented for all non-console administrative access and all access into the CDE."},
		{"8.5", "Account management", "Additional requirements for account management include timely removal of unnecessary accounts and regular review."},
		{"8.6", "Application authentication", "Applications accessing the CDE are authenticated using strong mechanisms."},
	}

	req9 := []struct{ id, title, desc string }{
		{"9.1", "Physical access controls", "Physical access controls are implemented to restrict access to system components in the CDE."},
		{"9.2", "Visitor management", "Procedures are implemented to identify and authorize visitor access to facilities housing system components."},
		{"9.3", "Physical access logging", "Physical access to sensitive areas is logged and monitored."},
		{"9.4", "Media protection", "All media containing cardholder data is physically secured and classified according to sensitivity."},
		{"9.5", "Media distribution controls", "Distribution of media containing cardholder data is controlled and tracked."},
		{"9.6", "Media destruction", "Media containing cardholder data is securely destroyed when no longer needed for business or legal reasons."},
	}

	req10 := []struct{ id, title, desc string }{
		{"10.1", "Audit trail implementation", "Audit trails are implemented to link all access to system components and cardholder data to individual users."},
		{"10.2", "Automated audit logging", "Automated audit logging is implemented for all system components to record security-relevant events."},
		{"10.3", "Audit log content", "Audit log entries include sufficient information to identify what occurred, who performed the action, and when."},
		{"10.4", "Log protection", "Audit logs are protected from unauthorized access and modification."},
		{"10.5", "Log review", "Audit logs are reviewed at least daily for anomalies and security events."},
		{"10.6", "Log retention", "Audit logs are retained for at least 12 months, with at least 3 months immediately available for analysis."},
		{"10.7", "Failure monitoring", "Failure of critical security control systems is detected, reported, and responded to promptly."},
	}

	req11 := []struct{ id, title, desc string }{
		{"11.1", "Intrusion detection and prevention", "Intrusion detection and prevention systems are deployed to detect and block attacks in the CDE."},
		{"11.2", "Vulnerability scanning", "Internal and external vulnerability scans are performed regularly to identify and remediate vulnerabilities."},
		{"11.3", "Penetration testing", "Penetration testing is performed at least annually and after significant changes to the network or applications."},
		{"11.4", "Intrusion detection monitoring", "Intrusion detection and prevention systems are monitored and tuned to detect unauthorized activity."},
		{"11.5", "File integrity monitoring", "File integrity monitoring solutions are deployed to detect unauthorized changes to critical system files."},
		{"11.6", "Unauthorized device detection", "Processes are implemented to detect and respond to unauthorized network connections and devices."},
	}

	req12 := []struct{ id, title, desc string }{
		{"12.1", "Information security policy", "An information security policy is established, published, maintained, and disseminated to all personnel."},
		{"12.2", "Risk assessment program", "A formal risk assessment program is implemented to identify and manage risks to cardholder data."},
		{"12.3", "Acceptable use policies", "Acceptable use policies for critical technologies are defined and enforced."},
		{"12.4", "PCI DSS compliance program", "A PCI DSS compliance program is established with defined roles and responsibilities."},
		{"12.5", "Security awareness training", "Security awareness training is provided to all personnel upon hire and at least annually."},
		{"12.6", "Incident response plan", "An incident response plan is maintained and tested to respond to security incidents involving cardholder data."},
		{"12.7", "Personnel screening", "Potential personnel with access to the CDE are screened to minimize risks from insider attacks."},
		{"12.8", "Third-party service provider management", "Third-party service providers with access to cardholder data are managed through formal agreements and monitoring."},
	}

	allReqs := []struct {
		req   string
		title string
		items []struct{ id, title, desc string }
	}{
		{"Requirement 1", "Install and Maintain Network Security Controls", req1},
		{"Requirement 2", "Apply Secure Configuration to System Components", req2},
		{"Requirement 3", "Protect Stored Account Data", req3},
		{"Requirement 4", "Protect Cardholder Data with Strong Cryptography During Transmission", req4},
		{"Requirement 5", "Protect All Systems Against Malicious Software", req5},
		{"Requirement 6", "Develop and Maintain Secure Systems and Software", req6},
		{"Requirement 7", "Restrict Access to Stored Account Data and System Components", req7},
		{"Requirement 8", "Identify Users and Validate Access to System Components", req8},
		{"Requirement 9", "Restrict Physical Access to Cardholder Data", req9},
		{"Requirement 10", "Log and Monitor All Access to System Components and Cardholder Data", req10},
		{"Requirement 11", "Test Security of Systems and Networks Regularly", req11},
		{"Requirement 12", "Support Information Security with Organizational Policies and Programs", req12},
	}

	for _, req := range allReqs {
		for _, c := range req.items {
			controls = append(controls, grc.Control{
				Framework:   FrameworkID,
				ControlID:   c.id,
				Title:       c.title,
				Family:      req.title,
				Description: c.desc,
				Level:       "standard",
				RelatedCWEs: pciCWEs(c.id),
				References:  []grc.Reference{{Source: "PCI DSS v4.0", Section: req.title}},
			})
		}
	}

	return controls
}
