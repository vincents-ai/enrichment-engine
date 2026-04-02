package cmmc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/shift/enrichment-engine/pkg/grc"
	"github.com/shift/enrichment-engine/pkg/storage"
)

const (
	FrameworkID = "CMMC_v2"
	CatalogURL  = "https://raw.githubusercontent.com/cmmc-assessment/controls/main/cmmc_v2_controls.json"
)

// Provider fetches and parses CMMC v2 (Cybersecurity Maturity Model Certification) controls.
type Provider struct {
	store  storage.Backend
	logger *slog.Logger
}

// New creates a new CMMC provider.
func New(store storage.Backend, logger *slog.Logger) *Provider {
	return &Provider{
		store:  store,
		logger: logger,
	}
}

// Name returns the provider identifier.
func (p *Provider) Name() string {
	return "cmmc"
}

// Run fetches the CMMC v2 controls catalog, parses controls, and writes them to storage.
func (p *Provider) Run(ctx context.Context) (int, error) {
	p.logger.Info("fetching CMMC v2 controls catalog", "url", CatalogURL)

	f, err := os.CreateTemp("", "cmmc_catalog_*.json")
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

	p.logger.Info("parsed CMMC controls", "count", len(controls))

	count := 0
	for _, ctrl := range controls {
		id := fmt.Sprintf("%s/%s", FrameworkID, ctrl.ControlID)
		if err := p.store.WriteControl(ctx, id, ctrl); err != nil {
			p.logger.Warn("failed to write control", "id", id, "error", err)
			continue
		}
		count++
	}

	p.logger.Info("wrote CMMC controls to storage", "count", count)
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

type cmmcCatalog struct {
	Controls []cmmcControl `json:"controls"`
	Groups   []cmmcGroup   `json:"groups,omitempty"`
}

type cmmcGroup struct {
	ID       string        `json:"id"`
	Domain   string        `json:"domain"`
	Level    string        `json:"level"`
	Controls []cmmcControl `json:"controls"`
}

type cmmcControl struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
	Domain      string `json:"domain,omitempty"`
	Level       string `json:"level,omitempty"`
	NISTRef     string `json:"nist_ref,omitempty"`
}

func (p *Provider) parse(path string) ([]grc.Control, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var catalog cmmcCatalog
	if err := json.NewDecoder(f).Decode(&catalog); err != nil {
		return nil, fmt.Errorf("decode CMMC catalog: %w", err)
	}

	var controls []grc.Control

	for _, group := range catalog.Groups {
		for _, ctrl := range group.Controls {
			controls = append(controls, p.toControl(ctrl, group.Domain, group.Level))
		}
	}

	if len(controls) == 0 {
		for _, ctrl := range catalog.Controls {
			controls = append(controls, p.toControl(ctrl, ctrl.Domain, ctrl.Level))
		}
	}

	return controls, nil
}

func (p *Provider) toControl(ctrl cmmcControl, domain, level string) grc.Control {
	cmmcLevel := level
	if ctrl.Level != "" {
		cmmcLevel = ctrl.Level
	}

	refs := []grc.Reference{
		{Source: "CMMC v2", Section: fmt.Sprintf("Level %s - %s", cmmcLevel, domain)},
	}
	if ctrl.NISTRef != "" {
		refs = append(refs, grc.Reference{Source: "NIST SP 800-171", Section: ctrl.NISTRef})
	}

	return grc.Control{
		Framework:   FrameworkID,
		ControlID:   ctrl.ID,
		Title:       ctrl.Title,
		Family:      domain,
		Description: ctrl.Description,
		Level:       strings.ToLower(cmmcLevel),
		RelatedCWEs: cmmcCWEs(ctrl.ID),
		References:  refs,
	}
}

func (p *Provider) writeEmbeddedControls(ctx context.Context) (int, error) {
	p.logger.Info("using embedded CMMC v2 controls")

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

	p.logger.Info("wrote embedded CMMC controls to storage", "count", count)
	return count, nil
}

var cmmcCWEMap = map[string][]string{
	"AC.L1-3.1.1":  {"CWE-284", "CWE-285", "CWE-862"},
	"AC.L1-3.1.2":  {"CWE-284", "CWE-285"},
	"AC.L2-3.1.3":  {"CWE-284", "CWE-668"},
	"AC.L2-3.1.4":  {"CWE-250", "CWE-269"},
	"AC.L2-3.1.5":  {"CWE-250", "CWE-269", "CWE-862"},
	"AC.L2-3.1.6":  {"CWE-250", "CWE-269"},
	"AC.L2-3.1.7":  {"CWE-287", "CWE-668"},
	"AC.L2-3.1.8":  {"CWE-284", "CWE-319"},
	"AC.L2-3.1.9":  {"CWE-668", "CWE-284"},
	"AC.L2-3.1.10": {"CWE-613"},
	"AT.L2-3.2.1":  {"CWE-919", "CWE-937"},
	"AT.L2-3.2.2":  {"CWE-919"},
	"AT.L2-3.2.3":  {"CWE-919", "CWE-1021"},
	"AU.L2-3.3.1":  {"CWE-778"},
	"AU.L2-3.3.2":  {"CWE-778", "CWE-693"},
	"AU.L2-3.3.3":  {"CWE-778", "CWE-311"},
	"AU.L2-3.3.4":  {"CWE-778", "CWE-693"},
	"AU.L2-3.3.6":  {"CWE-778", "CWE-250"},
	"CM.L2-3.4.1":  {"CWE-16", "CWE-1188"},
	"CM.L2-3.4.2":  {"CWE-16", "CWE-1188"},
	"CM.L2-3.4.3":  {"CWE-16", "CWE-494"},
	"CM.L2-3.4.5":  {"CWE-16", "CWE-1188"},
	"CM.L2-3.4.6":  {"CWE-1104"},
	"IA.L1-3.5.1":  {"CWE-287", "CWE-798"},
	"IA.L1-3.5.2":  {"CWE-287", "CWE-308"},
	"IA.L2-3.5.3":  {"CWE-287", "CWE-308"},
	"IA.L2-3.5.4":  {"CWE-287", "CWE-308"},
	"IA.L2-3.5.5":  {"CWE-287"},
	"IA.L2-3.5.6":  {"CWE-521", "CWE-265"},
	"IA.L2-3.5.7":  {"CWE-287", "CWE-319"},
	"IR.L2-3.6.1":  {"CWE-778", "CWE-693"},
	"IR.L2-3.6.2":  {"CWE-778"},
	"IR.L2-3.6.3":  {"CWE-1104"},
	"MA.L2-3.7.2":  {"CWE-250", "CWE-269"},
	"MA.L2-3.7.3":  {"CWE-668", "CWE-284"},
	"MP.L2-3.8.1":  {"CWE-311", "CWE-226"},
	"MP.L2-3.8.3":  {"CWE-226", "CWE-228"},
	"PE.L1-3.10.1": {"CWE-668", "CWE-284"},
	"PE.L2-3.10.2": {"CWE-778"},
	"RM.L2-3.11.1": {"CWE-1104", "CWE-937"},
	"RM.L2-3.11.3": {"CWE-1104"},
	"CA.L2-3.12.1": {"CWE-1104", "CWE-937"},
	"SC.L2-3.13.1": {"CWE-284", "CWE-668"},
	"SC.L2-3.13.2": {"CWE-319", "CWE-326"},
	"SC.L2-3.13.3": {"CWE-320", "CWE-326"},
	"SC.L2-3.13.4": {"CWE-400", "CWE-693"},
	"SC.L2-3.13.5": {"CWE-287", "CWE-345"},
	"SC.L2-3.13.8": {"CWE-668"},
	"SI.L1-3.14.1": {"CWE-94", "CWE-506"},
	"SI.L2-3.14.2": {"CWE-1104"},
	"SI.L2-3.14.3": {"CWE-1104", "CWE-937"},
	"SI.L2-3.14.6": {"CWE-250", "CWE-269", "CWE-787"},
}

func cmmcCWEs(controlID string) []string {
	return cmmcCWEMap[controlID]
}

func embeddedControls() []grc.Control {
	controls := []grc.Control{}

	accessControl := []struct{ id, title, desc, nistRef string }{
		{"AC.L1-3.1.1", "Limit system access to authorized users", "Limit information system access to authorized users, processes acting on behalf of authorized users, or devices (including other information systems).", "3.1.1"},
		{"AC.L1-3.1.2", "Limit system access to authorized types of transactions", "Limit information system access to the types of transactions and functions that authorized users are permitted to execute.", "3.1.2"},
		{"AC.L2-3.1.3", "Control information flow", "Control the flow of CUI in accordance with approved authorizations.", "3.1.3"},
		{"AC.L2-3.1.4", "Separate duties", "Separate duties of individuals to prevent malevolent activity without collusion.", "3.1.4"},
		{"AC.L2-3.1.5", "Least privilege principle", "Employ the principle of least privilege, allowing only authorized accesses for users which are necessary to accomplish assigned tasks.", "3.1.5"},
		{"AC.L2-3.1.6", "Privileged access restriction", "Restrict access to privileged functions and security-relevant information to explicitly authorized personnel.", "3.1.6"},
		{"AC.L2-3.1.7", "Remote access control", "Control and monitor remote access to the system.", "3.1.7"},
		{"AC.L2-3.1.8", "Wireless access control", "Control wireless access to the system using authentication and encryption.", "3.1.8"},
		{"AC.L2-3.1.9", "Mobile device access control", "Control and monitor the use of mobile devices and portable storage media.", "3.1.9"},
		{"AC.L2-3.1.10", "Session lock", "Prevent further access to the system by initiating a session lock after inactivity.", "3.1.10"},
	}

	awarenessTraining := []struct{ id, title, desc, nistRef string }{
		{"AT.L2-3.2.1", "Security awareness training", "Ensure that managers, system administrators, and users of organizational information systems are made aware of the security risks.", "3.2.1"},
		{"AT.L2-3.2.2", "Insider threat awareness", "Provide security awareness training on recognizing and reporting potential indicators of insider threat.", "3.2.2"},
		{"AT.L2-3.2.3", "Social engineering defense", "Train personnel to recognize and respond to social engineering attacks including phishing.", "3.2.3"},
	}

	auditAccountability := []struct{ id, title, desc, nistRef string }{
		{"AU.L2-3.3.1", "Audit event creation", "Create and retain system audit logs and records to the extent needed to enable the monitoring, analysis, investigation, and reporting of unlawful or unauthorized system activity.", "3.3.1"},
		{"AU.L2-3.3.2", "Audit log review", "Review and update logged events on an ongoing basis to ensure audit logs capture relevant events.", "3.3.2"},
		{"AU.L2-3.3.3", "Audit log protection", "Protect audit information and audit logging tools from unauthorized access, modification, and deletion.", "3.3.3"},
		{"AU.L2-3.3.4", "Audit log correlation", "Correlate audit record review, analysis, and reporting processes for investigation and response to indications of unlawful or unauthorized activity.", "3.3.4"},
		{"AU.L2-3.3.5", "Audit log retention", "Retain audit logs for a minimum of 1 year to support incident investigation and compliance requirements.", "3.3.5"},
		{"AU.L2-3.3.6", "Privileged user auditing", "Audit the execution of privileged functions and monitor for unauthorized use.", "3.3.6"},
	}

	configManagement := []struct{ id, title, desc, nistRef string }{
		{"CM.L2-3.4.1", "Baseline configuration", "Establish and document baseline configurations for information systems.", "3.4.1"},
		{"CM.L2-3.4.2", "Configuration change control", "Employ the principle of least functionality by configuring information systems to provide only essential capabilities.", "3.4.2"},
		{"CM.L2-3.4.3", "Impact analysis for changes", "Determine the potential impacts of proposed changes to the information system before implementation.", "3.4.3"},
		{"CM.L2-3.4.4", "Access restrictions for change", "Define, document, approve, and enforce physical and logical access restrictions associated with changes to the system.", "3.4.4"},
		{"CM.L2-3.4.5", "Least functionality", "Configure information systems to provide only essential capabilities and prohibit or restrict the use of unnecessary functions.", "3.4.5"},
		{"CM.L2-3.4.6", "Authorized software policy", "Implement and enforce policies regarding the installation and use of software on organizational systems.", "3.4.6"},
	}

	identificationAuthentication := []struct{ id, title, desc, nistRef string }{
		{"IA.L1-3.5.1", "User identification", "Identify information system users, processes acting on behalf of users, or devices.", "3.5.1"},
		{"IA.L1-3.5.2", "Authentication", "Authenticate (or verify) the identities of those users, processes, or devices as a prerequisite to allowing access to organizational systems.", "3.5.2"},
		{"IA.L2-3.5.3", "Multi-factor authentication", "Implement multi-factor authentication for local and network access to privileged accounts and for network access to non-privileged accounts.", "3.5.3"},
		{"IA.L2-3.5.4", "Multi-factor authentication for remote access", "Implement multi-factor authentication for remote access to privileged and non-privileged accounts.", "3.5.4"},
		{"IA.L2-3.5.5", "Device identification and authentication", "Identify and authenticate devices before establishing network connections.", "3.5.5"},
		{"IA.L2-3.5.6", "Password policy enforcement", "Enforce password complexity, rotation, and history requirements through technical controls.", "3.5.6"},
		{"IA.L2-3.5.7", "Cryptographic authentication", "Use cryptographic mechanisms for authentication to non-local access.", "3.5.7"},
	}

	incidentResponse := []struct{ id, title, desc, nistRef string }{
		{"IR.L2-3.6.1", "Incident response plan", "Establish an operational incident-handling capability for organizational systems that includes preparation, detection, analysis, containment, recovery, and user response activities.", "3.6.1"},
		{"IR.L2-3.6.2", "Incident tracking and reporting", "Track and document information system security incidents.", "3.6.2"},
		{"IR.L2-3.6.3", "Incident response testing", "Test the organizational incident response capability to ensure effectiveness.", "3.6.3"},
		{"IR.L2-3.6.4", "Incident response coordination", "Coordinate incident handling activities with external parties including law enforcement and CISA.", "3.6.4"},
	}

	maintenance := []struct{ id, title, desc, nistRef string }{
		{"MA.L2-3.7.1", "System maintenance", "Perform periodic and timely maintenance on organizational information systems.", "3.7.1"},
		{"MA.L2-3.7.2", "Maintenance tools control", "Control and monitor the use of maintenance tools and techniques.", "3.7.2"},
		{"MA.L2-3.7.3", "Remote maintenance", "Approve, control, and monitor remote maintenance activities.", "3.7.3"},
		{"MA.L2-3.7.4", "Maintenance record keeping", "Record and retain information system maintenance records.", "3.7.4"},
	}

	mediaProtection := []struct{ id, title, desc, nistRef string }{
		{"MP.L2-3.8.1", "Media protection policy", "Protect (i.e., control, secure, and sanitize) information system media, both paper and digital.", "3.8.1"},
		{"MP.L2-3.8.2", "Media access control", "Limit access to information system media to authorized users.", "3.8.2"},
		{"MP.L2-3.8.3", "Media sanitization", "Sanitize or destroy information system media containing CUI before disposal or release for reuse.", "3.8.3"},
		{"MP.L2-3.8.4", "Media marking", "Mark media with necessary CUI markings and distribution limitations.", "3.8.4"},
	}

	physicalProtection := []struct{ id, title, desc, nistRef string }{
		{"PE.L1-3.10.1", "Physical access authorization", "Limit physical access to organizational information systems, equipment, and the respective operating environments to authorized individuals.", "3.10.1"},
		{"PE.L2-3.10.2", "Physical access logging", "Maintain audit logs of physical access to the facilities where CUI is processed and stored.", "3.10.2"},
		{"PE.L2-3.10.3", "Visitor access control", "Escort visitors and monitor visitor activity in areas where CUI is processed and stored.", "3.10.3"},
		{"PE.L2-3.10.4", "Emergency access controls", "Enforce physical access controls during emergency situations.", "3.10.4"},
		{"PE.L2-3.10.5", "Environmental controls", "Implement environmental controls to protect information systems from environmental hazards.", "3.10.5"},
	}

	riskManagement := []struct{ id, title, desc, nistRef string }{
		{"RM.L2-3.11.1", "Risk assessment", "Periodically assess the risk to organizational operations, organizational assets, and individuals resulting from the operation of organizational systems.", "3.11.1"},
		{"RM.L2-3.11.2", "Risk mitigation", "Implement risk mitigation strategies based on risk assessment findings.", "3.11.2"},
		{"RM.L2-3.11.3", "Supply chain risk management", "Manage supply chain risks associated with the acquisition of products and services.", "3.11.3"},
		{"RM.L2-3.11.4", "Plan of action and milestones", "Develop and maintain a plan of action and milestones for the information system.", "3.11.4"},
	}

	securityAssessment := []struct{ id, title, desc, nistRef string }{
		{"CA.L2-3.12.1", "Security assessment", "Periodically assess the security controls in organizational systems to determine if the controls are effective.", "3.12.1"},
		{"CA.L2-3.12.2", "System security plan", "Develop, document, and periodically update the system security plan.", "3.12.2"},
		{"CA.L2-3.12.3", "Plan of action and milestones", "Develop and update a plan of action and milestones based on security assessment results.", "3.12.3"},
		{"CA.L2-3.12.4", "Security authorization", "Authorize the information system for operation prior to processing CUI.", "3.12.4"},
	}

	systemCommunicationsProtection := []struct{ id, title, desc, nistRef string }{
		{"SC.L2-3.13.1", "Boundary protection", "Monitor, control, and protect organizational communications at external boundaries and key internal boundaries.", "3.13.1"},
		{"SC.L2-3.13.2", "Transmission confidentiality and integrity", "Implement cryptographic mechanisms to prevent unauthorized disclosure and modification of CUI during transmission.", "3.13.2"},
		{"SC.L2-3.13.3", "Cryptographic key establishment", "Establish and manage cryptographic keys when cryptography is employed within the system.", "3.13.3"},
		{"SC.L2-3.13.4", "Denial of service protection", "Protect against or limit the effects of denial-of-service attacks.", "3.13.4"},
		{"SC.L2-3.13.5", "Session authenticity", "Protect the authenticity of communications sessions.", "3.13.5"},
		{"SC.L2-3.13.6", "Public key infrastructure", "Implement a PKI for digital signatures and encryption of CUI.", "3.13.6"},
		{"SC.L2-3.13.7", "Secure name/address resolution", "Ensure systems maintain high availability and correct responses for name/address resolution services.", "3.13.7"},
		{"SC.L2-3.13.8", "Network architecture protection", "Implement network segmentation and isolation to protect CUI processing and storage.", "3.13.8"},
	}

	systemInformationIntegrity := []struct{ id, title, desc, nistRef string }{
		{"SI.L1-3.14.1", "Malicious code protection", "Periodically update malicious code protection mechanisms and configure automatic updates.", "3.14.1"},
		{"SI.L2-3.14.2", "System flaw remediation", "Identify, report, and correct information system flaws in a timely manner.", "3.14.2"},
		{"SI.L2-3.14.3", "Vulnerability scanning", "Monitor and scan for vulnerabilities in the information system and hosted applications.", "3.14.3"},
		{"SI.L2-3.14.4", "Security alerts and advisories", "Receive, analyze, and respond to security alerts and advisories from external sources.", "3.14.4"},
		{"SI.L2-3.14.5", "Security function verification", "Verify the correct operation of security functions upon system startup and restart.", "3.14.5"},
		{"SI.L2-3.14.6", "Memory protection", "Implement security mechanisms to protect system memory from unauthorized code execution.", "3.14.6"},
	}

	allDomains := []struct {
		domain string
		level  string
		items  []struct{ id, title, desc, nistRef string }
	}{
		{"Access Control", "2", accessControl},
		{"Awareness and Training", "2", awarenessTraining},
		{"Audit and Accountability", "2", auditAccountability},
		{"Configuration Management", "2", configManagement},
		{"Identification and Authentication", "2", identificationAuthentication},
		{"Incident Response", "2", incidentResponse},
		{"Maintenance", "2", maintenance},
		{"Media Protection", "2", mediaProtection},
		{"Physical Protection", "2", physicalProtection},
		{"Risk Management", "2", riskManagement},
		{"Security Assessment", "2", securityAssessment},
		{"System and Communications Protection", "2", systemCommunicationsProtection},
		{"System and Information Integrity", "2", systemInformationIntegrity},
	}

	for _, d := range allDomains {
		for _, c := range d.items {
			refs := []grc.Reference{
				{Source: "CMMC v2", Section: fmt.Sprintf("Level %s - %s", d.level, d.domain)},
			}
			if c.nistRef != "" {
				refs = append(refs, grc.Reference{Source: "NIST SP 800-171", Section: c.nistRef})
			}

			controls = append(controls, grc.Control{
				Framework:   FrameworkID,
				ControlID:   c.id,
				Title:       c.title,
				Family:      d.domain,
				Description: c.desc,
				Level:       fmt.Sprintf("level_%s", strings.ToLower(d.level)),
				RelatedCWEs: cmmcCWEs(c.id),
				References:  refs,
			})
		}
	}

	return controls
}
