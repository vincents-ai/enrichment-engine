package nist_csf

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
	FrameworkID = "NIST_CSF_2_0"
)

var CatalogURL = "https://raw.githubusercontent.com/usnistgov/cybersecurity-framework/main/csf_2_0_catalog.json"

// Provider fetches and parses NIST Cybersecurity Framework 2.0 outcomes.
type Provider struct {
	store  storage.Backend
	logger *slog.Logger
}

// New creates a new NIST CSF provider.
func New(store storage.Backend, logger *slog.Logger) *Provider {
	return &Provider{
		store:  store,
		logger: logger,
	}
}

// Name returns the provider identifier.
func (p *Provider) Name() string {
	return "nist_csf"
}

// Run fetches the NIST CSF 2.0 catalog, parses outcomes, and writes them to storage.
func (p *Provider) Run(ctx context.Context) (int, error) {
	p.logger.Info("fetching NIST CSF 2.0 controls catalog", "url", CatalogURL)

	f, err := os.CreateTemp("", "nist_csf_catalog_*.json")
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

	p.logger.Info("parsed NIST CSF outcomes", "count", len(controls))

	count := 0
	for _, ctrl := range controls {
		id := fmt.Sprintf("%s/%s", FrameworkID, ctrl.ControlID)
		if err := p.store.WriteControl(ctx, id, ctrl); err != nil {
			p.logger.Warn("failed to write control", "id", id, "error", err)
			continue
		}
		count++
	}

	p.logger.Info("wrote NIST CSF controls to storage", "count", count)
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

type csfCatalog struct {
	Functions []csfFunction `json:"functions"`
}

type csfFunction struct {
	ID         string        `json:"id"`
	Name       string        `json:"name"`
	Categories []csfCategory `json:"categories"`
}

type csfCategory struct {
	ID            string           `json:"id"`
	Name          string           `json:"name"`
	Subcategories []csfSubcategory `json:"subcategories"`
}

type csfSubcategory struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	Level       string `json:"level,omitempty"`
}

func (p *Provider) parse(path string) ([]grc.Control, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var catalog csfCatalog
	if err := json.NewDecoder(f).Decode(&catalog); err != nil {
		return nil, fmt.Errorf("decode NIST CSF catalog: %w", err)
	}

	var controls []grc.Control

	for _, function := range catalog.Functions {
		for _, category := range function.Categories {
			for _, subcategory := range category.Subcategories {
				controls = append(controls, p.toSubcategory(subcategory, function.Name, category.Name, function.ID))
			}
		}
	}

	return controls, nil
}

func (p *Provider) toSubcategory(sub csfSubcategory, function, category, functionID string) grc.Control {
	level := "standard"
	if sub.Level != "" {
		level = strings.ToLower(sub.Level)
	}

	return grc.Control{
		Framework:   FrameworkID,
		ControlID:   sub.ID,
		Title:       sub.Description,
		Family:      fmt.Sprintf("%s - %s", function, category),
		Description: sub.Description,
		Level:       level,
		RelatedCWEs: nistCsfCWEs(sub.ID),
		References: []grc.Reference{
			{
				Source:  "NIST Cybersecurity Framework 2.0",
				Section: fmt.Sprintf("%s.%s", functionID, sub.ID),
			},
		},
	}
}

func (p *Provider) writeEmbeddedControls(ctx context.Context) (int, error) {
	p.logger.Info("using embedded NIST CSF 2.0 outcomes")

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

	p.logger.Info("wrote embedded NIST CSF controls to storage", "count", count)
	return count, nil
}

var nistCsfCWEMap = map[string][]string{
	"ID.RA-01": {"CWE-1090", "CWE-1104"},
	"ID.RA-02": {"CWE-1021", "CWE-937"},
	"ID.RA-05": {"CWE-1090", "CWE-1104"},
	"ID.RA-07": {"CWE-1104"},
	"PR.AA-01": {"CWE-287", "CWE-798", "CWE-638"},
	"PR.AA-02": {"CWE-265", "CWE-285", "CWE-287"},
	"PR.AA-03": {"CWE-287", "CWE-308", "CWE-522"},
	"PR.AA-04": {"CWE-287", "CWE-343"},
	"PR.AA-05": {"CWE-284", "CWE-285", "CWE-862", "CWE-863"},
	"PR.DS-01": {"CWE-200", "CWE-1069"},
	"PR.DS-02": {"CWE-311", "CWE-312", "CWE-313", "CWE-316"},
	"PR.DS-03": {"CWE-319", "CWE-326"},
	"PR.DS-04": {"CWE-311", "CWE-312", "CWE-326"},
	"PR.DS-05": {"CWE-226", "CWE-227", "CWE-228"},
	"PR.DS-06": {"CWE-200", "CWE-212", "CWE-497"},
	"PR.DS-07": {"CWE-494", "CWE-754"},
	"PR.DS-08": {"CWE-345", "CWE-353", "CWE-348"},
	"PR.IR-01": {"CWE-16", "CWE-2", "CWE-1188"},
	"PR.IR-02": {"CWE-16", "CWE-494"},
	"PR.IR-03": {"CWE-16", "CWE-1188"},
	"PR.IR-04": {"CWE-1104"},
	"PR.IR-05": {"CWE-94", "CWE-78", "CWE-95", "CWE-96", "CWE-119", "CWE-1336", "CWE-502"},
	"PR.IR-06": {"CWE-693", "CWE-1004", "CWE-1059"},
	"DE.CM-01": {"CWE-778"},
	"DE.CM-02": {"CWE-778"},
	"DE.CM-05": {"CWE-778", "CWE-1104"},
	"DE.CM-07": {"CWE-778"},
	"DE.CM-08": {"CWE-778", "CWE-693"},
	"DE.AE-01": {"CWE-778", "CWE-693"},
	"DE.AE-02": {"CWE-778", "CWE-208"},
	"DE.AE-03": {"CWE-778", "CWE-693"},
	"RS.MA-01": {"CWE-16", "CWE-778"},
	"RS.MA-03": {"CWE-778"},
	"RS.AN-01": {"CWE-778", "CWE-208"},
	"RS.AN-03": {"CWE-778"},
	"RS.AN-04": {"CWE-693", "CWE-400"},
	"RS.MI-01": {"CWE-693", "CWE-400"},
	"RC.RP-01": {"CWE-1007", "CWE-754"},
	"RC.RP-02": {"CWE-1007", "CWE-754"},
	"RC.RP-03": {"CWE-1007"},
}

func nistCsfCWEs(controlID string) []string {
	return nistCsfCWEMap[controlID]
}

func embeddedControls() []grc.Control {
	controls := []grc.Control{}

	govern := []struct{ id, title, desc string }{
		{"GV.OC-01", "Organizational context", "Organizational mission, objectives, and capabilities are understood and inform cybersecurity risk management decisions."},
		{"GV.OC-02", "Internal and external stakeholders", "Internal and external stakeholders are identified, and their needs and expectations regarding cybersecurity are understood."},
		{"GV.OC-03", "Legal and regulatory requirements", "Legal and regulatory requirements regarding cybersecurity are understood and managed."},
		{"GV.OC-04", "Critical objectives and capabilities", "Critical objectives, capabilities, and services and their cybersecurity dependencies are identified and documented."},
		{"GV.RM-01", "Risk management strategy", "A risk management strategy is established, communicated, and maintained."},
		{"GV.RM-02", "Risk appetite and tolerance", "Risk appetite and risk tolerance statements are established, communicated, and maintained."},
		{"GV.RM-03", "Strategic direction", "Cybersecurity strategic direction is established and communicated."},
		{"GV.RM-04", "Improvement", "Cybersecurity improvements are identified and implemented."},
		{"GV.RM-05", "Cybersecurity supply chain risk management", "Cybersecurity supply chain risk management activities are established and implemented."},
		{"GV.RM-06", "Roles and responsibilities", "Organizational leadership is responsible and accountable for cybersecurity risk and communicates this responsibility."},
		{"GV.RM-07", "Cybersecurity roles", "Cybersecurity roles and responsibilities are coordinated and aligned with internal and external stakeholders."},
		{"GV.PO-01", "Policy", "Organizational cybersecurity policy is established, communicated, and maintained."},
		{"GV.PO-02", "Policy review", "Cybersecurity policy is reviewed and updated at defined intervals or when significant changes occur."},
		{"GV.PO-03", "Policy compliance", "Compliance with cybersecurity policy is monitored and enforced."},
		{"GV.PO-04", "Oversight", "Cybersecurity risk management strategy outcomes are reviewed to inform and adjust the strategy."},
		{"GV.SC-01", "Cybersecurity governance", "Cybersecurity governance is established and maintained to enable organizational leadership to understand and manage cybersecurity risk."},
		{"GV.SC-02", "Cybersecurity culture", "A cybersecurity-aware culture is promoted across the organization."},
		{"GV.SC-03", "Cybersecurity expectations", "Cybersecurity expectations are communicated to and enforced with third parties."},
	}

	identify := []struct{ id, title, desc string }{
		{"ID.AM-01", "Inventories of hardware", "Inventories of hardware managed by the organization are maintained."},
		{"ID.AM-02", "Inventories of software", "Inventories of software, services, and systems managed by the organization are maintained."},
		{"ID.AM-03", "Representations of organizational communication", "Representations of organizational communication and data flows are maintained."},
		{"ID.AM-04", "Inventories of services", "Inventories of services provided by suppliers are maintained."},
		{"ID.AM-05", "Assets and data criticality", "Assets and data are classified by criticality to organizational objectives and risk management."},
		{"ID.AM-06", "Cybersecurity roles", "Cybersecurity roles and responsibilities for the entire workforce and third parties are established and communicated."},
		{"ID.AM-07", "Physical environment and data", "Physical environment and data are inventoried and managed."},
		{"ID.RA-01", "Vulnerabilities", "Vulnerabilities in assets are identified, validated, and recorded."},
		{"ID.RA-02", "Cyber threat intelligence", "Cyber threat intelligence is received from information sharing forums and sources."},
		{"ID.RA-03", "Internal and external threats", "Internal and external threats to the organization are identified and recorded."},
		{"ID.RA-04", "Potential impacts", "Potential impacts and likelihoods of threats exploiting vulnerabilities are identified and recorded."},
		{"ID.RA-05", "Threats and vulnerabilities", "Threats and vulnerabilities are identified and recorded."},
		{"ID.RA-06", "Risk response", "Risk responses are chosen, prioritized, planned, tracked, and communicated."},
		{"ID.RA-07", "Changes and potential impacts", "Changes and potential impacts on cybersecurity risk are identified and recorded."},
		{"ID.RA-08", "Supply chain risk", "Supply chain risks are identified and recorded."},
		{"ID.RA-09", "Critical suppliers", "Critical suppliers are identified and assessed."},
		{"ID.RA-10", "Supplier risk management", "Supplier risk management practices are established and implemented."},
		{"ID.IM-01", "Improvement", "Improvements are identified from evaluations."},
		{"ID.IM-02", "Assessments", "Assessments are performed to evaluate the effectiveness of cybersecurity activities."},
	}

	protect := []struct{ id, title, desc string }{
		{"PR.AA-01", "Identities and credentials", "Identities and credentials are issued, managed, verified, and revoked for authorized users and devices."},
		{"PR.AA-02", "Identity management", "Identity management is implemented for all users and devices."},
		{"PR.AA-03", "User and device authentication", "Users and devices are authenticated."},
		{"PR.AA-04", "Identity assertions", "Identity assertions are provided and validated."},
		{"PR.AA-05", "Access permissions", "Access permissions are managed and enforced."},
		{"PR.AT-01", "Training", "Personnel are trained to perform their cybersecurity duties."},
		{"PR.AT-02", "Awareness", "Personnel are provided with cybersecurity awareness training."},
		{"PR.DS-01", "Data inventory", "Data inventories are maintained."},
		{"PR.DS-02", "Data protection", "Data is protected in accordance with its classification and risk."},
		{"PR.DS-03", "Data in transit", "Data in transit is protected."},
		{"PR.DS-04", "Data at rest", "Data at rest is protected."},
		{"PR.DS-05", "Data sanitization", "Data is sanitized and disposed of securely."},
		{"PR.DS-06", "Data leakage prevention", "Data leakage prevention mechanisms are implemented."},
		{"PR.DS-07", "Backup and recovery", "Backups of data are maintained and tested."},
		{"PR.DS-08", "Data integrity", "Data integrity is verified and protected."},
		{"PR.PS-01", "Physical access", "Physical access to assets is managed and monitored."},
		{"PR.PS-02", "Physical environment", "Physical environment is secured against unauthorized access."},
		{"PR.PS-03", "Personnel screening", "Personnel are screened prior to granting access."},
		{"PR.IR-01", "Secure configuration", "Secure configurations are established and maintained."},
		{"PR.IR-02", "Change management", "Changes to systems and assets are managed."},
		{"PR.IR-03", "Configuration management", "Configuration management processes are implemented."},
		{"PR.IR-04", "Patch management", "Patches and updates are applied in a timely manner."},
		{"PR.IR-05", "Secure development", "Secure development practices are implemented."},
		{"PR.IR-06", "Secure architecture", "Secure architecture principles are applied."},
		{"PR.MA-01", "Maintenance", "Maintenance and repairs are performed and recorded."},
		{"PR.MA-02", "Remote maintenance", "Remote maintenance is approved, logged, and performed securely."},
	}

	detect := []struct{ id, title, desc string }{
		{"DE.CM-01", "Network monitoring", "Network activity is monitored to detect potential cybersecurity events."},
		{"DE.CM-02", "Physical activity monitoring", "Physical activity is monitored to detect potential cybersecurity events."},
		{"DE.CM-03", "Personnel activity monitoring", "Personnel activity is monitored to detect potential cybersecurity events."},
		{"DE.CM-04", "External service monitoring", "External service provider activity is monitored to detect potential cybersecurity events."},
		{"DE.CM-05", "Vulnerability monitoring", "Vulnerabilities are monitored and tracked."},
		{"DE.CM-06", "External information monitoring", "External information on cybersecurity threats is monitored."},
		{"DE.CM-07", "Adverse events", "Adverse events and anomalies are detected and logged."},
		{"DE.CM-08", "Runtime behavior", "Runtime behavior of applications and services is monitored for anomalous activity."},
		{"DE.AE-01", "Event detection", "Cybersecurity events are detected and analyzed."},
		{"DE.AE-02", "Event impact assessment", "The impact of cybersecurity events is assessed."},
		{"DE.AE-03", "Event correlation", "Cybersecurity events are correlated and analyzed."},
		{"DE.AE-04", "Event triage", "Cybersecurity events are triaged and prioritized."},
		{"DE.AE-05", "Event escalation", "Cybersecurity events are escalated according to defined criteria."},
		{"DE.AE-06", "Incident declaration", "Incidents are declared based on event analysis."},
	}

	respond := []struct{ id, title, desc string }{
		{"RS.MA-01", "Incident management plan", "An incident management plan is established and maintained."},
		{"RS.MA-02", "Incident reporting", "Incidents are reported and tracked."},
		{"RS.MA-03", "Incident response", "Incident response activities are executed according to plan."},
		{"RS.MA-04", "Incident response coordination", "Incident response is coordinated with internal and external stakeholders."},
		{"RS.MA-05", "Incident response improvements", "Incident response activities are improved based on lessons learned."},
		{"RS.AN-01", "Incident analysis", "Incidents are analyzed to determine scope, root cause, and impact."},
		{"RS.AN-02", "Incident categorization", "Incidents are categorized and prioritized."},
		{"RS.AN-03", "Forensic analysis", "Forensic analysis is performed when required."},
		{"RS.AN-04", "Incident containment", "Incidents are contained to limit impact."},
		{"RS.MI-01", "Mitigation", "Incident impacts are mitigated."},
		{"RS.MI-02", "Recovery prioritization", "Recovery activities are prioritized based on criticality."},
		{"RS.MI-03", "Recovery execution", "Recovery activities are executed according to plan."},
		{"RS.CO-01", "Internal communication", "Internal communication during incident response is coordinated."},
		{"RS.CO-02", "External communication", "External communication during incident response is coordinated."},
		{"RS.CO-03", "Legal and regulatory", "Legal and regulatory reporting requirements are met during incident response."},
	}

	recover := []struct{ id, title, desc string }{
		{"RC.RP-01", "Recovery plan", "A recovery plan is established and maintained."},
		{"RC.RP-02", "Recovery plan execution", "Recovery plans are executed to restore impacted systems and services."},
		{"RC.RP-03", "Recovery plan testing", "Recovery plans are tested to ensure effectiveness."},
		{"RC.RP-04", "Recovery prioritization", "Recovery activities are prioritized based on criticality and impact."},
		{"RC.RP-05", "Recovery communication", "Recovery activities are communicated to stakeholders."},
		{"RC.CO-01", "Public communication", "Public communication during recovery is coordinated."},
		{"RC.CO-02", "Stakeholder communication", "Stakeholder communication during recovery is coordinated."},
		{"RC.CO-03", "Reputation management", "Reputation management activities are implemented during recovery."},
		{"RC.IM-01", "Improvement", "Recovery activities are improved based on lessons learned."},
		{"RC.IM-02", "Post-incident review", "Post-incident reviews are conducted to identify improvements."},
		{"RC.IM-03", "Recovery metrics", "Recovery metrics are collected and analyzed."},
		{"RC.IM-04", "Recovery plan updates", "Recovery plans are updated based on lessons learned and changing conditions."},
	}

	allFunctions := []struct {
		function string
		items    []struct{ id, title, desc string }
	}{
		{"Govern", govern},
		{"Identify", identify},
		{"Protect", protect},
		{"Detect", detect},
		{"Respond", respond},
		{"Recover", recover},
	}

	for _, f := range allFunctions {
		for _, c := range f.items {
			controls = append(controls, grc.Control{
				Framework:   FrameworkID,
				ControlID:   c.id,
				Title:       c.title,
				Family:      f.function,
				Description: c.desc,
				Level:       "standard",
				RelatedCWEs: nistCsfCWEs(c.id),
				References:  []grc.Reference{{Source: "NIST Cybersecurity Framework 2.0", Section: c.id}},
			})
		}
	}

	return controls
}
