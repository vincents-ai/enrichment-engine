package soc2

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/shift/enrichment-engine/pkg/grc"
	"github.com/shift/enrichment-engine/pkg/storage"
)

const (
	FrameworkID = "SOC2_TSC_2017"
	CatalogURL  = "https://raw.githubusercontent.com/Drakkar-Software/SOC2-controls/main/soc2_tsc_2017.json"
)

// Provider fetches and parses SOC 2 Trust Services Criteria controls.
type Provider struct {
	store  storage.Backend
	logger *slog.Logger
}

// New creates a new SOC 2 provider.
func New(store storage.Backend, logger *slog.Logger) *Provider {
	return &Provider{
		store:  store,
		logger: logger,
	}
}

// Name returns the provider identifier.
func (p *Provider) Name() string {
	return "soc2"
}

// Run fetches the SOC 2 TSC catalog, parses controls, and writes them to storage.
func (p *Provider) Run(ctx context.Context) (int, error) {
	p.logger.Info("fetching SOC 2 Trust Services Criteria catalog", "url", CatalogURL)

	destPath := filepath.Join(os.TempDir(), "soc2_catalog.json")
	if err := p.download(ctx, CatalogURL, destPath); err != nil {
		p.logger.Warn("failed to download catalog, using embedded fallback", "error", err)
		return p.writeEmbeddedControls(ctx)
	}
	defer os.Remove(destPath)

	controls, err := p.parse(destPath)
	if err != nil {
		p.logger.Warn("failed to parse catalog, using embedded fallback", "error", err)
		return p.writeEmbeddedControls(ctx)
	}

	p.logger.Info("parsed SOC 2 controls", "count", len(controls))

	count := 0
	for _, ctrl := range controls {
		id := fmt.Sprintf("%s/%s", FrameworkID, ctrl.ControlID)
		if err := p.store.WriteControl(ctx, id, ctrl); err != nil {
			p.logger.Warn("failed to write control", "id", id, "error", err)
			continue
		}
		count++
	}

	p.logger.Info("wrote SOC 2 controls to storage", "count", count)
	return count, nil
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

// soc2Catalog represents the expected structure from the external catalog.
type soc2Catalog struct {
	Criteria []soc2Criterion `json:"criteria,omitempty"`
	Groups   []soc2Group     `json:"groups,omitempty"`
}

type soc2Group struct {
	ID       string          `json:"id"`
	Title    string          `json:"title"`
	Criteria []soc2Criterion `json:"criteria"`
}

type soc2Criterion struct {
	ID          string `json:"id"`
	ControlID   string `json:"control_id"`
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
	Category    string `json:"category,omitempty"`
}

func (p *Provider) parse(path string) ([]grc.Control, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var catalog soc2Catalog
	if err := json.NewDecoder(f).Decode(&catalog); err != nil {
		return nil, fmt.Errorf("decode SOC 2 catalog: %w", err)
	}

	var controls []grc.Control

	for _, group := range catalog.Groups {
		for _, c := range group.Criteria {
			controls = append(controls, p.toControl(c, group.Title))
		}
	}

	if len(controls) == 0 {
		for _, c := range catalog.Criteria {
			family := c.Category
			if family == "" {
				family = p.inferFamily(c.ControlID)
			}
			controls = append(controls, p.toControl(c, family))
		}
	}

	return controls, nil
}

func (p *Provider) toControl(c soc2Criterion, family string) grc.Control {
	return grc.Control{
		Framework:   FrameworkID,
		ControlID:   c.ControlID,
		Title:       c.Title,
		Family:      family,
		Description: strings.TrimSpace(c.Description),
		Level:       "standard",
	}
}

func (p *Provider) inferFamily(controlID string) string {
	if strings.HasPrefix(controlID, "A") {
		return "Availability"
	}
	if strings.HasPrefix(controlID, "PI") {
		return "Processing Integrity"
	}
	if strings.HasPrefix(controlID, "C") && !strings.HasPrefix(controlID, "CC") {
		return "Confidentiality"
	}
	if strings.HasPrefix(controlID, "P") && !strings.HasPrefix(controlID, "PI") {
		return "Privacy"
	}
	return "Security"
}

func (p *Provider) writeEmbeddedControls(ctx context.Context) (int, error) {
	p.logger.Info("using embedded SOC 2 TSC 2017 controls")

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

	p.logger.Info("wrote embedded SOC 2 controls to storage", "count", count)
	return count, nil
}

func embeddedControls() []grc.Control {
	controls := []grc.Control{}

	// CC1: Control Environment
	cc1 := []struct{ id, title, desc string }{
		{"CC1.1", "COSO Principle 1: Demonstrates Commitment to Integrity and Ethical Values", "The entity demonstrates a commitment to integrity and ethical values in the development of its system of internal control."},
		{"CC1.2", "COSO Principle 2: Exercises Board Oversight Responsibility", "The board of directors demonstrates independence from management and exercises oversight of the development and performance of internal control."},
		{"CC1.3", "COSO Principle 3: Establishes Structure, Authority, and Responsibility", "Management establishes, with board oversight, structures, reporting lines, and appropriate authorities and responsibilities in the pursuit of objectives."},
		{"CC1.4", "COSO Principle 4: Demonstrates Commitment to Competence", "The entity demonstrates a commitment to attract, develop, and retain competent individuals in alignment with objectives."},
		{"CC1.5", "COSO Principle 5: Enforces Accountability", "The entity holds individuals accountable for their internal control responsibilities in the pursuit of objectives."},
	}

	// CC2: Communication and Information
	cc2 := []struct{ id, title, desc string }{
		{"CC2.1", "COSO Principle 11: Uses Relevant Information", "The entity obtains or generates and uses relevant, quality information to support the functioning of internal control."},
		{"CC2.2", "COSO Principle 12: Communicates Internally", "The entity internally communicates the objectives, responsibilities assigned for internal control, and other significant matters."},
		{"CC2.3", "COSO Principle 13: Communicates Externally", "The entity communicates with external parties regarding matters affecting the functioning of internal control."},
	}

	// CC3: Risk Assessment
	cc3 := []struct{ id, title, desc string }{
		{"CC3.1", "COSO Principle 6: Specifies Objectives", "The entity specifies objectives with sufficient clarity to enable the identification and assessment of risks relating to objectives."},
		{"CC3.2", "COSO Principle 7: Identifies Risks", "The entity identifies risks to the achievement of its objectives across the entity and analyzes risks as a basis for determining how the risks should be managed."},
		{"CC3.3", "COSO Principle 8: Assesses Fraud Risk", "The entity considers the potential for fraud in assessing risks to the achievement of objectives."},
		{"CC3.4", "COSO Principle 9: Identifies Impact of Change", "The entity identifies and assesses changes that could significantly impact the system of internal control."},
	}

	// CC4: Monitoring Activities
	cc4 := []struct{ id, title, desc string }{
		{"CC4.1", "COSO Principle 14: Selects and Develops Monitoring Activities", "The entity selects, develops, and performs ongoing and/or separate evaluations to ascertain whether the components of internal control are present and functioning."},
		{"CC4.2", "COSO Principle 15: Evaluates and Communicates Deficiencies", "The entity evaluates and communicates internal control deficiencies in a timely manner to those parties responsible for taking corrective action."},
	}

	// CC5: Control Activities
	cc5 := []struct{ id, title, desc string }{
		{"CC5.1", "COSO Principle 10: Selects and Develops Control Activities", "The entity selects and develops control activities that contribute to the mitigation of risks to the achievement of objectives to acceptable levels."},
		{"CC5.2", "COSO Principle 10 (Technical): Technology Controls", "The entity also selects and develops general control activities over technology to support the achievement of objectives."},
		{"CC5.3", "COSO Principle 10 (Policies): Policies and Procedures", "The entity deploys control activities through policies that establish what is expected and in procedures that put policies into action."},
	}

	// CC6: Logical and Physical Access Controls
	cc6 := []struct{ id, title, desc string }{
		{"CC6.1", "Logical Access: Implements Logical Access Security", "The entity implements logical access security software, infrastructure, and architectures over protected information assets to protect them from security events."},
		{"CC6.2", "Logical Access: User Registration and Authorization", "Prior to issuing system credentials and granting system access, the entity registers and authorizes new internal and external users whose access is administered by the entity."},
		{"CC6.3", "Logical Access: Role-Based Access", "The entity authorizes, modifies, or removes access to data, software, functions, and other protected information assets based on roles, responsibilities, or the system design."},
		{"CC6.4", "Logical Access: Physical Access Credentials", "The entity restricts physical access to facilities and protected information assets to authorized personnel."},
		{"CC6.5", "Logical Access: System Account Management", "The entity discontinues logical and physical access protections when access is no longer authorized or when the access is no longer required."},
		{"CC6.6", "Logical Access: System Boundaries", "The entity implements logical access security measures to protect against threats from sources outside its system boundaries."},
		{"CC6.7", "Logical Access: Transmission and Storage Protection", "The entity restricts the transmission, movement, and removal of information to authorized internal and external users and processes."},
		{"CC6.8", "Logical Access: Malicious Software Prevention", "The entity implements controls to prevent or detect and act upon the introduction of unauthorized or malicious software."},
	}

	// CC7: System Operations
	cc7 := []struct{ id, title, desc string }{
		{"CC7.1", "System Operations: Detection and Monitoring", "To meet its objectives, the entity uses detection and monitoring procedures to identify changes to configurations that result in the introduction of new vulnerabilities."},
		{"CC7.2", "System Operations: Anomaly Detection", "The entity monitors system components and the operation of those components for anomalies that are indicators of malicious acts, natural disasters, and errors."},
		{"CC7.3", "System Operations: Evaluation of Security Events", "The entity evaluates detected security events to determine whether they could or have resulted in a failure of the entity to meet its objectives."},
		{"CC7.4", "System Operations: Incident Response", "The entity responds to identified security incidents by executing a defined incident response program to understand, contain, remediate, and communicate security incidents."},
		{"CC7.5", "System Operations: Incident Recovery", "The entity identifies, develops, and implements activities to recover from identified security incidents."},
	}

	// CC8: Change Management
	cc8 := []struct{ id, title, desc string }{
		{"CC8.1", "Change Management: Authorization", "The entity authorizes, designs, develops or acquires, configures, documents, tests, approves, and implements changes to infrastructure, data, software, and procedures."},
	}

	// CC9: Risk Mitigation
	cc9 := []struct{ id, title, desc string }{
		{"CC9.1", "Risk Mitigation: Transaction Integrity", "The entity identifies, selects, and develops risk mitigation activities for risks arising from potential business disruptions."},
		{"CC9.2", "Risk Mitigation: Vendor Management", "The entity assesses and manages risks associated with vendors and business partners."},
	}

	// A1: Availability
	a1 := []struct{ id, title, desc string }{
		{"A1.1", "Availability: Capacity Planning", "The entity maintains, monitors, and evaluates current processing capacity and use of system components to manage capacity demand or to enable the implementation of additional capacity to help meet its objectives."},
		{"A1.2", "Availability: Environmental Protections", "The entity authorizes, designs, develops or acquires, implements, operates, approves, maintains, and monitors environmental protections, software, data back-up processes, and recovery infrastructure to meet its objectives."},
		{"A1.3", "Availability: Recovery Testing", "The entity tests recovery plan procedures supporting system recovery to meet its objectives."},
	}

	// PI1: Processing Integrity
	pi1 := []struct{ id, title, desc string }{
		{"PI1.1", "Processing Integrity: Data Completeness", "The entity obtains or generates, uses, and communicates relevant, quality information regarding the objectives related to processing, including deprecations to or deviations from expected processing."},
		{"PI1.2", "Processing Integrity: Data Accuracy", "The entity implements policies and procedures over system inputs, including controls over completeness and accuracy, to result in products, services, and reporting to meet the entity's objectives."},
		{"PI1.3", "Processing Integrity: Data Timeliness", "The entity implements policies and procedures over system processing to result in products, services, and reporting to meet the entity's objectives."},
		{"PI1.4", "Processing Integrity: Data Output Integrity", "The entity implements policies and procedures to make available or deliver output completely, accurately, and timely in accordance with specifications to meet the entity's objectives."},
		{"PI1.5", "Processing Integrity: Processing Backlog", "The entity implements policies and procedures to store inputs, items in transit, and outputs completely, accurately, and timely in accordance with system specifications to meet its objectives."},
	}

	// C1: Confidentiality
	c1 := []struct{ id, title, desc string }{
		{"C1.1", "Confidentiality: Identification of Confidential Information", "The entity identifies and maintains confidential information to meet the entity's objectives related to confidentiality."},
		{"C1.2", "Confidentiality: Disposal of Confidential Information", "The entity disposes of confidential information to meet the entity's objectives related to confidentiality."},
	}

	// P1-P9: Privacy
	p1 := []struct{ id, title, desc string }{
		{"P1.1", "Privacy: Notice and Communication of Objectives", "The entity provides notice to data subjects about its privacy practices and communicates its privacy objectives to those responsible for carrying out those objectives."},
		{"P2.1", "Privacy: Choice and Consent", "The entity communicates choices available regarding the collection, use, retention, disclosure, and disposal of personal information to the data subjects."},
		{"P3.1", "Privacy: Collection of Personal Information", "Personal information is collected consistent with the entity's objectives related to privacy."},
		{"P4.1", "Privacy: Use, Retention, and Disposal of Personal Information", "Personal information is used, retained, and disposed of consistent with the entity's objectives related to privacy."},
		{"P5.1", "Privacy: Data Subject Access and Amendment", "The entity grants identified and authenticated data subjects the ability to access their stored personal information for review and, upon request, provides physical or electronic copies of that information to data subjects."},
		{"P6.1", "Privacy: Data Subject Consent for Disclosure", "The entity obtains consent from data subjects for disclosure of personal information to third parties, unless otherwise required by law or regulation."},
		{"P7.1", "Privacy: Accuracy and Quality of Personal Information", "The entity collects and maintains accurate, up-to-date, complete, and relevant personal information to meet the entity's objectives related to privacy."},
		{"P8.1", "Privacy: Personal Information Security", "The entity implements policies and procedures over personal information to protect it from unauthorized access, use, or disclosure."},
		{"P9.1", "Privacy: Privacy-Specific Risk Management", "The entity identifies, assesses, and manages risks to personal information to meet the entity's objectives related to privacy."},
	}

	for _, c := range cc1 {
		controls = append(controls, grc.Control{
			Framework:   FrameworkID,
			ControlID:   c.id,
			Title:       c.title,
			Family:      "Security",
			Description: c.desc,
			Level:       "standard",
		})
	}

	for _, c := range cc2 {
		controls = append(controls, grc.Control{
			Framework:   FrameworkID,
			ControlID:   c.id,
			Title:       c.title,
			Family:      "Security",
			Description: c.desc,
			Level:       "standard",
		})
	}

	for _, c := range cc3 {
		controls = append(controls, grc.Control{
			Framework:   FrameworkID,
			ControlID:   c.id,
			Title:       c.title,
			Family:      "Security",
			Description: c.desc,
			Level:       "standard",
		})
	}

	for _, c := range cc4 {
		controls = append(controls, grc.Control{
			Framework:   FrameworkID,
			ControlID:   c.id,
			Title:       c.title,
			Family:      "Security",
			Description: c.desc,
			Level:       "standard",
		})
	}

	for _, c := range cc5 {
		controls = append(controls, grc.Control{
			Framework:   FrameworkID,
			ControlID:   c.id,
			Title:       c.title,
			Family:      "Security",
			Description: c.desc,
			Level:       "standard",
		})
	}

	for _, c := range cc6 {
		controls = append(controls, grc.Control{
			Framework:   FrameworkID,
			ControlID:   c.id,
			Title:       c.title,
			Family:      "Security",
			Description: c.desc,
			Level:       "standard",
		})
	}

	for _, c := range cc7 {
		controls = append(controls, grc.Control{
			Framework:   FrameworkID,
			ControlID:   c.id,
			Title:       c.title,
			Family:      "Security",
			Description: c.desc,
			Level:       "standard",
		})
	}

	for _, c := range cc8 {
		controls = append(controls, grc.Control{
			Framework:   FrameworkID,
			ControlID:   c.id,
			Title:       c.title,
			Family:      "Security",
			Description: c.desc,
			Level:       "standard",
		})
	}

	for _, c := range cc9 {
		controls = append(controls, grc.Control{
			Framework:   FrameworkID,
			ControlID:   c.id,
			Title:       c.title,
			Family:      "Security",
			Description: c.desc,
			Level:       "standard",
		})
	}

	for _, c := range a1 {
		controls = append(controls, grc.Control{
			Framework:   FrameworkID,
			ControlID:   c.id,
			Title:       c.title,
			Family:      "Availability",
			Description: c.desc,
			Level:       "standard",
		})
	}

	for _, c := range pi1 {
		controls = append(controls, grc.Control{
			Framework:   FrameworkID,
			ControlID:   c.id,
			Title:       c.title,
			Family:      "Processing Integrity",
			Description: c.desc,
			Level:       "standard",
		})
	}

	for _, c := range c1 {
		controls = append(controls, grc.Control{
			Framework:   FrameworkID,
			ControlID:   c.id,
			Title:       c.title,
			Family:      "Confidentiality",
			Description: c.desc,
			Level:       "standard",
		})
	}

	for _, c := range p1 {
		controls = append(controls, grc.Control{
			Framework:   FrameworkID,
			ControlID:   c.id,
			Title:       c.title,
			Family:      "Privacy",
			Description: c.desc,
			Level:       "standard",
		})
	}

	return controls
}
