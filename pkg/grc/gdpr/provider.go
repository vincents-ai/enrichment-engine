package gdpr

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
	FrameworkID = "GDPR_2016_679"
	CatalogURL  = "https://raw.githubusercontent.com/gdpr-controls/registry/main/gdpr_controls.json"
)

// Provider fetches and parses GDPR (General Data Protection Regulation) controls.
type Provider struct {
	store  storage.Backend
	logger *slog.Logger
}

// New creates a new GDPR provider.
func New(store storage.Backend, logger *slog.Logger) *Provider {
	return &Provider{
		store:  store,
		logger: logger,
	}
}

// Name returns the provider identifier.
func (p *Provider) Name() string {
	return "gdpr"
}

// Run fetches the GDPR controls catalog, parses controls, and writes them to storage.
func (p *Provider) Run(ctx context.Context) (int, error) {
	p.logger.Info("fetching GDPR controls catalog", "url", CatalogURL)

	destPath := filepath.Join(os.TempDir(), "gdpr_catalog.json")
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

	p.logger.Info("parsed GDPR controls", "count", len(controls))

	count := 0
	for _, ctrl := range controls {
		id := fmt.Sprintf("%s/%s", FrameworkID, ctrl.ControlID)
		if err := p.store.WriteControl(ctx, id, ctrl); err != nil {
			p.logger.Warn("failed to write control", "id", id, "error", err)
			continue
		}
		count++
	}

	p.logger.Info("wrote GDPR controls to storage", "count", count)
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

type gdprCatalog struct {
	Controls []gdprControl `json:"controls"`
	Groups   []gdprGroup   `json:"groups,omitempty"`
}

type gdprGroup struct {
	ID       string        `json:"id"`
	Title    string        `json:"title"`
	Article  string        `json:"article"`
	Controls []gdprControl `json:"controls"`
}

type gdprControl struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
	Article     string `json:"article,omitempty"`
	Paragraph   string `json:"paragraph,omitempty"`
	Level       string `json:"level,omitempty"`
}

func (p *Provider) parse(path string) ([]grc.Control, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var catalog gdprCatalog
	if err := json.NewDecoder(f).Decode(&catalog); err != nil {
		return nil, fmt.Errorf("decode GDPR catalog: %w", err)
	}

	var controls []grc.Control

	for _, group := range catalog.Groups {
		for _, ctrl := range group.Controls {
			controls = append(controls, p.toControl(ctrl, group.Title, group.Article))
		}
	}

	if len(controls) == 0 {
		for _, ctrl := range catalog.Controls {
			controls = append(controls, p.toControl(ctrl, ctrl.Article, ctrl.Article))
		}
	}

	return controls, nil
}

func (p *Provider) toControl(ctrl gdprControl, family, article string) grc.Control {
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
		References: []grc.Reference{
			{
				Source:  "GDPR Regulation (EU) 2016/679",
				Section: ctrl.Article,
			},
		},
	}
}

func (p *Provider) writeEmbeddedControls(ctx context.Context) (int, error) {
	p.logger.Info("using embedded GDPR controls")

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

	p.logger.Info("wrote embedded GDPR controls to storage", "count", count)
	return count, nil
}

func embeddedControls() []grc.Control {
	controls := []grc.Control{}

	article5 := []struct{ id, title, desc string }{
		{"A5-1", "Lawfulness, fairness and transparency", "Personal data shall be processed lawfully, fairly and in a transparent manner in relation to the data subject."},
		{"A5-2", "Purpose limitation", "Personal data shall be collected for specified, explicit and legitimate purposes and not further processed in a manner that is incompatible with those purposes."},
		{"A5-3", "Data minimisation", "Personal data shall be adequate, relevant and limited to what is necessary in relation to the purposes for which they are processed."},
		{"A5-4", "Accuracy", "Personal data shall be accurate and, where necessary, kept up to date; every reasonable step must be taken to ensure that inaccurate data are erased or rectified without delay."},
		{"A5-5", "Storage limitation", "Personal data shall be kept in a form which permits identification of data subjects for no longer than is necessary for the purposes of processing."},
		{"A5-6", "Integrity and confidentiality", "Personal data shall be processed in a manner that ensures appropriate security, including protection against unauthorised or unlawful processing and against accidental loss, destruction or damage."},
		{"A5-7", "Accountability", "The controller shall be responsible for, and be able to demonstrate compliance with, the principles of data processing."},
	}

	article6 := []struct{ id, title, desc string }{
		{"A6-1", "Consent-based processing", "Processing shall be lawful only if and to the extent that the data subject has given consent to the processing of their personal data."},
		{"A6-2", "Contractual necessity", "Processing is lawful where necessary for the performance of a contract to which the data subject is party."},
		{"A6-3", "Legal obligation", "Processing is lawful where necessary for compliance with a legal obligation to which the controller is subject."},
		{"A6-4", "Vital interests", "Processing is lawful where necessary to protect the vital interests of the data subject or another natural person."},
		{"A6-5", "Public interest", "Processing is lawful where necessary for the performance of a task carried out in the public interest or in the exercise of official authority."},
		{"A6-6", "Legitimate interests", "Processing is lawful where necessary for the purposes of the legitimate interests pursued by the controller, except where overridden by the data subject's interests."},
	}

	article7 := []struct{ id, title, desc string }{
		{"A7-1", "Conditions for consent", "Where processing is based on consent, the controller shall be able to demonstrate that the data subject has consented."},
		{"A7-2", "Explicit consent", "If the data subject's consent is given in the context of a written declaration, the request for consent shall be presented in an intelligible and easily accessible form."},
		{"A7-3", "Right to withdraw consent", "The data subject shall have the right to withdraw consent at any time. Withdrawal shall not affect the lawfulness of processing based on consent before its withdrawal."},
	}

	article25 := []struct{ id, title, desc string }{
		{"A25-1", "Data protection by design", "The controller shall implement appropriate technical and organisational measures designed to implement data-protection principles effectively."},
		{"A25-2", "Data protection by default", "The controller shall implement appropriate technical and organisational measures to ensure that only personal data necessary for each specific purpose are processed."},
		{"A25-3", "Pseudonymisation measures", "Measures shall include pseudonymisation and encryption of personal data where appropriate."},
	}

	article32 := []struct{ id, title, desc string }{
		{"A32-1", "Security of processing", "The controller and processor shall implement appropriate technical and organisational measures to ensure a level of security appropriate to the risk."},
		{"A32-2", "Encryption of personal data", "Measures shall include the pseudonymisation and encryption of personal data as appropriate technical measures."},
		{"A32-3", "Confidentiality and resilience", "Measures shall ensure the ongoing confidentiality, integrity, availability and resilience of processing systems and services."},
		{"A32-4", "Restoration of availability", "Measures shall include the ability to restore the availability and access to personal data in a timely manner in the event of a physical or technical incident."},
		{"A32-5", "Regular testing and assessment", "The controller and processor shall implement a process for regularly testing, assessing and evaluating the effectiveness of security measures."},
		{"A32-6", "Adherence to codes of conduct", "Adherence to an approved code of conduct or certification mechanism may be used as an element to demonstrate compliance."},
	}

	article33 := []struct{ id, title, desc string }{
		{"A33-1", "Notification of breach to authority", "In the case of a personal data breach, the controller shall notify the supervisory authority without undue delay and, where feasible, not later than 72 hours after becoming aware of it."},
		{"A33-2", "Content of breach notification", "The notification shall describe the nature of the breach, categories and number of data subjects affected, likely consequences, and measures taken."},
		{"A33-3", "Documentation of breaches", "The controller shall document any personal data breaches, comprising the facts relating to the breach, its effects and remedial action taken."},
	}

	article34 := []struct{ id, title, desc string }{
		{"A34-1", "Communication of breach to data subject", "When the breach is likely to result in a high risk to the rights and freedoms of natural persons, the controller shall communicate the breach to the data subject without undue delay."},
		{"A34-2", "Content of breach communication", "The communication shall describe the nature of the breach in clear and plain language, and recommend measures to mitigate possible adverse effects."},
		{"A34-3", "Exceptions to communication", "Communication is not required if the data is encrypted, subsequent measures ensure high risk is unlikely to materialise, or communication would involve disproportionate effort."},
	}

	article35 := []struct{ id, title, desc string }{
		{"A35-1", "Data protection impact assessment", "Where processing is likely to result in a high risk to the rights and freedoms of natural persons, the controller shall carry out an assessment of the impact of the processing operations."},
		{"A35-2", "Assessment content", "The assessment shall contain a description of the processing operations, purposes, an assessment of necessity and proportionality, and measures to address risks."},
		{"A35-3", "Prior consultation", "Where a data protection impact assessment indicates high risk that cannot be mitigated, the controller shall consult the supervisory authority prior to processing."},
		{"A35-4", "Review of assessments", "The controller shall review the data protection impact assessment at least when there is a change of the risk represented by processing operations."},
	}

	for _, c := range article5 {
		controls = append(controls, grc.Control{
			Framework:   FrameworkID,
			ControlID:   c.id,
			Title:       c.title,
			Family:      "Principles (Article 5)",
			Description: c.desc,
			Level:       "standard",
			References:  []grc.Reference{{Source: "GDPR Regulation (EU) 2016/679", Section: "Article 5"}},
		})
	}

	for _, c := range article6 {
		controls = append(controls, grc.Control{
			Framework:   FrameworkID,
			ControlID:   c.id,
			Title:       c.title,
			Family:      "Lawfulness of Processing (Article 6)",
			Description: c.desc,
			Level:       "standard",
			References:  []grc.Reference{{Source: "GDPR Regulation (EU) 2016/679", Section: "Article 6"}},
		})
	}

	for _, c := range article7 {
		controls = append(controls, grc.Control{
			Framework:   FrameworkID,
			ControlID:   c.id,
			Title:       c.title,
			Family:      "Conditions for Consent (Article 7)",
			Description: c.desc,
			Level:       "standard",
			References:  []grc.Reference{{Source: "GDPR Regulation (EU) 2016/679", Section: "Article 7"}},
		})
	}

	for _, c := range article25 {
		controls = append(controls, grc.Control{
			Framework:   FrameworkID,
			ControlID:   c.id,
			Title:       c.title,
			Family:      "Data Protection by Design and Default (Article 25)",
			Description: c.desc,
			Level:       "standard",
			References:  []grc.Reference{{Source: "GDPR Regulation (EU) 2016/679", Section: "Article 25"}},
		})
	}

	for _, c := range article32 {
		controls = append(controls, grc.Control{
			Framework:   FrameworkID,
			ControlID:   c.id,
			Title:       c.title,
			Family:      "Security of Processing (Article 32)",
			Description: c.desc,
			Level:       "standard",
			References:  []grc.Reference{{Source: "GDPR Regulation (EU) 2016/679", Section: "Article 32"}},
		})
	}

	for _, c := range article33 {
		controls = append(controls, grc.Control{
			Framework:   FrameworkID,
			ControlID:   c.id,
			Title:       c.title,
			Family:      "Notification of Breach (Article 33)",
			Description: c.desc,
			Level:       "high",
			References:  []grc.Reference{{Source: "GDPR Regulation (EU) 2016/679", Section: "Article 33"}},
		})
	}

	for _, c := range article34 {
		controls = append(controls, grc.Control{
			Framework:   FrameworkID,
			ControlID:   c.id,
			Title:       c.title,
			Family:      "Communication of Breach (Article 34)",
			Description: c.desc,
			Level:       "high",
			References:  []grc.Reference{{Source: "GDPR Regulation (EU) 2016/679", Section: "Article 34"}},
		})
	}

	for _, c := range article35 {
		controls = append(controls, grc.Control{
			Framework:   FrameworkID,
			ControlID:   c.id,
			Title:       c.title,
			Family:      "Data Protection Impact Assessment (Article 35)",
			Description: c.desc,
			Level:       "standard",
			References:  []grc.Reference{{Source: "GDPR Regulation (EU) 2016/679", Section: "Article 35"}},
		})
	}

	return controls
}
