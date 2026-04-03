package nis2

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

const FrameworkID = "NIS2_Directive_2022"

var CatalogURL = "https://raw.githubusercontent.com/ENISA-EU/nis2-directive/main/nis2_requirements.json"

// Provider fetches NIS2 Directive compliance requirements from the EU cybersecurity directive.
type Provider struct {
	store  storage.Backend
	logger *slog.Logger
}

// New creates a new NIS2 Directive provider.
func New(store storage.Backend, logger *slog.Logger) *Provider {
	return &Provider{
		store:  store,
		logger: logger,
	}
}

// Name returns the provider identifier.
func (p *Provider) Name() string {
	return "nis2"
}

// Run fetches the NIS2 catalog, parses controls, and writes them to storage.
func (p *Provider) Run(ctx context.Context) (int, error) {
	p.logger.Info("fetching NIS2 Directive requirements catalog", "url", CatalogURL)

	f, err := os.CreateTemp("", "nis2_catalog_*.json")
	if err != nil {
		return 0, fmt.Errorf("create temp file: %w", err)
	}
	destPath := f.Name()
	f.Close()
	defer os.Remove(destPath)

	var controls []grc.Control

	if err := p.download(ctx, CatalogURL, destPath); err != nil {
		p.logger.Warn("failed to download remote catalog, using embedded fallback", "error", err)
		controls = p.embeddedControls()
	} else {
		var err error
		controls, err = p.parse(destPath)
		if err != nil {
			p.logger.Warn("failed to parse remote catalog, using embedded fallback", "error", err)
			controls = p.embeddedControls()
		}
	}

	p.logger.Info("parsed NIS2 controls", "count", len(controls))

	count := 0
	for _, ctrl := range controls {
		id := fmt.Sprintf("%s/%s", FrameworkID, ctrl.ControlID)
		if err := p.store.WriteControl(ctx, id, ctrl); err != nil {
			p.logger.Warn("failed to write control", "id", id, "error", err)
			continue
		}
		count++
	}

	p.logger.Info("wrote NIS2 controls to storage", "count", count)
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

// nis2Catalog represents the expected structure of a NIS2 requirements JSON catalog.
type nis2Catalog struct {
	Directive string        `json:"directive"`
	Version   string        `json:"version"`
	Articles  []nis2Article `json:"articles"`
}

type nis2Article struct {
	Number       string            `json:"number"`
	Title        string            `json:"title"`
	Description  string            `json:"description,omitempty"`
	Requirements []nis2Requirement `json:"requirements"`
}

type nis2Requirement struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Category    string `json:"category,omitempty"`
	Level       string `json:"level,omitempty"`
}

func (p *Provider) parse(path string) ([]grc.Control, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var catalog nis2Catalog
	if err := json.NewDecoder(f).Decode(&catalog); err != nil {
		return nil, fmt.Errorf("decode NIS2 catalog: %w", err)
	}

	var controls []grc.Control
	for _, article := range catalog.Articles {
		for _, req := range article.Requirements {
			level := req.Level
			if level == "" {
				level = "standard"
			}

			control := grc.Control{
				Framework:   FrameworkID,
				ControlID:   req.ID,
				Title:       req.Title,
				Family:      article.Title,
				Description: req.Description,
				Level:       level,
				References: []grc.Reference{
					{
						Source:  "NIS2 Directive",
						Section: fmt.Sprintf("Article %s", article.Number),
						URL:     "https://eur-lex.europa.eu/eli/dir/2022/2555/oj",
					},
				},
			}
			controls = append(controls, control)
		}
	}

	return controls, nil
}

// embeddedControls returns the NIS2 Directive requirements when the remote catalog is unavailable.
func (p *Provider) embeddedControls() []grc.Control {
	return []grc.Control{
		{
			Framework:   FrameworkID,
			ControlID:   "Art.21.1",
			Title:       "Risk analysis and information system security policies",
			Family:      "Risk management measures",
			Description: "Entities shall take appropriate and proportionate technical, operational and organisational measures to manage the risks posed to the security of network and information systems which they use for their operations, and to prevent or minimise the impact of incidents on recipients of their services and on other services.",
			Level:       "high",
			References:  nis2Refs("21"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "Art.21.2",
			Title:       "Incident handling",
			Family:      "Risk management measures",
			Description: "Entities shall implement measures for the prevention, detection, and handling of incidents, including incident detection systems, incident response procedures, and incident analysis capabilities.",
			Level:       "high",
			References:  nis2Refs("21"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "Art.21.3",
			Title:       "Business continuity and crisis management",
			Family:      "Risk management measures",
			Description: "Entities shall establish business continuity management practices, including risk analysis, backup management, disaster recovery, and crisis management procedures to ensure continuity of essential services.",
			Level:       "high",
			References:  nis2Refs("21"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "Art.21.4",
			Title:       "Supply chain security",
			Family:      "Risk management measures",
			Description: "Entities shall address security in their supply chains and relationships with direct suppliers and service providers, including assessing the cybersecurity posture of suppliers and verifying that suppliers implement adequate security measures.",
			Level:       "high",
			References:  nis2Refs("21"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "Art.21.5",
			Title:       "Security in network and information system acquisition, development and maintenance",
			Family:      "Risk management measures",
			Description: "Entities shall implement policies and procedures for the secure acquisition, development, and maintenance of network and information systems, including vulnerability handling and secure development practices.",
			Level:       "high",
			References:  nis2Refs("21"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "Art.21.6",
			Title:       "Policies and procedures for assessing the effectiveness of cybersecurity risk management measures",
			Family:      "Risk management measures",
			Description: "Entities shall establish policies and procedures to regularly assess the effectiveness of their cybersecurity risk management measures, including audits, reviews, and continuous monitoring.",
			Level:       "standard",
			References:  nis2Refs("21"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "Art.21.7",
			Title:       "Use of cryptography and encryption",
			Family:      "Risk management measures",
			Description: "Entities shall implement the use of cryptography and encryption where appropriate, including encryption of data in transit and at rest, and secure key management practices.",
			Level:       "high",
			References:  nis2Refs("21"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "Art.21.8",
			Title:       "Human resources security and access control policies",
			Family:      "Risk management measures",
			Description: "Entities shall implement human resources security policies, including access control policies, identity management, and the principle of least privilege for access to network and information systems.",
			Level:       "high",
			References:  nis2Refs("21"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "Art.21.9",
			Title:       "Asset management",
			Family:      "Risk management measures",
			Description: "Entities shall maintain an inventory of assets, including hardware, software, data, and services, and classify them according to their criticality and sensitivity to apply appropriate security controls.",
			Level:       "standard",
			References:  nis2Refs("21"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "Art.21.10",
			Title:       "Multi-factor authentication and secure communications",
			Family:      "Risk management measures",
			Description: "Entities shall implement multi-factor authentication or continuous authentication solutions, secure voice, video, and text communications, and secure emergency communication systems where relevant.",
			Level:       "high",
			References:  nis2Refs("21"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "Art.23.1",
			Title:       "Early warning of significant incidents",
			Family:      "Incident handling",
			Description: "Entities shall notify the CSIRT or competent authority without undue delay and in any event within 24 hours of becoming aware of a significant incident, providing an early warning with an initial indication of the cause and type of incident.",
			Level:       "high",
			References:  nis2Refs("23"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "Art.23.2",
			Title:       "Incident notification with intermediate update",
			Family:      "Incident handling",
			Description: "Entities shall provide an intermediate update within 72 hours of the initial notification, including a detailed description of the incident, severity assessment, indicators of compromise, and mitigation measures applied.",
			Level:       "high",
			References:  nis2Refs("23"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "Art.23.3",
			Title:       "Final incident report",
			Family:      "Incident handling",
			Description: "Entities shall submit a final report within one month of the intermediate update, including a detailed description of the incident, root cause analysis, impact assessment, and remedial measures taken and planned.",
			Level:       "standard",
			References:  nis2Refs("23"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "Art.24.1",
			Title:       "Notification obligations for significant incidents",
			Family:      "Notification requirements",
			Description: "Entities shall notify the competent authority or CSIRT of any incident having a substantial impact on the provision of their services, including the severity, duration, geographical spread, and number of users affected.",
			Level:       "high",
			References:  nis2Refs("24"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "Art.24.2",
			Title:       "Notification to service recipients",
			Family:      "Notification requirements",
			Description: "Entities shall notify the recipients of their services of any significant incident that may adversely affect the provision of the service, and inform them of any measures or remedies they can take in response.",
			Level:       "high",
			References:  nis2Refs("24"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "Art.25.1",
			Title:       "Use of European cybersecurity certification schemes",
			Family:      "Certification",
			Description: "Entities are encouraged to use European cybersecurity certification schemes adopted under Regulation (EU) 2019/881 for ICT products, services, and processes relevant to their operations.",
			Level:       "standard",
			References:  nis2Refs("25"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "Art.25.2",
			Title:       "Recognition of equivalent certification",
			Family:      "Certification",
			Description: "Member States shall recognize European cybersecurity certificates issued in other Member States as equivalent to national certificates, avoiding duplication of certification requirements.",
			Level:       "standard",
			References:  nis2Refs("25"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "Art.21.11",
			Title:       "Basic cyber hygiene practices and training",
			Family:      "Risk management measures",
			Description: "Entities shall implement basic cyber hygiene practices and provide regular cybersecurity awareness training and digital skills training to employees, management, and relevant personnel.",
			Level:       "high",
			References:  nis2Refs("21"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "Art.21.12",
			Title:       "Vulnerability handling and disclosure",
			Family:      "Risk management measures",
			Description: "Entities shall implement policies for vulnerability handling, including regular vulnerability scanning, patch management, and coordinated vulnerability disclosure procedures.",
			Level:       "high",
			References:  nis2Refs("21"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "Art.21.13",
			Title:       "Security testing and monitoring",
			Family:      "Risk management measures",
			Description: "Entities shall conduct regular security testing, including penetration testing, vulnerability assessments, and continuous monitoring of network and information systems for anomalies and threats.",
			Level:       "high",
			References:  nis2Refs("21"),
		},
	}
}

func nis2Refs(article string) []grc.Reference {
	return []grc.Reference{
		{
			Source:  "NIS2 Directive",
			Section: fmt.Sprintf("Article %s", article),
			URL:     "https://eur-lex.europa.eu/eli/dir/2022/2555/oj",
		},
	}
}

// Ensure Provider implements expected interface at compile time.
var _ interface {
	Name() string
	Run(ctx context.Context) (int, error)
} = (*Provider)(nil)
