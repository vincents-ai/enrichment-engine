package dora

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
	FrameworkID = "DORA_2022_2554"
)

var CatalogURL = ""

// Provider fetches and parses DORA (Digital Operational Resilience Act) controls.
type Provider struct {
	store  storage.Backend
	logger *slog.Logger
}

// New creates a new DORA provider.
func New(store storage.Backend, logger *slog.Logger) *Provider {
	return &Provider{
		store:  store,
		logger: logger,
	}
}

// Name returns the provider identifier.
func (p *Provider) Name() string {
	return "dora"
}

// Run fetches the DORA controls catalog, parses controls, and writes them to storage.
func (p *Provider) Run(ctx context.Context) (int, error) {
	if CatalogURL == "" {
		p.logger.Info("no remote catalog URL configured, using embedded DORA controls")
		return p.writeEmbeddedControls(ctx)
	}

	p.logger.Info("fetching DORA controls catalog", "url", CatalogURL)

	f, err := os.CreateTemp("", "dora_catalog_*.json")
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

	p.logger.Info("parsed DORA controls", "count", len(controls))

	count := 0
	for _, ctrl := range controls {
		id := fmt.Sprintf("%s/%s", FrameworkID, ctrl.ControlID)
		if err := p.store.WriteControl(ctx, id, ctrl); err != nil {
			p.logger.Warn("failed to write control", "id", id, "error", err)
			continue
		}
		count++
	}

	p.logger.Info("wrote DORA controls to storage", "count", count)
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

type doraCatalog struct {
	Controls []doraControl `json:"controls"`
	Groups   []doraGroup   `json:"groups,omitempty"`
}

type doraGroup struct {
	ID       string        `json:"id"`
	Title    string        `json:"title"`
	Pillar   string        `json:"pillar"`
	Controls []doraControl `json:"controls"`
}

type doraControl struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
	Pillar      string `json:"pillar,omitempty"`
	Article     string `json:"article,omitempty"`
	Level       string `json:"level,omitempty"`
}

func (p *Provider) parse(path string) ([]grc.Control, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var catalog doraCatalog
	if err := json.NewDecoder(f).Decode(&catalog); err != nil {
		return nil, fmt.Errorf("decode DORA catalog: %w", err)
	}

	var controls []grc.Control

	for _, group := range catalog.Groups {
		for _, ctrl := range group.Controls {
			controls = append(controls, p.toControl(ctrl, group.Title, group.Pillar))
		}
	}

	if len(controls) == 0 {
		for _, ctrl := range catalog.Controls {
			controls = append(controls, p.toControl(ctrl, ctrl.Pillar, ctrl.Pillar))
		}
	}

	return controls, nil
}

func (p *Provider) toControl(ctrl doraControl, family, pillar string) grc.Control {
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
				Source:  "DORA Regulation (EU) 2022/2554",
				Section: ctrl.Article,
			},
		},
	}
}

func (p *Provider) writeEmbeddedControls(ctx context.Context) (int, error) {
	p.logger.Info("using embedded DORA controls")

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

	p.logger.Info("wrote embedded DORA controls to storage", "count", count)
	return count, nil
}

func embeddedControls() []grc.Control {
	controls := []grc.Control{}

	ictRiskManagement := []struct{ id, title, desc, article string }{
		{"ICT-RM-1", "ICT risk management framework", "Financial entities shall have a sound, comprehensive and well-documented ICT risk management framework as an integral component of their overall risk management strategy.", "Article 5"},
		{"ICT-RM-2", "Governance and oversight", "The management body shall define, approve, oversee and be responsible for the implementation of all arrangements related to the ICT risk management framework.", "Article 6"},
		{"ICT-RM-3", "ICT risk management strategy", "Financial entities shall establish, implement and maintain an ICT risk management strategy that specifies the risk tolerance level for ICT risk and the acceptable level of disruption.", "Article 6"},
		{"ICT-RM-4", "ICT systems, policies and procedures", "Financial entities shall put in place and maintain sound ICT systems, protocols and tools to support their business functions.", "Article 7"},
		{"ICT-RM-5", "Identification of ICT risks", "Financial entities shall identify, classify and document all ICT-supported business functions, their information assets, and the roles and responsibilities for ICT risk management.", "Article 8"},
		{"ICT-RM-6", "Protection and prevention measures", "Financial entities shall define, document and implement ICT security policies, procedures, protocols and tools to protect information assets.", "Article 9"},
		{"ICT-RM-7", "Detection of anomalous activities", "Financial entities shall establish mechanisms to detect anomalous activities and performance indicators for ICT systems.", "Article 10"},
		{"ICT-RM-8", "Response and recovery plans", "Financial entities shall develop and implement ICT business continuity policies and response and recovery plans.", "Article 11"},
		{"ICT-RM-9", "Learning and evolution", "Financial entities shall review their ICT risk management framework and update it based on lessons learned from incidents and testing.", "Article 12"},
		{"ICT-RM-10", "Communication and reporting", "Financial entities shall establish communication plans for ICT-related incidents and ensure reporting to the management body.", "Article 13"},
	}

	incidentReporting := []struct{ id, title, desc, article string }{
		{"IR-1", "Incident management process", "Financial entities shall establish and maintain an ICT-related incident management process to detect, manage and follow up on ICT-related incidents.", "Article 17"},
		{"IR-2", "Initial notification", "Financial entities shall notify the competent authority of a major ICT-related incident without undue delay, and no later than 4 hours after classification.", "Article 18"},
		{"IR-3", "Intermediate reports", "Financial entities shall provide intermediate reports to the competent authority at appropriate intervals, updated with the status of the incident.", "Article 18"},
		{"IR-4", "Final report", "Financial entities shall submit a final report to the competent authority once the root cause analysis is completed.", "Article 18"},
		{"IR-5", "Incident classification", "Financial entities shall classify ICT-related incidents based on criteria including number of users affected, data loss, and criticality of services.", "Article 18"},
		{"IR-6", "Incident logging", "Financial entities shall log all ICT-related incidents and maintain records for analysis and regulatory reporting.", "Article 19"},
		{"IR-7", "Reporting templates", "Financial entities shall use standardized reporting templates as specified by the European Supervisory Authorities.", "Article 19"},
	}

	resilienceTesting := []struct{ id, title, desc, article string }{
		{"RT-1", "ICT business continuity policy", "Financial entities shall have an ICT business continuity policy as part of their overall business continuity policy.", "Article 24"},
		{"RT-2", "Disaster recovery policy", "Financial entities shall develop and document disaster recovery plans addressing all ICT-supported business functions.", "Article 24"},
		{"RT-3", "Backup and restoration", "Financial entities shall establish backup policies and procedures for ICT systems and data, including frequency and type of backups.", "Article 24"},
		{"RT-4", "Testing program", "Financial entities shall establish a comprehensive digital operational resilience testing program to identify and remediate vulnerabilities.", "Article 25"},
		{"RT-5", "Vulnerability assessments", "Financial entities shall perform regular vulnerability assessments and scans of ICT systems and applications.", "Article 25"},
		{"RT-6", "Open-source analyses", "Financial entities shall perform analyses of open-source software components for known vulnerabilities.", "Article 25"},
		{"RT-7", "Scenario-based testing", "Financial entities shall conduct scenario-based testing to evaluate response and recovery capabilities.", "Article 25"},
		{"RT-8", "Penetration testing", "Financial entities shall conduct regular penetration testing of critical ICT systems and applications.", "Article 25"},
		{"RT-9", "Threat-led penetration testing", "Significant financial entities shall conduct threat-led penetration testing at least every three years.", "Article 26"},
		{"RT-10", "Post-testing remediation", "Financial entities shall develop and implement remediation plans to address findings from resilience testing.", "Article 27"},
	}

	thirdPartyRisk := []struct{ id, title, desc, article string }{
		{"TPR-1", "Third-party risk policy", "Financial entities shall establish a third-party risk policy governing the use of ICT services, including cloud computing.", "Article 28"},
		{"TPR-2", "Register of information", "Financial entities shall maintain a register of all contractual arrangements on the use of ICT services provided by third-party providers.", "Article 28"},
		{"TPR-3", "Risk assessment", "Financial entities shall assess risks associated with ICT third-party service providers before entering into contractual arrangements.", "Article 28"},
		{"TPR-4", "Due diligence", "Financial entities shall perform comprehensive due diligence on ICT third-party service providers during the selection process.", "Article 28"},
		{"TPR-5", "Contractual requirements", "Contracts with ICT third-party service providers shall specify rights and obligations, including access, audit, and termination rights.", "Article 29"},
		{"TPR-6", "Exit strategies", "Financial entities shall develop and maintain exit strategies for transitioning from ICT third-party service providers.", "Article 28"},
		{"TPR-7", "Ongoing monitoring", "Financial entities shall continuously monitor the performance and risk profile of ICT third-party service providers.", "Article 28"},
		{"TPR-8", "Concentration risk", "Financial entities shall assess and manage concentration risk arising from reliance on specific ICT third-party service providers.", "Article 28"},
	}

	informationSharing := []struct{ id, title, desc, article string }{
		{"IS-1", "Information sharing arrangements", "Financial entities may exchange cyber threat information and intelligence with other financial entities.", "Article 45"},
		{"IS-2", "Sharing protocols", "Information sharing arrangements shall follow established protocols and respect confidentiality requirements.", "Article 45"},
		{"IS-3", "Collective defense", "Financial entities shall participate in information sharing communities to enhance collective cyber resilience.", "Article 45"},
	}

	for _, c := range ictRiskManagement {
		relatedCWEs := []string{}
		tags := []string{}
		if c.id == "ICT-RM-5" {
			relatedCWEs = []string{"CWE-1003", "CWE-200"}
			tags = []string{"asset-discovery", "risk-identification"}
		} else if c.id == "ICT-RM-6" {
			relatedCWEs = []string{"CWE-311", "CWE-312", "CWE-327"}
			tags = []string{"security-controls", "encryption"}
		}
		controls = append(controls, grc.Control{
			Framework:   FrameworkID,
			ControlID:   c.id,
			Title:       c.title,
			Family:      "ICT Risk Management",
			Description: c.desc,
			Level:       "standard",
			RelatedCWEs: relatedCWEs,
			Tags:        tags,
			References: []grc.Reference{
				{Source: "DORA Regulation (EU) 2022/2554", Section: c.article},
			},
		})
	}

	for _, c := range incidentReporting {
		relatedCWEs := []string{"CWE-778", "CWE-400"}
		tags := []string{"incident-reporting", "logging"}
		controls = append(controls, grc.Control{
			Framework:   FrameworkID,
			ControlID:   c.id,
			Title:       c.title,
			Family:      "ICT-related Incident Reporting",
			Description: c.desc,
			Level:       "standard",
			RelatedCWEs: relatedCWEs,
			Tags:        tags,
			References: []grc.Reference{
				{Source: "DORA Regulation (EU) 2022/2554", Section: c.article},
			},
		})
	}

	for _, c := range resilienceTesting {
		relatedCWEs := []string{}
		tags := []string{}
		switch c.id {
		case "RT-5":
			relatedCWEs = []string{"CWE-1035", "CWE-400"}
			tags = []string{"vulnerability-assessment", "resilience-testing"}
		case "RT-6":
			relatedCWEs = []string{"CWE-1035", "CWE-829"}
			tags = []string{"open-source-risk", "resilience-testing"}
		case "RT-8", "RT-9":
			relatedCWEs = []string{"CWE-284", "CWE-693"}
			tags = []string{"penetration-testing", "resilience-testing"}
		default:
			// RT-1 backup/continuity, RT-2 disaster recovery, RT-3 backup, RT-4 testing program, RT-7 scenario, RT-10 remediation
			relatedCWEs = []string{"CWE-400", "CWE-693"}
			tags = []string{"resilience-testing", "business-continuity"}
		}
		controls = append(controls, grc.Control{
			Framework:   FrameworkID,
			ControlID:   c.id,
			Title:       c.title,
			Family:      "Digital Operational Resilience Testing",
			Description: c.desc,
			Level:       "standard",
			RelatedCWEs: relatedCWEs,
			Tags:        tags,
			References: []grc.Reference{
				{Source: "DORA Regulation (EU) 2022/2554", Section: c.article},
			},
		})
	}

	for _, c := range thirdPartyRisk {
		controls = append(controls, grc.Control{
			Framework:   FrameworkID,
			ControlID:   c.id,
			Title:       c.title,
			Family:      "ICT Third-Party Risk Management",
			Description: c.desc,
			Level:       "standard",
			RelatedCWEs: []string{"CWE-1357", "CWE-693"},
			Tags:        []string{"third-party-risk", "supply-chain"},
			References: []grc.Reference{
				{Source: "DORA Regulation (EU) 2022/2554", Section: c.article},
			},
		})
	}

	for _, c := range informationSharing {
		controls = append(controls, grc.Control{
			Framework:   FrameworkID,
			ControlID:   c.id,
			Title:       c.title,
			Family:      "Information Sharing Arrangements",
			Description: c.desc,
			Level:       "standard",
			RelatedCWEs: []string{"CWE-200", "CWE-311"},
			Tags:        []string{"information-sharing", "confidentiality"},
			References: []grc.Reference{
				{Source: "DORA Regulation (EU) 2022/2554", Section: c.article},
			},
		})
	}

	return controls
}
