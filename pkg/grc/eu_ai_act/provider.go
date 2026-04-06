package eu_ai_act

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/shift/enrichment-engine/pkg/grc"
	"github.com/shift/enrichment-engine/pkg/storage"
)

const FrameworkID = "EU_AI_ACT"

// Provider implements the EU AI Act (Regulation (EU) 2024/1689) cybersecurity controls.
type Provider struct {
	store  storage.Backend
	logger *slog.Logger
}

// New creates a new EU AI Act provider.
func New(store storage.Backend, logger *slog.Logger) *Provider {
	return &Provider{
		store:  store,
		logger: logger,
	}
}

// Name returns the provider identifier.
func (p *Provider) Name() string {
	return "eu_ai_act"
}

// Run writes all EU AI Act controls to storage.
func (p *Provider) Run(ctx context.Context) (int, error) {
	p.logger.Info("loading EU AI Act (Regulation (EU) 2024/1689) controls")

	controls := staticControls()
	count := 0
	for _, ctrl := range controls {
		id := fmt.Sprintf("%s/%s", FrameworkID, ctrl.ControlID)
		if err := p.store.WriteControl(ctx, id, ctrl); err != nil {
			p.logger.Warn("failed to write control", "id", id, "error", err)
			continue
		}
		count++
	}

	p.logger.Info("wrote EU AI Act controls to storage", "count", count)
	return count, nil
}

func staticControls() []grc.Control {
	ref := func(section string) []grc.Reference {
		return []grc.Reference{
			{
				Source:  "Regulation (EU) 2024/1689",
				URL:     "https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32024R1689",
				Section: section,
			},
		}
	}

	return []grc.Control{
		{
			Framework:   FrameworkID,
			ControlID:   "Art9.1",
			Title:       "Risk management system for AI",
			Family:      "Risk Management",
			Description: "A risk management system shall be established, implemented, documented and maintained for high-risk AI systems throughout their lifecycle.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-693"},
			Tags:        []string{"governance", "ai", "risk-management"},
			References:  ref("Article 9(1)"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "Art9.7",
			Title:       "Residual risk documentation",
			Family:      "Risk Management",
			Description: "Residual risks and their management measures shall be documented after applying risk controls.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-693"},
			Tags:        []string{"governance", "ai"},
			References:  ref("Article 9(7)"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "Art10.1",
			Title:       "Training data governance",
			Family:      "Data and Data Governance",
			Description: "Training, validation and testing datasets shall be subject to appropriate data governance and management practices.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-20", "CWE-116"},
			Tags:        []string{"input-validation", "ai", "data"},
			References:  ref("Article 10(1)"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "Art10.2",
			Title:       "Data quality criteria",
			Family:      "Data and Data Governance",
			Description: "Training, validation and testing datasets shall be relevant, sufficiently representative and free of errors.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-20"},
			Tags:        []string{"input-validation", "ai"},
			References:  ref("Article 10(2)"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "Art13.1",
			Title:       "Transparency and logging",
			Family:      "Transparency and Provision of Information",
			Description: "High-risk AI systems shall be designed and developed to ensure sufficient transparency including operation logs.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-778"},
			Tags:        []string{"logging", "ai", "transparency"},
			References:  ref("Article 13(1)"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "Art13.3",
			Title:       "Information to deployers",
			Family:      "Transparency and Provision of Information",
			Description: "Providers shall supply deployers with instructions for use including information about capabilities and limitations.",
			Level:       "standard",
			RelatedCWEs: []string{},
			Tags:        []string{"ai", "documentation"},
			References:  ref("Article 13(3)"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "Art14.1",
			Title:       "Human oversight",
			Family:      "Human Oversight",
			Description: "High-risk AI systems shall be designed and developed to enable effective human oversight during their use.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-693"},
			Tags:        []string{"ai", "governance"},
			References:  ref("Article 14(1)"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "Art15.1",
			Title:       "Accuracy, robustness, cybersecurity",
			Family:      "Accuracy, Robustness and Cybersecurity",
			Description: "High-risk AI systems shall be designed to achieve appropriate levels of accuracy, robustness and cybersecurity throughout their lifecycle.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-682", "CWE-693", "CWE-400"},
			Tags:        []string{"ai", "robustness", "denial-of-service"},
			References:  ref("Article 15(1)"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "Art15.3",
			Title:       "Resilience to adversarial inputs",
			Family:      "Accuracy, Robustness and Cybersecurity",
			Description: "High-risk AI systems shall be resilient to attempts by unauthorised third parties to alter their use, output or performance through adversarial inputs.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-20", "CWE-682"},
			Tags:        []string{"ai", "input-validation", "robustness"},
			References:  ref("Article 15(3)"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "Art15.4",
			Title:       "Cybersecurity measures for high-risk AI",
			Family:      "Accuracy, Robustness and Cybersecurity",
			Description: "Technical and organisational cybersecurity measures shall protect high-risk AI systems against unauthorised access.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-693", "CWE-284"},
			Tags:        []string{"ai", "access-control"},
			References:  ref("Article 15(4)"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "Art17.1",
			Title:       "Quality management system",
			Family:      "Quality Management System",
			Description: "Providers of high-risk AI systems shall put a quality management system in place.",
			Level:       "standard",
			RelatedCWEs: []string{},
			Tags:        []string{"governance", "ai"},
			References:  ref("Article 17(1)"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "Art72.1",
			Title:       "Incident reporting obligations",
			Family:      "Post-Market Monitoring and Reporting",
			Description: "Providers of high-risk AI systems shall report serious incidents or malfunctions to national competent authorities.",
			Level:       "standard",
			RelatedCWEs: []string{},
			Tags:        []string{"incident-response", "ai"},
			References:  ref("Article 72(1)"),
		},
	}
}
