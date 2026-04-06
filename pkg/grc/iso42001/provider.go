package iso42001

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/shift/enrichment-engine/pkg/grc"
	"github.com/shift/enrichment-engine/pkg/storage"
)

const FrameworkID = "ISO_42001"

type Provider struct {
	store  storage.Backend
	logger *slog.Logger
}

func New(store storage.Backend, logger *slog.Logger) *Provider {
	return &Provider{store: store, logger: logger}
}

func (p *Provider) Name() string { return "iso42001" }

func (p *Provider) Run(ctx context.Context) (int, error) {
	p.logger.Info("loading ISO/IEC 42001 AI management system controls")

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

	p.logger.Info("wrote ISO 42001 controls to storage", "count", count)
	return count, nil
}

func staticControls() []grc.Control {
	ref := func(section string) []grc.Reference {
		return []grc.Reference{{Source: "ISO/IEC 42001:2023", Section: section}}
	}

	return []grc.Control{
		{
			Framework:   FrameworkID,
			ControlID:   "A.6.1",
			Title:       "AI Risk Assessment and Impact Analysis",
			Family:      "AI Risk Assessment",
			Description: "Systematically identify and evaluate risks that arise from deploying artificial intelligence systems, including risks to fairness, safety, and reliability. The assessment should consider both intended uses and foreseeable misuses of the AI system across its operational context.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-693"},
			Tags:        []string{"governance", "vulnerability-management"},
			References:  ref("A.6.1"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "A.6.2",
			Title:       "AI System Categorisation and Classification",
			Family:      "AI Risk Assessment",
			Description: "Classify AI systems according to their risk level based on factors such as autonomy, decision-making impact, and the sensitivity of data they process. Classification determines the rigour of controls that must be applied throughout the system lifecycle.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-693"},
			Tags:        []string{"governance"},
			References:  ref("A.6.2"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "A.7.1",
			Title:       "AI Policy and Governance Framework",
			Family:      "AI Governance",
			Description: "Establish an organisational policy that defines roles, responsibilities, and accountability structures for AI system development and operation. The governance framework should align with existing information security management practices and regulatory obligations.",
			Level:       "standard",
			RelatedCWEs: []string{},
			Tags:        []string{"governance"},
			References:  ref("A.7.1"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "A.7.2",
			Title:       "AI System Roles and Responsibilities",
			Family:      "AI Governance",
			Description: "Assign clear ownership for each AI system, covering development oversight, operational monitoring, and incident escalation. Defined responsibilities prevent gaps where nobody is accountable for a system's behaviour after deployment.",
			Level:       "standard",
			RelatedCWEs: []string{},
			Tags:        []string{"governance"},
			References:  ref("A.7.2"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "A.8.1",
			Title:       "Training Data Quality and Provenance",
			Family:      "AI Data Quality",
			Description: "Ensure that data used to train AI models is representative, accurate, and free from biases that could lead to unfair outcomes. Document the origin, collection methods, and preprocessing steps applied to training datasets to support reproducibility and audit.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-1357", "CWE-829"},
			Tags:        []string{"supply-chain", "integrity"},
			References:  ref("A.8.1"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "A.8.2",
			Title:       "AI Model Supply Chain Controls",
			Family:      "AI Data Quality",
			Description: "Manage risks introduced by third-party models, pre-trained weights, and external datasets integrated into the AI system. Verify the provenance of acquired components and assess them for hidden vulnerabilities or embedded biases before deployment.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-1357", "CWE-829"},
			Tags:        []string{"supply-chain", "sdlc"},
			References:  ref("A.8.2"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "A.9.1",
			Title:       "AI System Transparency and Explainability",
			Family:      "AI Transparency",
			Description: "Provide stakeholders with meaningful information about how AI systems make decisions, including the factors considered and the confidence levels of outputs. Transparency measures should be calibrated to the audience, offering technical detail for auditors and plain-language summaries for affected individuals.",
			Level:       "standard",
			RelatedCWEs: []string{},
			Tags:        []string{"governance"},
			References:  ref("A.9.1"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "A.9.2",
			Title:       "AI System Monitoring and Performance Tracking",
			Family:      "AI Transparency",
			Description: "Continuously observe deployed AI systems for drift in accuracy, fairness, and alignment with stated objectives. Monitoring results should trigger reviews or retraining when performance degrades beyond acceptable thresholds, ensuring the system remains fit for purpose over time.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-693"},
			Tags:        []string{"logging", "vulnerability-management"},
			References:  ref("A.9.2"),
		},
	}
}
