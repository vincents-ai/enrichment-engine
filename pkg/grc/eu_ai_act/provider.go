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
			Description: "Organisations deploying high-risk AI systems must maintain a structured risk management process that covers the entire system lifecycle, from design through decommissioning. This involves continuously identifying potential failure modes, assessing their likelihood and severity, and applying mitigations proportionate to the risk level. Without such a process, latent hazards can propagate into production where they are far more expensive and dangerous to address.",
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
			Description: "After risk controls have been applied, any dangers that remain must be explicitly recorded along with the measures taken to keep them within acceptable bounds. This residual-risk record is essential because it provides auditors and downstream operators with a clear picture of what the system can still do wrong, even when functioning as designed.",
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
			Description: "Every dataset used to train, validate, or test a high-risk AI model needs a defined governance framework covering provenance, consent, and handling procedures. Poorly managed data introduces biases, compliance violations, and subtle model defects that are difficult to detect after training. Establishing clear ownership and pipeline controls ensures reproducibility and accountability across the data supply chain.",
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
			Description: "Datasets feeding into a high-risk model must be checked for relevance to the intended task, statistical representativeness of the deployment population, and freedom from corruption or mislabelling. A model trained on stale or unrepresentative data will produce unreliable predictions in the field, undermining safety and trust. Ongoing quality assurance on data splits is therefore a prerequisite for any credible model evaluation.",
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
			Description: "High-risk AI systems need to expose enough internal state and decision history to let operators understand and audit their behaviour in practice. This typically means structured logging of inputs, outputs, and configuration changes throughout the inference pipeline. Without such traceability, diagnosing failures or investigating misuse after the fact becomes nearly impossible.",
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
			Description: "Providers must give deployers clear, actionable documentation covering what the system can and cannot do, expected operating conditions, and known limitations. This matters because downstream operators are rarely the original developers and may misapply the technology without proper guidance, leading to unsafe outcomes and liability exposure.",
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
			Description: "Systems classified as high-risk must include mechanisms that let a qualified person monitor, interrupt, or override automated decisions in real time. Fully autonomous operation without a human safety net increases the blast radius of model failures and erodes accountability. Effective oversight design means the system surfaces the right signals at the right time for a human reviewer to act on.",
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
			Description: "High-risk AI systems must meet defined thresholds for prediction accuracy, fault tolerance, and resistance to hostile manipulation across their entire operational lifespan. A model that drifts or degrades silently in production can cause compounding errors in safety-critical domains like healthcare or transport. Continuous benchmarking and hardening against edge-case inputs are needed to maintain these properties as the deployment environment evolves.",
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
			Description: "Models operating in high-stakes environments need defences that detect and reject deliberately crafted inputs intended to skew outputs or bypass safety constraints. Adversarial attacks exploit the gap between training data and real-world inputs, and can cause a model to confidently produce harmful results. Building input sanitisation layers and adversarial testing into the development pipeline reduces this attack surface significantly.",
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
			Description: "Access to the model, its weights, training infrastructure, and prediction endpoints must be restricted using both technical controls and organisational policies. An AI system is only as secure as its least protected interface; once an attacker gains write access or can tamper with the inference pipeline, all safety guarantees dissolve. Role-based access, network segmentation, and supply-chain hardening are the baseline protections expected here.",
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
			Description: "Providers of high-risk AI must establish a formal quality management programme covering development workflows, release criteria, change control, and post-market review. This creates a repeatable, auditable chain of evidence that every model version was built and validated under controlled conditions. Without it, there is no systematic way to prevent quality regressions or demonstrate compliance to regulators.",
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
			Description: "When a high-risk AI system causes or contributes to a serious safety incident, the provider must notify the relevant national authority within a defined timeframe. Prompt reporting enables regulators to spot systemic patterns across providers and issue corrective guidance before more users are affected. Failing to report undermines collective market intelligence and can expose the provider to additional enforcement action.",
			Level:       "standard",
			RelatedCWEs: []string{},
			Tags:        []string{"incident-response", "ai"},
			References:  ref("Article 72(1)"),
		},
	}
}
