package iso27701

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/vincents-ai/enrichment-engine/pkg/grc"
	"github.com/vincents-ai/enrichment-engine/pkg/storage"
)

const FrameworkID = "ISO_27701"

type Provider struct {
	store  storage.Backend
	logger *slog.Logger
}

func New(store storage.Backend, logger *slog.Logger) *Provider {
	return &Provider{store: store, logger: logger}
}

func (p *Provider) Name() string { return "iso27701" }

func (p *Provider) Run(ctx context.Context) (int, error) {
	p.logger.Info("loading ISO/IEC 27701 privacy information management controls")

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

	p.logger.Info("wrote ISO 27701 controls to storage", "count", count)
	return count, nil
}

func staticControls() []grc.Control {
	ref := func(section string) []grc.Reference {
		return []grc.Reference{{Source: "ISO/IEC 27701:2019", Section: section}}
	}

	return []grc.Control{
		{
			Framework:   FrameworkID,
			ControlID:   "7.4.1",
			Title:       "Consent Collection and Recording",
			Family:      "Consent",
			Description: "Obtain and document data subject consent before collecting personal information, ensuring that consent is freely given, specific, and revocable. Maintain auditable records of when consent was granted and what the individual agreed to at that time.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-359"},
			Tags:        []string{"privacy", "governance"},
			References:  ref("7.4.1"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "7.4.2",
			Title:       "Consent Withdrawal Mechanisms",
			Family:      "Consent",
			Description: "Provide individuals with straightforward ways to retract their consent at any time, and ensure withdrawal is processed promptly across all systems. Withdrawing consent must not impair the individual's ability to exercise other data rights or access services they are entitled to.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-359"},
			Tags:        []string{"privacy", "access-control"},
			References:  ref("7.4.2"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "7.4.3",
			Title:       "Right of Access Facilitation",
			Family:      "Data Subject Rights",
			Description: "Enable data subjects to obtain a copy of their personal data and information about how it is being processed. The response must be delivered within a reasonable timeframe and in a format that is easy to understand.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-200"},
			Tags:        []string{"privacy", "access-control"},
			References:  ref("7.4.3"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "7.4.4",
			Title:       "Right to Erasure and Data Retention Limits",
			Family:      "Data Subject Rights",
			Description: "Delete personal data when it is no longer needed for the stated purpose or when the data subject requests removal. Implement retention schedules that balance business requirements with the obligation to minimise data holding periods.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-200", "CWE-532"},
			Tags:        []string{"privacy", "governance"},
			References:  ref("7.4.4"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "7.4.5",
			Title:       "Right to Data Portability",
			Family:      "Data Subject Rights",
			Description: "Supply personal data to the data subject in a structured, machine-readable format so they can transfer it to another controller. Portability mechanisms should cover data the individual provided directly and any inferred or derived data resulting from processing.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-200"},
			Tags:        []string{"privacy"},
			References:  ref("7.4.5"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "7.4.6",
			Title:       "Automated Decision-Making Safeguards",
			Family:      "Data Subject Rights",
			Description: "Protect individuals from decisions based solely on automated processing that produce legal or similarly significant effects. Provide a means for data subjects to request human review and to contest automated outcomes.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-693"},
			Tags:        []string{"privacy", "governance"},
			References:  ref("7.4.6"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "7.4.7",
			Title:       "PII Processing Purpose Limitation",
			Family:      "PII Processing",
			Description: "Collect and process personally identifiable information only for specified, explicit, and legitimate purposes. Any secondary use must be compatible with the original purpose or require a new consent from the data subject.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-359"},
			Tags:        []string{"privacy", "governance"},
			References:  ref("7.4.7"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "7.4.8",
			Title:       "PII Disclosure Logging and Audit",
			Family:      "PII Processing",
			Description: "Maintain a record of all disclosures of personal data to third parties, including the recipient, date, and lawful basis. These logs support accountability and enable the organisation to respond accurately to data subject access requests.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-532"},
			Tags:        []string{"privacy", "logging"},
			References:  ref("7.4.8"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "7.4.9",
			Title:       "Privacy by Design Integration",
			Family:      "Privacy by Design",
			Description: "Embed privacy considerations into the earliest stages of system design, architecture decisions, and process engineering. Privacy-protective measures should be proactive rather than reactive, becoming a default property of the product or service.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-200"},
			Tags:        []string{"privacy", "sdlc"},
			References:  ref("7.4.9"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "7.4.10",
			Title:       "Data Protection Impact Assessments",
			Family:      "Privacy by Design",
			Description: "Conduct structured assessments before initiating processing activities that are likely to result in high privacy risk. These assessments identify potential harms, evaluate mitigation measures, and document the rationale for proceeding with the activity.",
			Level:       "standard",
			RelatedCWEs: []string{},
			Tags:        []string{"privacy", "governance"},
			References:  ref("7.4.10"),
		},
	}
}
