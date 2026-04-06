package kait_zait

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/shift/enrichment-engine/pkg/grc"
	"github.com/shift/enrichment-engine/pkg/storage"
)

const (
	FrameworkKAIT = "KAIT"
	FrameworkZAIT = "ZAIT"
)

// Provider implements KAIT (capital markets) and ZAIT (payment institutions) BaFin IT supervisory controls.
// Controls are written under both KAIT/ and ZAIT/ framework prefixes.
type Provider struct {
	store  storage.Backend
	logger *slog.Logger
}

// New creates a new KAIT/ZAIT provider.
func New(store storage.Backend, logger *slog.Logger) *Provider {
	return &Provider{
		store:  store,
		logger: logger,
	}
}

// Name returns the provider identifier.
func (p *Provider) Name() string {
	return "kait_zait"
}

// Run writes all KAIT and ZAIT controls to storage.
func (p *Provider) Run(ctx context.Context) (int, error) {
	p.logger.Info("loading KAIT/ZAIT BaFin capital/payment IT supervisory controls")

	count := 0

	for _, ctrl := range kaitControls() {
		id := fmt.Sprintf("%s/%s", FrameworkKAIT, ctrl.ControlID)
		if err := p.store.WriteControl(ctx, id, ctrl); err != nil {
			p.logger.Warn("failed to write control", "id", id, "error", err)
			continue
		}
		count++
	}

	for _, ctrl := range zaitControls() {
		id := fmt.Sprintf("%s/%s", FrameworkZAIT, ctrl.ControlID)
		if err := p.store.WriteControl(ctx, id, ctrl); err != nil {
			p.logger.Warn("failed to write control", "id", id, "error", err)
			continue
		}
		count++
	}

	p.logger.Info("wrote KAIT/ZAIT controls to storage", "count", count)
	return count, nil
}

func kaitControls() []grc.Control {
	ref := func(section string) []grc.Reference {
		return []grc.Reference{
			{
				Source:  "KAIT (BaFin 2019 — Kapitalverwaltungsaufsichtliche Anforderungen an die IT)",
				Section: section,
			},
		}
	}

	return []grc.Control{
		{
			Framework:   FrameworkKAIT,
			ControlID:   "KAIT.1.1",
			Title:       "IT governance (capital markets)",
			Family:      "IT Strategy",
			Description: "An IT strategy and governance framework is established for capital investment management institutions.",
			Level:       "standard",
			RelatedCWEs: []string{},
			Tags:        []string{"governance", "capital-markets"},
			References:  ref("KAIT.1.1"),
		},
		{
			Framework:   FrameworkKAIT,
			ControlID:   "KAIT.2.1",
			Title:       "Risk management",
			Family:      "Information Risk Management",
			Description: "Information risks are identified, assessed, and managed for capital investment IT systems.",
			Level:       "standard",
			RelatedCWEs: []string{},
			Tags:        []string{"risk-management", "capital-markets"},
			References:  ref("KAIT.2.1"),
		},
		{
			Framework:   FrameworkKAIT,
			ControlID:   "KAIT.3.1",
			Title:       "Access control",
			Family:      "Access Control",
			Description: "Access to capital markets IT systems is controlled using authentication and authorisation mechanisms.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-284", "CWE-287"},
			Tags:        []string{"access-control", "capital-markets"},
			References:  ref("KAIT.3.1"),
		},
		{
			Framework:   FrameworkKAIT,
			ControlID:   "KAIT.4.1",
			Title:       "Application security for trading systems",
			Family:      "Application Development",
			Description: "Trading system applications are developed and maintained securely with protection against race conditions and logic flaws.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-362"},
			Tags:        []string{"sdlc", "race-condition", "capital-markets"},
			References:  ref("KAIT.4.1"),
		},
		{
			Framework:   FrameworkKAIT,
			ControlID:   "KAIT.5.1",
			Title:       "Outsourcing and cloud",
			Family:      "IT Outsourcing",
			Description: "IT outsourcing and cloud service arrangements are subject to appropriate security controls.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-1357"},
			Tags:        []string{"supply-chain", "capital-markets"},
			References:  ref("KAIT.5.1"),
		},
		{
			Framework:   FrameworkKAIT,
			ControlID:   "KAIT.6.1",
			Title:       "Logging and audit trail",
			Family:      "IT Operations",
			Description: "Comprehensive logging and audit trails are maintained for capital markets trading and IT operations.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-778"},
			Tags:        []string{"logging", "capital-markets"},
			References:  ref("KAIT.6.1"),
		},
		{
			Framework:   FrameworkKAIT,
			ControlID:   "KAIT.7.1",
			Title:       "Incident response",
			Family:      "IT Operations",
			Description: "IT security incidents are managed and reported to BaFin in accordance with capital markets supervisory requirements.",
			Level:       "standard",
			RelatedCWEs: []string{},
			Tags:        []string{"incident-response", "capital-markets"},
			References:  ref("KAIT.7.1"),
		},
	}
}

func zaitControls() []grc.Control {
	ref := func(section string) []grc.Reference {
		return []grc.Reference{
			{
				Source:  "ZAIT (BaFin 2022 — Zahlungsdiensteaufsichtliche Anforderungen an die IT)",
				Section: section,
			},
		}
	}

	return []grc.Control{
		{
			Framework:   FrameworkZAIT,
			ControlID:   "ZAIT.1.1",
			Title:       "IT governance (payment)",
			Family:      "IT Strategy",
			Description: "An IT strategy and governance framework is established for payment service providers.",
			Level:       "standard",
			RelatedCWEs: []string{},
			Tags:        []string{"governance", "payment"},
			References:  ref("ZAIT.1.1"),
		},
		{
			Framework:   FrameworkZAIT,
			ControlID:   "ZAIT.2.1",
			Title:       "Risk management",
			Family:      "Information Risk Management",
			Description: "Information risks including operational and cyber risks are managed for payment IT systems.",
			Level:       "standard",
			RelatedCWEs: []string{},
			Tags:        []string{"risk-management", "payment"},
			References:  ref("ZAIT.2.1"),
		},
		{
			Framework:   FrameworkZAIT,
			ControlID:   "ZAIT.3.1",
			Title:       "Authentication for payment transactions",
			Family:      "Access Control",
			Description: "Strong authentication is implemented for payment transactions including PSD2-compliant strong customer authentication.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-287", "CWE-306", "CWE-798"},
			Tags:        []string{"authentication", "payment"},
			References:  ref("ZAIT.3.1"),
		},
		{
			Framework:   FrameworkZAIT,
			ControlID:   "ZAIT.4.1",
			Title:       "Payment data protection",
			Family:      "Data Security",
			Description: "Payment and financial data is protected using encryption at rest and in transit.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-311", "CWE-312"},
			Tags:        []string{"encryption", "payment"},
			References:  ref("ZAIT.4.1"),
		},
		{
			Framework:   FrameworkZAIT,
			ControlID:   "ZAIT.5.1",
			Title:       "Fraud detection systems",
			Family:      "IT Operations",
			Description: "Fraud detection and prevention systems are implemented for payment processing.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-840"},
			Tags:        []string{"payment", "fraud"},
			References:  ref("ZAIT.5.1"),
		},
		{
			Framework:   FrameworkZAIT,
			ControlID:   "ZAIT.6.1",
			Title:       "Third-party payment processor security",
			Family:      "IT Outsourcing",
			Description: "Third-party payment processors and service providers are subject to security controls and monitoring.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-1357"},
			Tags:        []string{"supply-chain", "payment"},
			References:  ref("ZAIT.6.1"),
		},
		{
			Framework:   FrameworkZAIT,
			ControlID:   "ZAIT.7.1",
			Title:       "Incident reporting to BaFin/EBA",
			Family:      "IT Operations",
			Description: "Major operational and security incidents are reported to BaFin and EBA in accordance with PSD2 and ZAIT requirements.",
			Level:       "standard",
			RelatedCWEs: []string{},
			Tags:        []string{"incident-response", "payment"},
			References:  ref("ZAIT.7.1"),
		},
	}
}
