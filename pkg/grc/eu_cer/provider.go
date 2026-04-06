package eu_cer

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/shift/enrichment-engine/pkg/grc"
	"github.com/shift/enrichment-engine/pkg/storage"
)

const FrameworkID = "EU_CYBER_CERT"

type Provider struct {
	store  storage.Backend
	logger *slog.Logger
}

func New(store storage.Backend, logger *slog.Logger) *Provider {
	return &Provider{store: store, logger: logger}
}

func (p *Provider) Name() string {
	return "eu_cer"
}

func (p *Provider) Run(ctx context.Context) (int, error) {
	p.logger.Info("loading EU Cybersecurity Certification Framework controls")

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

	p.logger.Info("wrote EU Cybersecurity Certification controls to storage", "count", count)
	return count, nil
}

func staticControls() []grc.Control {
	ref := func(section string) []grc.Reference {
		return []grc.Reference{{Source: "EU Cybersecurity Certification Regulation (EU) 2024/XXX", Section: section}}
	}

	return []grc.Control{
		{
			Framework:   FrameworkID,
			ControlID:   "EUCER-01",
			Title:       "European Certification Scheme Establishment",
			Family:      "Certification Schemes",
			Description: "Establish and maintain a European cybersecurity certification scheme that defines common criteria for evaluating the security properties of ICT products, services, and processes. The scheme must be adopted by the European Commission through implementing acts and provide a structured methodology for assessing conformity across all member states.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-1357"},
			Tags:        []string{"governance", "supply-chain"},
			References:  ref("Art. 46-48"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "EUCER-02",
			Title:       "Conformity Assessment Procedures",
			Family:      "Conformity Assessment",
			Description: "Implement conformity assessment procedures that evaluate whether ICT products and services meet the security requirements defined in the applicable certification scheme. Assessments must be carried out by accredited conformity assessment bodies and cover the full lifecycle including design, development, production, and deployment phases.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-1357"},
			Tags:        []string{"governance", "supply-chain"},
			References:  ref("Art. 49-52"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "EUCER-03",
			Title:       "National Supervisory Authority Oversight",
			Family:      "Supervision",
			Description: "Designate and empower national supervisory authorities to monitor and enforce cybersecurity certification requirements within their jurisdiction. These authorities must have the competence to suspend or withdraw certificates when certified products no longer satisfy the applicable security requirements.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-284"},
			Tags:        []string{"governance", "access-control"},
			References:  ref("Art. 53-57"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "EUCER-04",
			Title:       "Market Surveillance and Enforcement",
			Family:      "Market Surveillance",
			Description: "Conduct market surveillance activities to verify that certified ICT products and services offered on the EU market maintain compliance with the issued certificates. Market surveillance authorities must have the power to restrict or prohibit the placing on the market of products that pose a cybersecurity risk.",
			Level:       "standard",
			RelatedCWEs: []string{},
			Tags:        []string{"governance", "supply-chain"},
			References:  ref("Art. 58-60"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "EUCER-05",
			Title:       "Cross-Border Mutual Recognition of Certificates",
			Family:      "Mutual Recognition",
			Description: "Ensure that cybersecurity certificates issued under a European scheme are recognised and accepted across all EU member states without requiring additional national certification. This mutual recognition principle eliminates fragmentation and reduces compliance costs for providers operating in the internal market.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-1357"},
			Tags:        []string{"governance"},
			References:  ref("Art. 61"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "EUCER-06",
			Title:       "Technical Security Requirements Definition",
			Family:      "Technical Requirements",
			Description: "Define and apply technical security requirements that specify the security properties which ICT products and services must demonstrate. These requirements must be risk-based, technology-neutral, and aligned with the state of the art to ensure they remain effective against evolving threat landscapes.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-284"},
			Tags:        []string{"governance", "access-control"},
			References:  ref("Art. 43-44"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "EUCER-07",
			Title:       "Assurance Level Differentiation",
			Family:      "Security Levels",
			Description: "Categorise cybersecurity certification into distinct assurance levels based on the risk profile and intended use of the ICT product or service. Each assurance level must correspond to the severity of potential impacts from security breaches, with higher levels mandating more rigorous evaluation methods.",
			Level:       "standard",
			RelatedCWEs: []string{},
			Tags:        []string{"governance"},
			References:  ref("Art. 45"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "EUCER-08",
			Title:       "Transparency and Public Disclosure",
			Family:      "Transparency",
			Description: "Maintain public registers of issued cybersecurity certificates and ensure that relevant certification information is accessible to consumers, businesses, and public authorities. Transparency mechanisms must enable market participants to verify the certification status of products and services.",
			Level:       "standard",
			RelatedCWEs: []string{},
			Tags:        []string{"governance"},
			References:  ref("Art. 62"),
		},
	}
}
