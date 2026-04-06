package tisax

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/shift/enrichment-engine/pkg/grc"
	"github.com/shift/enrichment-engine/pkg/storage"
)

const FrameworkID = "TISAX"

// Provider implements the TISAX (Trusted Information Security Assessment Exchange) VDA ISA v6.0 controls.
type Provider struct {
	store  storage.Backend
	logger *slog.Logger
}

// New creates a new TISAX provider.
func New(store storage.Backend, logger *slog.Logger) *Provider {
	return &Provider{
		store:  store,
		logger: logger,
	}
}

// Name returns the provider identifier.
func (p *Provider) Name() string {
	return "tisax"
}

// Run writes all TISAX controls to storage.
func (p *Provider) Run(ctx context.Context) (int, error) {
	p.logger.Info("loading TISAX VDA ISA v6.0 controls")

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

	p.logger.Info("wrote TISAX controls to storage", "count", count)
	return count, nil
}

func staticControls() []grc.Control {
	ref := func(section string) []grc.Reference {
		return []grc.Reference{
			{
				Source:  "VDA ISA v6.0 (TISAX)",
				URL:     "https://www.enx.com/tisax/",
				Section: section,
			},
		}
	}

	return []grc.Control{
		{
			Framework:   FrameworkID,
			ControlID:   "1.1.1",
			Title:       "Information security policy",
			Family:      "Information Security Management",
			Description: "An information security policy is established, approved by management, published and communicated.",
			Level:       "standard",
			RelatedCWEs: []string{},
			Tags:        []string{"governance"},
			References:  ref("1.1.1"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "2.1.1",
			Title:       "Asset inventory",
			Family:      "Asset Management",
			Description: "An inventory of all information assets and systems is maintained and kept up to date.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-1059"},
			Tags:        []string{"asset-management", "supply-chain"},
			References:  ref("2.1.1"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "2.1.2",
			Title:       "Classification of information assets",
			Family:      "Asset Management",
			Description: "Information assets are classified according to their sensitivity and criticality.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-200"},
			Tags:        []string{"data", "information-disclosure"},
			References:  ref("2.1.2"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "3.1.1",
			Title:       "Access rights management",
			Family:      "Access Control",
			Description: "Access rights to information and systems are granted on a least-privilege basis and reviewed regularly.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-284", "CWE-269"},
			Tags:        []string{"access-control", "authz"},
			References:  ref("3.1.1"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "3.1.2",
			Title:       "Network access control",
			Family:      "Access Control",
			Description: "Network access is controlled and restricted to authorised users and systems.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-284"},
			Tags:        []string{"network", "access-control"},
			References:  ref("3.1.2"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "3.2.1",
			Title:       "Cryptographic controls",
			Family:      "Cryptography",
			Description: "Cryptographic controls are used to protect sensitive information and communications.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-327", "CWE-326"},
			Tags:        []string{"crypto", "cryptography"},
			References:  ref("3.2.1"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "4.1.1",
			Title:       "Patch and vulnerability management",
			Family:      "Operations Security",
			Description: "A formal patch management process identifies, assesses, and applies security patches in a timely manner.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-693"},
			Tags:        []string{"vulnerability-management"},
			References:  ref("4.1.1"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "4.1.2",
			Title:       "Malware protection",
			Family:      "Operations Security",
			Description: "Malware protection controls are implemented and maintained on all relevant systems.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-94"},
			Tags:        []string{"injection", "malware"},
			References:  ref("4.1.2"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "5.1.1",
			Title:       "Physical security of ECU/hardware",
			Family:      "Physical and Environmental Security",
			Description: "Physical security controls protect ECUs and hardware components from unauthorised access.",
			Level:       "standard",
			RelatedCWEs: []string{},
			Tags:        []string{"physical"},
			References:  ref("5.1.1"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "5.2.1",
			Title:       "Secure development lifecycle",
			Family:      "Supplier Relationships and Development",
			Description: "Security is integrated into the software development lifecycle for automotive components.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-693"},
			Tags:        []string{"sdlc", "supply-chain"},
			References:  ref("5.2.1"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "5.2.2",
			Title:       "Security testing of vehicle components",
			Family:      "Supplier Relationships and Development",
			Description: "Security testing is performed on vehicle software and firmware components prior to release.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-693"},
			Tags:        []string{"testing", "automotive"},
			References:  ref("5.2.2"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "5.2.3",
			Title:       "Vulnerability assessment for automotive",
			Family:      "Supplier Relationships and Development",
			Description: "Vulnerability assessments are performed on automotive software components including memory safety analysis.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-119", "CWE-787"},
			Tags:        []string{"memory", "automotive"},
			References:  ref("5.2.3"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "5.3.1",
			Title:       "Third-party/supplier security",
			Family:      "Supplier Relationships and Development",
			Description: "Security requirements are imposed on third-party suppliers and their software components are verified.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-1357"},
			Tags:        []string{"supply-chain"},
			References:  ref("5.3.1"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "6.1.1",
			Title:       "Incident response",
			Family:      "Incident Management",
			Description: "An incident response plan is established and tested to handle security incidents.",
			Level:       "standard",
			RelatedCWEs: []string{},
			Tags:        []string{"incident-response"},
			References:  ref("6.1.1"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "6.2.1",
			Title:       "Business continuity",
			Family:      "Business Continuity Management",
			Description: "Business continuity plans are established to maintain operations during and after security incidents.",
			Level:       "standard",
			RelatedCWEs: []string{},
			Tags:        []string{"availability"},
			References:  ref("6.2.1"),
		},
	}
}
