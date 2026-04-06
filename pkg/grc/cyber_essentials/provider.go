package cyber_essentials

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/shift/enrichment-engine/pkg/grc"
	"github.com/shift/enrichment-engine/pkg/storage"
)

const FrameworkID = "NCSC_CYBER_ESSENTIALS"

type Provider struct {
	store  storage.Backend
	logger *slog.Logger
}

func New(store storage.Backend, logger *slog.Logger) *Provider {
	return &Provider{store: store, logger: logger}
}

func (p *Provider) Name() string {
	return "cyber_essentials"
}

func (p *Provider) Run(ctx context.Context) (int, error) {
	p.logger.Info("loading NCSC Cyber Essentials controls")

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

	p.logger.Info("wrote NCSC Cyber Essentials controls to storage", "count", count)
	return count, nil
}

func staticControls() []grc.Control {
	ref := func(section string) []grc.Reference {
		return []grc.Reference{{Source: "NCSC Cyber Essentials", Section: section}}
	}

	return []grc.Control{
		{
			Framework:   FrameworkID,
			ControlID:   "CE-1",
			Title:       "Boundary Firewalls and Internet Gateways",
			Family:      "Firewalls",
			Description: "Organisations must deploy firewalls at every network boundary connecting to untrusted networks, with default-deny rules that only permit traffic required for business operations. Administrative interfaces must not be exposed to the public internet, and firewall configurations should be reviewed periodically to remove rules that are no longer necessary.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-284", "CWE-345"},
			Tags:        []string{"network", "access-control", "integrity"},
			References:  ref("CE-1"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "CE-2",
			Title:       "Secure Configuration of Systems and Devices",
			Family:      "Secure Configuration",
			Description: "All computers, network devices, and software should be configured using secure baseline settings that remove unnecessary accounts, disable unused services, and enforce strong authentication. Default credentials must be changed before deployment, and only essential software should be installed to reduce the attack surface of each system.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-254", "CWE-927"},
			Tags:        []string{"access-control", "vulnerability-management", "integrity"},
			References:  ref("CE-2"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "CE-3",
			Title:       "Access Control and Privilege Management",
			Family:      "Access Control",
			Description: "Access to systems and data must be restricted to authenticated users who require it for their role, with administrative accounts provided only to personnel who genuinely need elevated privileges. Multi-factor authentication should be mandatory for all remote access and for any administrative functions, and access rights must be reviewed when staff change roles or leave.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-284", "CWE-254"},
			Tags:        []string{"access-control", "governance"},
			References:  ref("CE-3"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "CE-4",
			Title:       "Malware Protection",
			Family:      "Malware Protection",
			Description: "Anti-malware software must be deployed on all computers and laptops, configured to scan files automatically on access, and set to update its detection signatures at least daily. In addition to signature-based detection, organisations should consider application whitelisting on systems that run a fixed set of programs to block unauthorised executables.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-927", "CWE-254"},
			Tags:        []string{"vulnerability-management", "integrity"},
			References:  ref("CE-4"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "CE-5",
			Title:       "Patch Management and Software Updates",
			Family:      "Patch Management",
			Description: "All software running on devices within the organisation must be kept up to date with the latest security patches, with high-risk and widely exploited vulnerabilities addressed within fourteen days of a patch being available. Operating systems, firmware, and third-party applications should all be covered by a documented patching process that includes testing before deployment.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-345", "CWE-927"},
			Tags:        []string{"vulnerability-management", "integrity"},
			References:  ref("CE-5"),
		},
	}
}
