package enisa_healthcare

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/shift/enrichment-engine/pkg/grc"
	"github.com/shift/enrichment-engine/pkg/storage"
)

const FrameworkID = "ENISA_HEALTHCARE"

type Provider struct {
	store  storage.Backend
	logger *slog.Logger
}

func New(store storage.Backend, logger *slog.Logger) *Provider {
	return &Provider{store: store, logger: logger}
}

func (p *Provider) Name() string {
	return "enisa_healthcare"
}

func (p *Provider) Run(ctx context.Context) (int, error) {
	p.logger.Info("loading ENISA Healthcare Cybersecurity controls")

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

	p.logger.Info("wrote ENISA Healthcare controls to storage", "count", count)
	return count, nil
}

func staticControls() []grc.Control {
	ref := func(section string) []grc.Reference {
		return []grc.Reference{{Source: "ENISA Cybersecurity for Hospitals", Section: section}}
	}

	return []grc.Control{
		{
			Framework:   FrameworkID,
			ControlID:   "HC-1",
			Title:       "Clinical Network Segmentation",
			Family:      "Network Segmentation",
			Description: "Hospital networks must be divided into isolated zones that separate clinical devices from administrative systems and public-facing services. Traffic between zones should be restricted through firewalls and access control lists to limit the blast radius of a breach and protect sensitive medical equipment from lateral movement.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-287", "CWE-306"},
			Tags:        []string{"supply-chain", "access-control", "network"},
			References:  ref("HC-1"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "HC-2",
			Title:       "Medical Device Security Assurance",
			Family:      "Medical Device Security",
			Description: "Connected medical devices such as infusion pumps, imaging systems, and patient monitors must be inventoried, patched within vendor-supported lifecycles, and isolated on dedicated network segments. Security assessments should verify that devices cannot be trivially compromised and that default credentials have been changed before deployment.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-119", "CWE-306"},
			Tags:        []string{"supply-chain", "integrity"},
			References:  ref("HC-2"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "HC-3",
			Title:       "Role-Based Access to Clinical Systems",
			Family:      "Access Control",
			Description: "Access to electronic health records and clinical information systems must follow the principle of least privilege, with role-based permissions ensuring staff can only view or modify data relevant to their duties. Authentication should enforce strong passwords or multi-factor mechanisms, and sessions should expire after periods of inactivity.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-287", "CWE-306"},
			Tags:        []string{"access-control", "governance"},
			References:  ref("HC-3"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "HC-4",
			Title:       "Patient Data Protection and Encryption",
			Family:      "Data Protection",
			Description: "All patient data must be encrypted at rest and in transit using industry-standard algorithms, with key management procedures that limit access to authorised personnel only. Data minimisation principles should be applied so that only the information strictly necessary for treatment or billing is collected and retained.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-200", "CWE-311"},
			Tags:        []string{"access-control", "governance", "integrity"},
			References:  ref("HC-4"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "HC-5",
			Title:       "Healthcare Incident Response Planning",
			Family:      "Incident Response",
			Description: "Hospitals must maintain and regularly test incident response plans tailored to healthcare scenarios, including ransomware attacks that could disrupt patient care. Plans should define escalation paths, communication procedures with regulators and patients, and manual fallback processes for critical clinical workflows when IT systems are unavailable.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-200", "CWE-287"},
			Tags:        []string{"supply-chain", "logging", "governance"},
			References:  ref("HC-5"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "HC-6",
			Title:       "Clinical Business Continuity",
			Family:      "Business Continuity",
			Description: "Continuity plans must ensure that essential clinical services can continue operating during cyber incidents, with documented manual procedures for triage, medication administration, and diagnostic workflows. Regular disaster recovery drills should test both IT restoration timelines and the ability of clinical staff to function without electronic systems.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-119", "CWE-200"},
			Tags:        []string{"governance", "integrity"},
			References:  ref("HC-6"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "HC-7",
			Title:       "Cybersecurity Awareness for Clinical Staff",
			Family:      "Staff Training",
			Description: "All hospital personnel including clinical, administrative, and support staff should receive regular cybersecurity awareness training covering phishing, social engineering, and safe handling of patient data. Training programmes should be updated to reflect current threat trends and should include practical exercises such as simulated phishing campaigns.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-287", "CWE-306"},
			Tags:        []string{"governance", "access-control"},
			References:  ref("HC-7"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "HC-8",
			Title:       "Secure Remote Access for Healthcare",
			Family:      "Remote Access",
			Description: "Remote access to hospital systems, whether by travelling clinicians, telemedicine providers, or medical device vendors, must be mediated through encrypted VPN tunnels with multi-factor authentication. Vendor remote sessions should be time-limited, recorded where possible, and restricted to specific systems and functions needed for maintenance.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-287", "CWE-306", "CWE-200"},
			Tags:        []string{"access-control", "supply-chain", "logging"},
			References:  ref("HC-8"),
		},
	}
}
