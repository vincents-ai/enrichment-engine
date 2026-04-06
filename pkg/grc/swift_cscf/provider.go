package swift_cscf

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/shift/enrichment-engine/pkg/grc"
	"github.com/shift/enrichment-engine/pkg/storage"
)

const FrameworkID = "SWIFT_CSP"

type Provider struct {
	store  storage.Backend
	logger *slog.Logger
}

func New(store storage.Backend, logger *slog.Logger) *Provider {
	return &Provider{store: store, logger: logger}
}

func (p *Provider) Name() string {
	return "swift_cscf"
}

func (p *Provider) Run(ctx context.Context) (int, error) {
	p.logger.Info("loading SWIFT Customer Security Controls Framework controls")

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

	p.logger.Info("wrote SWIFT CSCF controls to storage", "count", count)
	return count, nil
}

func staticControls() []grc.Control {
	ref := func(section string) []grc.Reference {
		return []grc.Reference{{Source: "SWIFT Customer Security Controls Framework v2024", Section: section}}
	}

	return []grc.Control{
		{
			Framework:   FrameworkID,
			ControlID:   "CSCF-01",
			Title:       "Secure Environment for SWIFT Infrastructure",
			Family:      "Secure Environment",
			Description: "Isolate and harden the computing environment that hosts SWIFT-related applications and interfaces to prevent unauthorised access and lateral movement. This includes maintaining strict network segmentation, applying operating system hardening baselines, and ensuring that only essential services are running on systems within the SWIFT security perimeter.",
			Level:       "mandatory",
			RelatedCWEs: []string{"CWE-287", "CWE-306"},
			Tags:        []string{"network", "access-control"},
			References:  ref("1.1 Environment Protection"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "CSCF-02",
			Title:       "Privileged Access Management and Authentication",
			Family:      "Access Control",
			Description: "Enforce multi-factor authentication for all accounts with access to SWIFT systems and apply the principle of least privilege to restrict user permissions to the minimum required for their operational role. Privileged account credentials must be stored in an approved vault and regularly rotated to limit exposure from potential compromise.",
			Level:       "mandatory",
			RelatedCWEs: []string{"CWE-287", "CWE-306"},
			Tags:        []string{"access-control", "governance"},
			References:  ref("1.2 Access Control"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "CSCF-03",
			Title:       "Transaction Anomaly Detection and Monitoring",
			Family:      "Anomaly Detection",
			Description: "Deploy anomaly detection mechanisms that continuously monitor SWIFT messaging traffic and user behaviour patterns to identify potentially fraudulent or unauthorised transactions. Detection rules must be regularly updated to reflect evolving attack techniques and must generate alerts for immediate investigation by the security operations team.",
			Level:       "mandatory",
			RelatedCWEs: []string{"CWE-778"},
			Tags:        []string{"logging", "governance"},
			References:  ref("1.3 Detect Anomalies"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "CSCF-04",
			Title:       "Data Protection and Encryption Controls",
			Family:      "Data Protection",
			Description: "Apply encryption and data protection measures to safeguard SWIFT-related data both at rest and in transit, ensuring that sensitive financial messages and authentication credentials cannot be intercepted or exfiltrated. Cryptographic key management procedures must define generation, storage, rotation, and destruction lifecycle stages.",
			Level:       "mandatory",
			RelatedCWEs: []string{"CWE-311", "CWE-532"},
			Tags:        []string{"cryptography", "network"},
			References:  ref("1.4 Physical Security and Data Protection"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "CSCF-05",
			Title:       "Regular Security Testing and Vulnerability Scanning",
			Family:      "Security Testing",
			Description: "Conduct periodic vulnerability assessments and penetration tests against all systems within the SWIFT environment to identify weaknesses before adversaries can exploit them. Testing must cover both the infrastructure layer and application-layer controls, with findings tracked through to remediation and verified through retesting.",
			Level:       "mandatory",
			RelatedCWEs: []string{"CWE-287", "CWE-306"},
			Tags:        []string{"vulnerability-management", "governance"},
			References:  ref("1.5 Perform Security Testing"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "CSCF-06",
			Title:       "Cybersecurity Awareness and Training Programme",
			Family:      "Awareness",
			Description: "Deliver mandatory cybersecurity awareness training to all personnel who interact with SWIFT systems, covering social engineering tactics, phishing recognition, and incident reporting procedures. Training content must be updated at least annually and reinforced with simulated phishing exercises to measure organisational readiness.",
			Level:       "mandatory",
			RelatedCWEs: []string{"CWE-532"},
			Tags:        []string{"governance"},
			References:  ref("1.6 Train Staff"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "CSCF-07",
			Title:       "Incident Response and Recovery Planning",
			Family:      "Incident Response",
			Description: "Establish and regularly exercise an incident response plan specifically tailored to SWIFT-related security incidents, defining roles, communication protocols, escalation paths, and recovery procedures. The plan must include coordination procedures with SWIFT and relevant financial authorities and must be tested through tabletop exercises at least annually.",
			Level:       "mandatory",
			RelatedCWEs: []string{"CWE-778"},
			Tags:        []string{"governance", "logging"},
			References:  ref("1.7 Incident Response and Recovery"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "CSCF-08",
			Title:       "Third-Party and Vendor Risk Management",
			Family:      "Third-Party Risk",
			Description: "Assess and manage cybersecurity risks arising from third-party vendors, service providers, and connectivity partners that have access to or interact with SWIFT infrastructure. Vendor assessments must evaluate security controls, contractual security obligations, and the potential impact of a vendor compromise on the institution's SWIFT operations.",
			Level:       "advisory",
			RelatedCWEs: []string{"CWE-287", "CWE-311"},
			Tags:        []string{"governance", "supply-chain"},
			References:  ref("1.8 Third-Party Risk Management"),
		},
	}
}
