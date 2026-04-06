package iec_62443

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/shift/enrichment-engine/pkg/grc"
	"github.com/shift/enrichment-engine/pkg/storage"
)

const FrameworkID = "IEC_62443"

type Provider struct {
	store  storage.Backend
	logger *slog.Logger
}

func New(store storage.Backend, logger *slog.Logger) *Provider {
	return &Provider{store: store, logger: logger}
}

func (p *Provider) Name() string { return "iec_62443" }

func (p *Provider) Run(ctx context.Context) (int, error) {
	p.logger.Info("loading IEC 62443 industrial automation controls")

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

	p.logger.Info("wrote IEC 62443 controls to storage", "count", count)
	return count, nil
}

func staticControls() []grc.Control {
	ref := func(section string) []grc.Reference {
		return []grc.Reference{{Source: "IEC 62443", Section: section}}
	}

	return []grc.Control{
		{
			Framework:   FrameworkID,
			ControlID:   "FR-1",
			Title:       "Functional Safety Integration",
			Family:      "Functional Safety",
			Description: "Ensure that security measures do not compromise the functional safety requirements of industrial control systems. Safety instrumented functions must continue operating correctly even when cybersecurity defences are triggered or under attack.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-1357"},
			Tags:        []string{"governance", "supply-chain"},
			References:  ref("IEC 62443-3-3 FR-1"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "SR-1",
			Title:       "Human User Identification and Authentication",
			Family:      "System Security",
			Description: "Require all human operators interacting with the control system to prove their identity through unique credentials before gaining access. This prevents unauthorised individuals from manipulating industrial processes or configuration settings.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-287", "CWE-306"},
			Tags:        []string{"authentication", "access-control"},
			References:  ref("IEC 62443-3-3 SR-1"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "SR-2",
			Title:       "Software and Firmware Integrity Verification",
			Family:      "System Security",
			Description: "Verify that all software and firmware loaded onto control system devices originates from a trusted source and has not been altered. Cryptographic signatures or checksums should be validated before execution to guard against malicious modifications introduced through the supply chain.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-1357", "CWE-347"},
			Tags:        []string{"supply-chain", "integrity"},
			References:  ref("IEC 62443-3-3 SR-2"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "SR-3",
			Title:       "Malicious Code Protection",
			Family:      "System Security",
			Description: "Deploy mechanisms to detect, prevent, and respond to the introduction of malicious software into the industrial control environment. Anti-malware scanning and application whitelisting help maintain the operational integrity of field devices and engineering workstations.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-506"},
			Tags:        []string{"network", "vulnerability-management"},
			References:  ref("IEC 62443-3-3 SR-3"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "SR-4",
			Title:       "Security Functionality Audit Logging",
			Family:      "System Security",
			Description: "Record all security-relevant events such as authentication attempts, access control decisions, and configuration changes in tamper-evident logs. These records support forensic analysis and incident response when abnormal behaviour is detected on the industrial network.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-778"},
			Tags:        []string{"logging", "network"},
			References:  ref("IEC 62443-3-3 SR-4"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "SR-5",
			Title:       "Communications Integrity",
			Family:      "System Security",
			Description: "Protect data traversing industrial networks against unauthorised modification or injection through cryptographic mechanisms. Ensuring message authenticity between controllers, sensors, and actuators prevents adversaries from spoofing process commands.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-345"},
			Tags:        []string{"network", "cryptography"},
			References:  ref("IEC 62443-3-3 SR-5"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "SR-6",
			Title:       "Communications Confidentiality",
			Family:      "System Security",
			Description: "Encrypt sensitive data exchanged across the industrial network so that intercepted traffic cannot be read by unauthorised parties. Confidentiality is especially important for proprietary process parameters and operator credentials transmitted between components.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-319"},
			Tags:        []string{"cryptography", "network"},
			References:  ref("IEC 62443-3-3 SR-6"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "SR-7",
			Title:       "Network Traffic Filtering",
			Family:      "System Security",
			Description: "Enforce boundary controls that restrict network traffic to only the protocols and endpoints required for industrial operations. Deep packet inspection and allow-list policies reduce the attack surface exposed to the plant network.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-284"},
			Tags:        []string{"network", "access-control"},
			References:  ref("IEC 62443-3-3 SR-7"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "CR-1",
			Title:       "Component Robustness Against Input Validation Errors",
			Family:      "Component Security",
			Description: "Design embedded and application components to reject malformed inputs without crashing or entering an undefined state. Buffer overflows and injection flaws in industrial protocols can be exploited to disrupt physical processes, so strict input handling is essential.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-119", "CWE-20"},
			Tags:        []string{"sdlc", "integrity"},
			References:  ref("IEC 62443-4-2 CR-1"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "CR-2",
			Title:       "Component Resource Availability Protection",
			Family:      "Component Security",
			Description: "Ensure that individual components can withstand resource exhaustion attacks such as flooding or connection depletion. Industrial devices often have limited processing capacity, making them vulnerable to denial-of-service tactics that could halt production.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-400"},
			Tags:        []string{"network", "vulnerability-management"},
			References:  ref("IEC 62443-4-2 CR-2"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "CR-3",
			Title:       "Component Session and Communication Authentication",
			Family:      "Component Security",
			Description: "Require each component to authenticate communication peers before exchanging sensitive data or control commands. Mutual authentication between devices on the control network limits the risk of man-in-the-middle attacks targeting industrial protocols.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-287", "CWE-306"},
			Tags:        []string{"authentication", "network"},
			References:  ref("IEC 62443-4-2 CR-3"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "CR-4",
			Title:       "Component Cryptographic Integrity and Confidentiality",
			Family:      "Component Security",
			Description: "Implement cryptographic protections at the component level to verify the integrity of stored data and to encrypt sensitive configuration values. This prevents tampering with device settings that could alter process behaviour or disable safety interlocks.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-311", "CWE-327"},
			Tags:        []string{"cryptography", "integrity"},
			References:  ref("IEC 62443-4-2 CR-4"),
		},
	}
}
