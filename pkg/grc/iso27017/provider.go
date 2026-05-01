package iso27017

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/vincents-ai/enrichment-engine/pkg/grc"
	"github.com/vincents-ai/enrichment-engine/pkg/storage"
)

const FrameworkID = "ISO_27017"

type Provider struct {
	store  storage.Backend
	logger *slog.Logger
}

func New(store storage.Backend, logger *slog.Logger) *Provider {
	return &Provider{store: store, logger: logger}
}

func (p *Provider) Name() string { return "iso27017" }

func (p *Provider) Run(ctx context.Context) (int, error) {
	p.logger.Info("loading ISO/IEC 27017 cloud security controls")

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

	p.logger.Info("wrote ISO 27017 controls to storage", "count", count)
	return count, nil
}

func staticControls() []grc.Control {
	ref := func(section string) []grc.Reference {
		return []grc.Reference{{Source: "ISO/IEC 27017:2015", Section: section}}
	}

	return []grc.Control{
		{
			Framework:   FrameworkID,
			ControlID:   "CLD.6.1.1",
			Title:       "Shared Responsibility Roles and Obligations",
			Family:      "Access Control",
			Description: "Define and document which security responsibilities belong to the cloud service provider and which remain with the cloud customer. Clear delineation prevents gaps where neither party addresses a particular risk, especially during incident response and data recovery scenarios.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-284"},
			Tags:        []string{"governance", "access-control"},
			References:  ref("6.1.1"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "CLD.6.1.2",
			Title:       "Customer Identity and Credential Management",
			Family:      "Access Control",
			Description: "Manage the lifecycle of user identities and access credentials for cloud services, including provisioning, modification, and revocation. Strong credential policies reduce the chance that exfiltrated credentials allow unauthorised access to cloud resources.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-287", "CWE-522"},
			Tags:        []string{"authentication", "access-control"},
			References:  ref("6.1.2"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "CLD.6.1.3",
			Title:       "Access Protection for Cloud Interfaces",
			Family:      "Access Control",
			Description: "Restrict access to cloud management consoles, APIs, and service endpoints using network-level controls and authentication requirements. Limiting exposure of administrative interfaces lowers the risk of brute-force attacks and credential stuffing.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-306", "CWE-284"},
			Tags:        []string{"access-control", "network"},
			References:  ref("6.1.3"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "CLD.6.1.4",
			Title:       "Segregation of Virtual Environments",
			Family:      "Access Control",
			Description: "Isolate virtual machines, containers, and tenant workloads from one another using logical or physical separation mechanisms. Proper segregation prevents one customer's compromised workload from affecting another customer's data or availability.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-265"},
			Tags:        []string{"network", "access-control"},
			References:  ref("6.1.4"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "CLD.6.1.5",
			Title:       "Virtual Machine Hardening",
			Family:      "Access Control",
			Description: "Apply secure configuration baselines to virtual machine images, disable unnecessary services, and keep the operating system patched. Hardened images reduce the attack surface when new instances are provisioned from shared templates.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-927"},
			Tags:        []string{"vulnerability-management", "sdlc"},
			References:  ref("6.1.5"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "CLD.6.1.6",
			Title:       "Cryptographic Key Management for Cloud Services",
			Family:      "Cryptography",
			Description: "Establish processes for generating, storing, rotating, and destroying encryption keys used within cloud environments. Customers should retain control over their own keys where possible, and key usage should be auditable to detect unauthorised access.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-320", "CWE-321"},
			Tags:        []string{"cryptography", "governance"},
			References:  ref("6.1.6"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "CLD.6.1.7",
			Title:       "Encryption of Data at Rest in the Cloud",
			Family:      "Cryptography",
			Description: "Apply encryption to customer data stored on cloud infrastructure so that even physical media theft or unauthorised storage access does not expose sensitive information. Encryption schemes should allow the customer to manage or own the decryption keys independently.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-311", "CWE-312"},
			Tags:        []string{"cryptography", "privacy"},
			References:  ref("6.1.7"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "CLD.6.1.8",
			Title:       "Encryption of Data in Transit for Cloud Communications",
			Family:      "Communication Security",
			Description: "Protect all network traffic between cloud customers and cloud services using strong transport-layer encryption. This guards against eavesdropping and tampering when data traverses shared or public networks on its way to cloud endpoints.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-319"},
			Tags:        []string{"cryptography", "network"},
			References:  ref("6.1.8"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "CLD.6.1.9",
			Title:       "Cloud Supplier Relationship Security Agreements",
			Family:      "Supplier Relationships",
			Description: "Include security and privacy clauses in contracts with cloud providers that address data handling, breach notification, audit rights, and service continuity. Formal agreements give the customer legal recourse and clear expectations when security incidents occur.",
			Level:       "standard",
			RelatedCWEs: []string{},
			Tags:        []string{"supply-chain", "governance"},
			References:  ref("6.1.9"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "CLD.6.1.10",
			Title:       "Monitoring and Incident Coordination with Cloud Providers",
			Family:      "Supplier Relationships",
			Description: "Coordinate security monitoring and incident response activities with the cloud service provider to ensure timely detection and notification of threats. Joint procedures should cover log sharing, alert thresholds, and escalation paths for security events affecting customer data.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-778"},
			Tags:        []string{"logging", "supply-chain"},
			References:  ref("6.1.10"),
		},
	}
}
