package csa_ccm

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/vincents-ai/enrichment-engine/pkg/grc"
	"github.com/vincents-ai/enrichment-engine/pkg/storage"
)

const FrameworkID = "CSA_CCM_V4"
const CatalogURL = ""

type Provider struct {
	store  storage.Backend
	logger *slog.Logger
}

func New(store storage.Backend, logger *slog.Logger) *Provider {
	return &Provider{store: store, logger: logger}
}

func (p *Provider) Name() string { return "csa_ccm" }

func (p *Provider) Run(ctx context.Context) (int, error) {
	return p.writeEmbeddedControls(ctx)
}

func (p *Provider) writeEmbeddedControls(ctx context.Context) (int, error) {
	p.logger.Info("using embedded CSA CCM v4 controls")
	controls := embeddedControls()
	count := 0
	for _, ctrl := range controls {
		id := fmt.Sprintf("%s/%s", FrameworkID, ctrl.ControlID)
		if err := p.store.WriteControl(ctx, id, ctrl); err != nil {
			p.logger.Warn("failed to write control", "id", id, "error", err)
			continue
		}
		count++
	}
	p.logger.Info("wrote embedded CSA CCM controls to storage", "count", count)
	return count, nil
}

func embeddedControls() []grc.Control {
	type c struct{ id, title, desc string }
	items := []struct {
		family string
		items  []c
	}{
		{"IAM", []c{
			{"IAM-01", "Identity and Access Management (IAM) Policy", "Define and implement an IAM policy aligned with cloud-specific requirements including lifecycle management of identities."},
			{"IAM-02", "Identity Federation", "Implement identity federation using standards such as SAML or OpenID Connect to enable single sign-on across cloud services."},
			{"IAM-03", "Role-Based Access Control", "Implement role-based access controls with least privilege enforcement and regular access reviews."},
			{"IAM-04", "Multi-Factor Authentication", "Require multi-factor authentication for privileged accounts and all access to management consoles and APIs."},
			{"IAM-05", "Credential Management", "Implement secure credential lifecycle management including rotation, storage, and revocation."},
			{"IAM-06", "Privileged Access Management", "Implement privileged access management with just-in-time access, session recording, and approval workflows."},
			{"IAM-07", "Service Account Management", "Manage service accounts with appropriate permissions, regular rotation, and monitoring for misuse."},
			{"IAM-08", "API Authentication", "Secure API access using authentication tokens, API keys, and mutual TLS as appropriate."},
			{"IAM-09", "De-provisioning", "Ensure timely de-provisioning of access upon role change or termination including cloud service accounts."},
			{"IAM-10", "Access Reviews", "Conduct periodic reviews of user access rights and privileges across all cloud services."},
			{"IAM-11", "Shared Responsibility Awareness", "Clearly define and document IAM responsibilities between cloud provider and customer."},
		}},
		{"TVM", []c{
			{"TVM-01", "Vulnerability Scanning", "Perform regular vulnerability scans on cloud infrastructure, applications, and container images."},
			{"TVM-02", "Vulnerability Remediation", "Establish and enforce timelines for vulnerability remediation based on severity."},
			{"TVM-03", "Penetration Testing", "Conduct penetration testing on cloud environments including applications, APIs, and infrastructure."},
			{"TVM-04", "Threat Intelligence", "Subscribe to and consume threat intelligence feeds relevant to cloud services and threats."},
			{"TVM-05", "Bug Bounty", "Implement or participate in a bug bounty program to identify vulnerabilities in cloud-facing assets."},
			{"TVM-06", "Vulnerability Disclosure", "Establish a vulnerability disclosure policy and process for reporting and responding to findings."},
			{"TVM-07", "Attack Surface Management", "Maintain an inventory of internet-facing assets and continuously monitor for unauthorized changes."},
		}},
		{"DSP", []c{
			{"DSP-01", "Data Classification", "Classify data based on sensitivity and regulatory requirements with cloud-specific handling rules."},
			{"DSP-02", "Data Encryption at Rest", "Encrypt all sensitive data at rest using customer-managed keys with FIPS-140 validated modules."},
			{"DSP-03", "Data Encryption in Transit", "Enforce TLS 1.2 or higher for all data in transit including internal service-to-service communication."},
			{"DSP-04", "Data Loss Prevention", "Implement data loss prevention controls to prevent unauthorized exfiltration of sensitive data."},
			{"DSP-05", "Data Retention and Disposal", "Define data retention policies and implement secure data disposal for cloud-stored data."},
			{"DSP-06", "Key Management", "Implement a key management lifecycle including generation, rotation, storage, and destruction of cryptographic keys."},
			{"DSP-07", "Privacy Impact Assessment", "Conduct privacy impact assessments for cloud services that process personal data."},
		}},
		{"CIS", []c{
			{"CIS-01", "Continuous Monitoring", "Implement continuous security monitoring across cloud infrastructure, applications, and data."},
			{"CIS-02", "Security Configuration Baselines", "Maintain and enforce security configuration baselines for all cloud resources."},
			{"CIS-03", "Change Management", "Implement change management processes for cloud resources including approval, testing, and rollback."},
			{"CIS-04", "Compliance Monitoring", "Continuously monitor compliance against relevant frameworks, standards, and internal policies."},
			{"CIS-05", "Security Posture Management", "Implement cloud security posture management (CSPM) to detect and remediate misconfigurations."},
			{"CIS-06", "Incident Detection", "Deploy detection capabilities for security incidents including anomalous behavior and policy violations."},
			{"CIS-07", "Security Automation", "Automate security controls including remediation, scaling, and compliance reporting."},
		}},
		{"IPY", []c{
			{"IPY-01", "Network Segmentation", "Implement network segmentation to isolate cloud workloads and limit lateral movement."},
			{"IPY-02", "Firewall and Network Controls", "Deploy firewalls, security groups, and network access control lists following least privilege."},
			{"IPY-03", "DDoS Protection", "Implement DDoS protection for all internet-facing cloud resources."},
			{"IPY-04", "Secure Network Architecture", "Design and implement secure network architecture following zero trust principles."},
			{"IPY-05", "Private Connectivity", "Use private connectivity options such as VPC peering, VPN, or private endpoints."},
		}},
		{"SAB", []c{
			{"SAB-01", "Supply Chain Risk Management", "Implement a supply chain risk management program for cloud services and third-party components."},
			{"SAB-02", "Vendor Assessment", "Assess third-party cloud vendors and services for security posture before onboarding."},
			{"SAB-03", "Software Bill of Materials", "Maintain a software bill of materials (SBOM) for all deployed software components."},
			{"SAB-04", "Third-Party Monitoring", "Continuously monitor third-party services for security incidents and compliance changes."},
			{"SAB-05", "Contractual Security Requirements", "Include security requirements in contracts with cloud providers and third-party vendors."},
		}},
		{"SEF", []c{
			{"SEF-01", "Log Collection", "Collect and aggregate security logs from all cloud services, applications, and infrastructure."},
			{"SEF-02", "Security Event Analysis", "Analyze security events for indicators of compromise and anomalous activity."},
			{"SEF-03", "Incident Response Integration", "Integrate cloud security events with incident response processes and playbooks."},
			{"SEF-04", "Threat Hunting", "Conduct proactive threat hunting based on intelligence and behavioral analytics."},
			{"SEF-05", "Security Metrics and Reporting", "Define, track, and report security metrics aligned with business objectives."},
		}},
		{"RSK", []c{
			{"RSK-01", "Risk Assessment", "Conduct regular risk assessments of cloud environments including threats, vulnerabilities, and impacts."},
			{"RSK-02", "Risk Treatment", "Implement risk treatment plans including accept, mitigate, transfer, or avoid strategies."},
			{"RSK-03", "Risk Register", "Maintain a risk register for cloud-specific risks with ownership and treatment status."},
			{"RSK-04", "Risk Appetite", "Define and communicate risk appetite and tolerance for cloud operations."},
		}},
		{"GRC", []c{
			{"GRC-01", "Governance Framework", "Establish a governance framework for cloud security aligned with organizational objectives."},
			{"GRC-02", "Compliance Mapping", "Map cloud controls to applicable regulatory requirements and frameworks."},
			{"GRC-03", "Audit Readiness", "Maintain audit readiness with comprehensive logging, documentation, and evidence collection."},
			{"GRC-04", "Regulatory Monitoring", "Monitor regulatory changes and update cloud security controls accordingly."},
			{"GRC-05", "Policy Management", "Implement centralized policy management for cloud security policies."},
		}},
		{"KEA", []c{
			{"KEA-01", "Encryption Standards", "Use approved encryption standards and algorithms for all cryptographic operations."},
			{"KEA-02", "Key Generation", "Generate cryptographic keys using approved random number generators and appropriate key lengths."},
			{"KEA-03", "Key Storage", "Store cryptographic keys in hardware security modules or approved key management services."},
			{"KEA-04", "Key Rotation", "Implement cryptographic key rotation policies based on usage, time, or compromise events."},
			{"KEA-05", "Certificate Management", "Manage digital certificates including issuance, renewal, and revocation."},
		}},
		{"INR", []c{
			{"INR-01", "Data Portability", "Ensure data portability and interoperability across cloud services using open standards."},
			{"INR-02", "API Security", "Secure APIs with authentication, authorization, input validation, and rate limiting."},
			{"INR-03", "Service Integration Security", "Secure service-to-service integrations with mutual authentication and encrypted channels."},
			{"INR-04", "Standards Compliance", "Use industry standards for cloud service integration and data exchange."},
		}},
	}

	controls := make([]grc.Control, 0)
	for _, group := range items {
		for _, c := range group.items {
			controls = append(controls, grc.Control{
				Framework:   FrameworkID,
				ControlID:   c.id,
				Title:       c.title,
				Family:      group.family,
				Description: c.desc,
				Level:       "standard",
				References:  []grc.Reference{{Source: "CSA Cloud Controls Matrix v4", Section: c.id}},
			})
		}
	}
	return controls
}
