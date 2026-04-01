package fedramp

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/shift/enrichment-engine/pkg/grc"
	"github.com/shift/enrichment-engine/pkg/storage"
)

const FrameworkID = "FEDRAMP_REV5"
const CatalogURL = ""

type Provider struct {
	store  storage.Backend
	logger *slog.Logger
}

func New(store storage.Backend, logger *slog.Logger) *Provider {
	return &Provider{store: store, logger: logger}
}

func (p *Provider) Name() string { return "fedramp" }

func (p *Provider) Run(ctx context.Context) (int, error) {
	return p.writeEmbeddedControls(ctx)
}

func (p *Provider) writeEmbeddedControls(ctx context.Context) (int, error) {
	p.logger.Info("using embedded FedRAMP Rev 5 controls")
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
	p.logger.Info("wrote embedded FedRAMP controls to storage", "count", count)
	return count, nil
}

func embeddedControls() []grc.Control {
	type c struct{ id, title, desc, family, level string }
	items := []struct {
		family string
		items  []c
	}{
		{"Access Control", []c{
			{"AC-1", "Policy and Procedures", "The organization develops, documents, and disseminates access control policy and procedures.", "Access Control", "low"},
			{"AC-2", "Account Management", "The organization manages system accounts including creation, activation, modification, review, disabling, and removal.", "Access Control", "low"},
			{"AC-3", "Access Enforcement", "The organization enforces approved authorizations for logical access to systems and data.", "Access Control", "low"},
			{"AC-4", "Information Flow Enforcement", "The organization enforces approved authorizations for controlling the flow of information within and between systems.", "Access Control", "moderate"},
			{"AC-5", "Separation of Duties", "The organization separates duties of individuals to reduce risk of malevolent activity without collusion.", "Access Control", "moderate"},
			{"AC-6", "Least Privilege", "The organization employs the principle of least privilege allowing only authorized accesses for users.", "Access Control", "low"},
			{"AC-7", "Unsuccessful Logon Attempts", "The organization enforces a limit of consecutive invalid logon attempts by a user during a defined time period.", "Access Control", "low"},
			{"AC-8", "System Use Notification", "The organization displays system use notification messages before granting access to the system.", "Access Control", "low"},
			{"AC-11", "Session Lock", "The organization prevents further access to the system by initiating a session lock after a defined period of inactivity.", "Access Control", "moderate"},
			{"AC-12", "Session Termination", "The organization automatically terminates a user session after defined conditions or trigger events.", "Access Control", "moderate"},
			{"AC-14", "Permitted Actions Without Identification or Authentication", "The organization identifies specific actions that can be performed without identification or authentication.", "Access Control", "low"},
			{"AC-17", "Remote Access", "The organization authorizes, monitors, and controls remote access to the system.", "Access Control", "moderate"},
		}},
		{"Audit and Accountability", []c{
			{"AU-1", "Policy and Procedures", "The organization develops, documents, and disseminates audit and accountability policy and procedures.", "Audit and Accountability", "low"},
			{"AU-2", "Audit Events", "The organization defines audit events to be recorded including user identity, type of event, date/time, and outcome.", "Audit and Accountability", "low"},
			{"AU-3", "Content of Audit Records", "The organization generates audit records containing sufficient information to establish what occurred, the source, and the outcome.", "Audit and Accountability", "low"},
			{"AU-6", "Audit Review, Analysis, and Reporting", "The organization reviews and analyzes audit records for suspicious activity and reports findings.", "Audit and Accountability", "moderate"},
			{"AU-8", "Time Stamps", "The organization uses authoritative time sources to generate time stamps for audit records.", "Audit and Accountability", "low"},
			{"AU-9", "Protection of Audit Information", "The organization protects audit information and audit tools from unauthorized access, modification, and deletion.", "Audit and Accountability", "moderate"},
			{"AU-10", "Non-repudiation", "The organization employs non-repudiation capabilities for select system events to protect against repudiation by individuals.", "Audit and Accountability", "high"},
			{"AU-12", "Audit Record Generation", "The organization generates audit records for events defined in AU-2.", "Audit and Accountability", "low"},
		}},
		{"Configuration Management", []c{
			{"CM-1", "Policy and Procedures", "The organization develops, documents, and disseminates configuration management policy and procedures.", "Configuration Management", "low"},
			{"CM-2", "Baseline Configuration", "The organization develops and maintains a baseline configuration of the system.", "Configuration Management", "low"},
			{"CM-3", "Configuration Change Control", "The organization controls changes to the system and documents security impact of changes.", "Configuration Management", "low"},
			{"CM-6", "Configuration Settings", "The organization establishes and documents configuration settings for the system using security configuration checklists.", "Configuration Management", "low"},
			{"CM-7", "Least Functionality", "The organization configures the system to provide only essential capabilities and prohibits or restricts non-essential functions.", "Configuration Management", "moderate"},
		}},
		{"Identification and Authentication", []c{
			{"IA-1", "Policy and Procedures", "The organization develops, documents, and disseminates identification and authentication policy and procedures.", "Identification and Authentication", "low"},
			{"IA-2", "User Identification and Authentication", "The organization uniquely identifies and authenticates users and processes acting on behalf of users.", "Identification and Authentication", "low"},
			{"IA-3", "Device Identification and Authentication", "The organization uniquely identifies and authenticates devices before establishing connections.", "Identification and Authentication", "moderate"},
			{"IA-5", "Authenticator Management", "The organization manages authenticators including creation, transmission, storage, and disposal.", "Identification and Authentication", "low"},
			{"IA-8", "Identification and Authentication (Non-organizational Users)", "The organization identifies and authenticates non-organizational users and processes acting on behalf of those users.", "Identification and Authentication", "low"},
		}},
		{"Incident Response", []c{
			{"IR-1", "Policy and Procedures", "The organization develops, documents, and disseminates incident response policy and procedures.", "Incident Response", "low"},
			{"IR-2", "Incident Response Training", "The organization provides incident response training to workforce members with assigned roles.", "Incident Response", "low"},
			{"IR-4", "Incident Handling", "The organization handles incidents including detection, analysis, containment, eradication, and recovery.", "Incident Response", "low"},
			{"IR-5", "Incident Monitoring", "The organization tracks and documents incidents including status, actions taken, and resolution.", "Incident Response", "low"},
			{"IR-6", "Incident Reporting", "The organization reports incident information to designated authorities including FISMA, US-CERT, and OIG.", "Incident Response", "moderate"},
		}},
		{"System and Communications Protection", []c{
			{"SC-1", "Policy and Procedures", "The organization develops, documents, and disseminates system and communications protection policy and procedures.", "System and Communications Protection", "low"},
			{"SC-7", "Boundary Protection", "The organization monitors and controls communications at the external boundary and key internal boundaries.", "System and Communications Protection", "moderate"},
			{"SC-8", "Transmission Confidentiality and Integrity", "The organization protects the confidentiality and integrity of transmitted information.", "System and Communications Protection", "moderate"},
			{"SC-12", "Cryptographic Key Establishment and Management", "The organization establishes and manages cryptographic keys for cryptography employed within the system.", "System and Communications Protection", "moderate"},
			{"SC-13", "Cryptographic Protection", "The organization employs FIPS-validated cryptography to protect the confidentiality and integrity of information.", "System and Communications Protection", "high"},
			{"SC-28", "Protection of Information at Rest", "The organization protects the confidentiality and integrity of information at rest.", "System and Communications Protection", "moderate"},
		}},
		{"System and Information Integrity", []c{
			{"SI-1", "Policy and Procedures", "The organization develops, documents, and disseminates system and information integrity policy and procedures.", "System and Information Integrity", "low"},
			{"SI-2", "Flaw Remediation", "The organization identifies, reports, and corrects system flaws in a timely manner.", "System and Information Integrity", "low"},
			{"SI-3", "Malicious Code Protection", "The organization employs malicious code protection mechanisms to detect and eradicate malicious code.", "System and Information Integrity", "low"},
			{"SI-4", "System Monitoring", "The organization monitors the system to detect attacks, unauthorized access, and anomalous behavior.", "System and Information Integrity", "moderate"},
			{"SI-7", "Software, Firmware, and Information Integrity", "The organization verifies software, firmware, and information integrity using cryptographic verification.", "System and Information Integrity", "moderate"},
		}},
		{"Privacy", []c{
			{"PR-1", "Policy and Procedures", "The organization develops, documents, and disseminates privacy policy and procedures.", "Privacy", "low"},
			{"PR-2", "Privacy Impact Assessment", "The organization conducts privacy impact assessments for systems that process PII.", "Privacy", "low"},
			{"PR-3", "Privacy Requirements for Contractors", "The organization establishes privacy requirements for contractors and service providers.", "Privacy", "low"},
			{"PR-4", "Privacy Notice", "The organization provides appropriate privacy notices to individuals whose PII is collected.", "Privacy", "low"},
		}},
	}

	controls := make([]grc.Control, 0)
	for _, group := range items {
		for _, c := range group.items {
			controls = append(controls, grc.Control{
				Framework:   FrameworkID,
				ControlID:   c.id,
				Title:       c.title,
				Family:      c.family,
				Description: c.desc,
				Level:       c.level,
				References:  []grc.Reference{{Source: "NIST SP 800-53 Rev 5", Section: c.id}},
			})
		}
	}
	return controls
}
