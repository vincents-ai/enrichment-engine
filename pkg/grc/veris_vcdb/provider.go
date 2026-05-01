package veris_vcdb

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/vincents-ai/enrichment-engine/pkg/grc"
	"github.com/vincents-ai/enrichment-engine/pkg/storage"
)

const (
	FrameworkID = "VERIS_VCDB_V2"
	CatalogURL  = ""
)

type Provider struct {
	store  storage.Backend
	logger *slog.Logger
}

func New(store storage.Backend, logger *slog.Logger) *Provider {
	return &Provider{store: store, logger: logger}
}

func (p *Provider) Name() string {
	return "veris_vcdb"
}

func (p *Provider) Run(ctx context.Context) (int, error) {
	return p.writeEmbeddedControls(ctx)
}

func (p *Provider) writeEmbeddedControls(ctx context.Context) (int, error) {
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
	if p.logger != nil {
		p.logger.Info("wrote VERIS/VCDB controls", "count", count)
	}
	return count, nil
}

func embeddedControls() []grc.Control {
	return []grc.Control{
		{
			Framework: FrameworkID, ControlID: "VERIS-ACT-1.1",
			Title: "Malware Action: Delivered via Email", Family: "Actions",
			Description:            "Tracks incidents where malware was delivered via email attachments or links. Includes phishing-based malware delivery, malicious document payloads, and exploit kit redirects from email.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-94", "CWE-353", "CWE-494"},
			References:             []grc.Reference{{Source: "VERIS Framework", URL: "https://veriscommunity.net/", Section: "A1: Malware"}, {Source: "VCDB", URL: "https://github.com/vz-risk/VCDB", Section: "Malware Actions"}},
			ImplementationGuidance: "Monitor email gateway logs for malware detections. Track email-based delivery vectors. Correlate with phishing campaign data. Map to MITRE ATT&CK T1566.001 (Spearphishing Attachment).",
			AssessmentMethods:      []string{"Email Gateway Logs", "Phishing Campaign Data", "SIEM Correlation Rules"},
		},
		{
			Framework: FrameworkID, ControlID: "VERIS-ACT-1.2",
			Title: "Malware Action: Delivered via Web", Family: "Actions",
			Description:            "Tracks incidents where malware was delivered via web-based vectors including drive-by downloads, malicious URLs, compromised websites, and exploit kit landing pages.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-94", "CWE-78", "CWE-494"},
			References:             []grc.Reference{{Source: "VERIS Framework", URL: "https://veriscommunity.net/", Section: "A1: Malware"}, {Source: "MITRE ATT&CK", URL: "https://attack.mitre.org/", Section: "T1189: Drive-by Compromise"}},
			ImplementationGuidance: "Monitor web proxy logs for malware downloads. Track exploit kit activity. Correlate with URL reputation feeds. Map to MITRE ATT&CK T1189.",
			AssessmentMethods:      []string{"Web Proxy Logs", "URL Reputation Feeds", "Exploit Kit Tracking"},
		},
		{
			Framework: FrameworkID, ControlID: "VERIS-ACT-1.3",
			Title: "Hacking Action: Brute Force", Family: "Actions",
			Description:            "Tracks incidents involving brute force or credential stuffing attacks to gain unauthorized access to systems, accounts, or services.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-307", "CWE-521"},
			References:             []grc.Reference{{Source: "VERIS Framework", URL: "https://veriscommunity.net/", Section: "A2: Hacking"}, {Source: "MITRE ATT&CK", URL: "https://attack.mitre.org/", Section: "T1110: Brute Force"}},
			ImplementationGuidance: "Monitor authentication logs for brute force patterns. Track failed login attempts. Implement account lockout and MFA. Map to MITRE ATT&CK T1110.",
			AssessmentMethods:      []string{"Authentication Logs", "Failed Login Analytics", "Credential Stuffing Detection"},
		},
		{
			Framework: FrameworkID, ControlID: "VERIS-ACT-1.4",
			Title: "Hacking Action: SQL Injection", Family: "Actions",
			Description:            "Tracks incidents involving SQL injection attacks targeting web applications to extract, modify, or delete database contents.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-89"},
			References:             []grc.Reference{{Source: "VERIS Framework", URL: "https://veriscommunity.net/", Section: "A2: Hacking"}, {Source: "OWASP Top 10", URL: "https://owasp.org/www-project-top-ten/", Section: "A03:2021 Injection"}},
			ImplementationGuidance: "Monitor WAF logs for SQL injection patterns. Track application vulnerability assessments. Map to MITRE ATT&CK T1190. Remediate via parameterized queries.",
			AssessmentMethods:      []string{"WAF Logs", "SAST/DAST Results", "Application Code Review"},
		},
		{
			Framework: FrameworkID, ControlID: "VERIS-ACT-1.5",
			Title: "Social Action: Phishing", Family: "Actions",
			Description:            "Tracks incidents involving social engineering via phishing emails, vishing calls, or smishing messages designed to trick targets into revealing credentials or executing malicious actions.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-451", "CWE-346"},
			References:             []grc.Reference{{Source: "VERIS Framework", URL: "https://veriscommunity.net/", Section: "A3: Social"}, {Source: "MITRE ATT&CK", URL: "https://attack.mitre.org/", Section: "T1566: Phishing"}},
			ImplementationGuidance: "Track phishing simulation results. Monitor email reporting. Map to MITRE ATT&CK T1566. Correlate with credential compromise incidents.",
			AssessmentMethods:      []string{"Phishing Simulation Reports", "User Reported Emails", "Credential Compromise Correlation"},
		},
		{
			Framework: FrameworkID, ControlID: "VERIS-ACT-1.6",
			Title: "Misuse Action: Privilege Abuse", Family: "Actions",
			Description:            "Tracks incidents involving authorized users abusing their access privileges to access, modify, or exfiltrate data beyond their authorized scope.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-269", "CWE-284", "CWE-285"},
			References:             []grc.Reference{{Source: "VERIS Framework", URL: "https://veriscommunity.net/", Section: "A4: Misuse"}, {Source: "MITRE ATT&CK", URL: "https://attack.mitre.org/", Section: "T1548: Abuse Elevation Control"}},
			ImplementationGuidance: "Monitor privileged session activity. Track access beyond normal patterns. Implement separation of duties. Map to MITRE ATT&CK T1548.",
			AssessmentMethods:      []string{"Privileged Access Monitoring", "UEBA Alerts", "Access Pattern Analysis"},
		},
		{
			Framework: FrameworkID, ControlID: "VERIS-ACT-1.7",
			Title: "Physical Action: Theft of Equipment", Family: "Actions",
			Description:            "Tracks incidents involving physical theft of computing equipment (laptops, servers, mobile devices, storage media) that contain or provide access to sensitive data.",
			Level:                  "medium",
			RelatedCWEs:            []string{"CWE-523"},
			References:             []grc.Reference{{Source: "VERIS Framework", URL: "https://veriscommunity.net/", Section: "A5: Physical"}, {Source: "MITRE ATT&CK", URL: "https://attack.mitre.org/", Section: "T1052: Physical Access"}},
			ImplementationGuidance: "Track stolen device reports. Correlate with data breach assessment. Implement full-disk encryption to mitigate impact. Map to MITRE ATT&CK T1052.",
			AssessmentMethods:      []string{"Asset Theft Reports", "Encryption Status Verification", "Data Exposure Assessment"},
		},
		{
			Framework: FrameworkID, ControlID: "VERIS-ACT-1.8",
			Title: "Error Action: Misdelivery", Family: "Actions",
			Description:            "Tracks incidents involving accidental data exposure due to misdelivery of information to unintended recipients via email, postal mail, or other communication channels.",
			Level:                  "medium",
			RelatedCWEs:            []string{"CWE-359"},
			References:             []grc.Reference{{Source: "VERIS Framework", URL: "https://veriscommunity.net/", Section: "A6: Error"}, {Source: "UK ICO", URL: "https://ico.org.uk/", Section: "Data Misdelivery"}},
			ImplementationGuidance: "Track misdelivery incidents. Implement DLP email rules. Configure email encryption for sensitive data. Train staff on data handling procedures.",
			AssessmentMethods:      []string{"DLP Alert Logs", "Incident Reports", "Email Configuration Review"},
		},
		{
			Framework: FrameworkID, ControlID: "VERIS-ACT-1.9",
			Title: "Environmental Action: Natural Disaster", Family: "Actions",
			Description:            "Tracks incidents involving environmental threats (floods, fires, earthquakes, power outages) that impact the availability or integrity of data processing systems and stored data.",
			Level:                  "low",
			RelatedCWEs:            []string{"CWE-24"},
			References:             []grc.Reference{{Source: "VERIS Framework", URL: "https://veriscommunity.net/", Section: "A7: Environmental"}, {Source: "ISO 22301", URL: "https://www.iso.org/standard/22301", Section: "Business Continuity"}},
			ImplementationGuidance: "Track environmental incidents. Assess impact on data availability and integrity. Review BCP/DRP effectiveness. Update risk assessments based on incidents.",
			AssessmentMethods:      []string{"Incident Impact Assessment", "BCP/DRP Review", "Environmental Risk Register"},
		},
		{
			Framework: FrameworkID, ControlID: "VERIS-VAR-1.1",
			Title: "Variety: Unauthorized Access to System", Family: "Varieties",
			Description:            "Tracks the specific variety of unauthorized access incidents where an attacker gains access to systems, applications, or databases without authorization.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-284", "CWE-862", "CWE-22"},
			References:             []grc.Reference{{Source: "VERIS Framework", URL: "https://veriscommunity.net/", Section: "V1: Unauthorized Access"}},
			ImplementationGuidance: "Classify unauthorized access incidents by vector (web app, remote access, insider). Track initial access methods. Correlate with privilege escalation data.",
			AssessmentMethods:      []string{"Incident Classification Review", "Access Log Analysis", "Vector Attribution"},
		},
		{
			Framework: FrameworkID, ControlID: "VERIS-VAR-1.2",
			Title: "Variety: Privilege Escalation", Family: "Varieties",
			Description:            "Tracks incidents where attackers escalate privileges from standard user to admin or system-level access, enabling broader unauthorized actions.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-269", "CWE-250"},
			References:             []grc.Reference{{Source: "VERIS Framework", URL: "https://veriscommunity.net/", Section: "V1: Privilege Escalation"}, {Source: "MITRE ATT&CK", URL: "https://attack.mitre.org/", Section: "T1548: Abuse Elevation Control"}},
			ImplementationGuidance: "Track privilege escalation techniques used. Correlate with initial access vector. Map to MITRE ATT&CK privilege escalation tactics. Review remediation effectiveness.",
			AssessmentMethods:      []string{"Incident Forensic Analysis", "ATT&CK Mapping", "Remediation Review"},
		},
		{
			Framework: FrameworkID, ControlID: "VERIS-VAR-1.3",
			Title: "Variety: Data Exfiltration", Family: "Varieties",
			Description:            "Tracks incidents involving unauthorized data exfiltration, including the volume and type of data stolen, exfiltration methods, and detection mechanisms.",
			Level:                  "critical",
			RelatedCWEs:            []string{"CWE-200", "CWE-359"},
			References:             []grc.Reference{{Source: "VERIS Framework", URL: "https://veriscommunity.net/", Section: "V2: Exfiltration"}, {Source: "MITRE ATT&CK", URL: "https://attack.mitre.org/", Section: "T1048: Exfiltration Over Alternative Protocol"}},
			ImplementationGuidance: "Track exfiltration volumes and methods. Monitor network egress for anomalies. Correlate with DLP alerts. Map to MITRE ATT&CK exfiltration techniques.",
			AssessmentMethods:      []string{"DLP Logs", "Network Egress Analysis", "Data Loss Quantification"},
		},
		{
			Framework: FrameworkID, ControlID: "VERIS-VAR-1.4",
			Title: "Variety: Data Modification", Family: "Varieties",
			Description:            "Tracks incidents involving unauthorized modification of data, including database tampering, file alteration, configuration changes, and web defacement.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-345", "CWE-20"},
			References:             []grc.Reference{{Source: "VERIS Framework", URL: "https://veriscommunity.net/", Section: "V3: Data Modification"}},
			ImplementationGuidance: "Track data modification incidents. Monitor file integrity (FIM). Detect unauthorized database changes. Assess data recovery requirements.",
			AssessmentMethods:      []string{"File Integrity Monitoring", "Database Audit Logs", "Data Recovery Assessment"},
		},
		{
			Framework: FrameworkID, ControlID: "VERIS-VAR-1.5",
			Title: "Variety: Denial of Service", Family: "Varieties",
			Description:            "Tracks incidents involving denial of service attacks, including volumetric DDoS, application-layer attacks, and ransom DDoS campaigns that impact service availability.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-400", "CWE-770"},
			References:             []grc.Reference{{Source: "VERIS Framework", URL: "https://veriscommunity.net/", Section: "V5: DoS"}, {Source: "MITRE ATT&CK", URL: "https://attack.mitre.org/", Section: "T1498: Network Denial of Service"}},
			ImplementationGuidance: "Track DoS/DDoS incidents. Monitor for volumetric and application-layer attacks. Correlate with ransom demands. Map to MITRE ATT&CK T1498.",
			AssessmentMethods:      []string{"Network Traffic Analysis", "DDoS Mitigation Logs", "Ransom Demand Tracking"},
		},
		{
			Framework: FrameworkID, ControlID: "VERIS-VAR-1.6",
			Title: "Variety: Credential Theft", Family: "Varieties",
			Description:            "Tracks incidents involving theft of credentials through phishing, keylogging, password database breaches, or credential stuffing, enabling unauthorized account access.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-522", "CWE-798"},
			References:             []grc.Reference{{Source: "VERIS Framework", URL: "https://veriscommunity.net/", Section: "V1: Credential Theft"}, {Source: "MITRE ATT&CK", URL: "https://attack.mitre.org/", Section: "T1110: Brute Force"}},
			ImplementationGuidance: "Track credential theft incidents by vector. Monitor for credential stuffing using Have I Been Pwned data. Enforce MFA to mitigate stolen credential impact.",
			AssessmentMethods:      []string{"Credential Breach Database Cross-reference", "Authentication Log Analysis", "MFA Adoption Metrics"},
		},
		{
			Framework: FrameworkID, ControlID: "VERIS-VAR-1.7",
			Title: "Variety: Ransomware", Family: "Varieties",
			Description:            "Tracks ransomware incidents including ransomware family, encryption method, ransom demand, payment status, and recovery method (backup restoration vs. payment).",
			Level:                  "critical",
			RelatedCWEs:            []string{"CWE-20", "CWE-24"},
			References:             []grc.Reference{{Source: "VERIS Framework", URL: "https://veriscommunity.net/", Section: "V1: Ransomware"}, {Source: "MITRE ATT&CK", URL: "https://attack.mitre.org/", Section: "T1486: Data Encrypted for Impact"}},
			ImplementationGuidance: "Track ransomware incidents by family and variant. Document ransom demands and payment decisions. Assess recovery timeline. Map to MITRE ATT&CK T1486.",
			AssessmentMethods:      []string{"Ransomware Incident Database", "Recovery Metrics", "ATT&CK Mapping"},
		},
		{
			Framework: FrameworkID, ControlID: "VERIS-AST-1.1",
			Title: "Asset: Server Compromise", Family: "Assets",
			Description:            "Tracks incidents where servers (web, application, database, mail, file) were compromised or used as attack infrastructure.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-20"},
			References:             []grc.Reference{{Source: "VERIS Framework", URL: "https://veriscommunity.net/", Section: "A5: Server"}},
			ImplementationGuidance: "Classify incidents by server type and role. Track server compromise rates by OS and service. Correlate with vulnerability data. Assess blast radius per server type.",
			AssessmentMethods:      []string{"Asset Inventory Correlation", "Server Compromise Analytics", "Vulnerability Mapping"},
		},
		{
			Framework: FrameworkID, ControlID: "VERIS-AST-1.2",
			Title: "Asset: Network Compromise", Family: "Assets",
			Description:            "Tracks incidents where network infrastructure (routers, switches, firewalls, VPNs, wireless access points) was compromised or abused.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-20"},
			References:             []grc.Reference{{Source: "VERIS Framework", URL: "https://veriscommunity.net/", Section: "A6: Network"}},
			ImplementationGuidance: "Classify network compromise by device type. Track unauthorized network access. Correlate with network segmentation effectiveness. Assess lateral movement paths.",
			AssessmentMethods:      []string{"Network Device Logs", "Segmentation Effectiveness Review", "Lateral Movement Analysis"},
		},
		{
			Framework: FrameworkID, ControlID: "VERIS-AST-1.3",
			Title: "Asset: User Device Compromise", Family: "Assets",
			Description:            "Tracks incidents where end-user devices (laptops, desktops, mobile phones, tablets) were compromised via malware, phishing, or physical access.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-20"},
			References:             []grc.Reference{{Source: "VERIS Framework", URL: "https://veriscommunity.net/", Section: "A7: User Device"}},
			ImplementationGuidance: "Classify user device incidents by device type and OS. Track compromise vectors. Correlate with EDR detections. Assess data stored on compromised devices.",
			AssessmentMethods:      []string{"EDR Detection Logs", "Device Type Analytics", "Data Exposure Assessment"},
		},
		{
			Framework: FrameworkID, ControlID: "VERIS-AST-1.4",
			Title: "Asset: Media Compromise or Loss", Family: "Assets",
			Description:            "Tracks incidents involving compromise, theft, or loss of removable media (USB drives, external hard drives, backup tapes, optical media) containing sensitive data.",
			Level:                  "medium",
			RelatedCWEs:            []string{"CWE-523"},
			References:             []grc.Reference{{Source: "VERIS Framework", URL: "https://veriscommunity.net/", Section: "A8: Media"}},
			ImplementationGuidance: "Track media loss/theft incidents. Assess data encryption status of lost media. Quantify data exposure. Review removable media policies.",
			AssessmentMethods:      []string{"Media Loss Reports", "Encryption Status Check", "Data Exposure Assessment"},
		},
		{
			Framework: FrameworkID, ControlID: "VERIS-AST-1.5",
			Title: "Asset: Person Target", Family: "Assets",
			Description:            "Tracks incidents where individuals (employees, executives, customers) were directly targeted by social engineering, physical threats, or identity theft.",
			Level:                  "medium",
			RelatedCWEs:            []string{"CWE-451", "CWE-346"},
			References:             []grc.Reference{{Source: "VERIS Framework", URL: "https://veriscommunity.net/", Section: "A9: Person"}},
			ImplementationGuidance: "Track person-targeted incidents by role and attack method. Correlate with executive protection data. Assess social engineering success rates by department.",
			AssessmentMethods:      []string{"Target Analysis", "Social Engineering Success Rates", "Role-based Risk Assessment"},
		},
		{
			Framework: FrameworkID, ControlID: "VERIS-ATR-1.1",
			Title: "Attribute: Confidentiality Breach", Family: "Attributes",
			Description:            "Tracks incidents where data confidentiality was breached, including the type and volume of data disclosed, data sensitivity classification, and number of affected records.",
			Level:                  "critical",
			RelatedCWEs:            []string{"CWE-200", "CWE-306"},
			References:             []grc.Reference{{Source: "VERIS Framework", URL: "https://veriscommunity.net/", Section: "C: Confidentiality"}},
			ImplementationGuidance: "Quantify confidentiality breaches by data type (PII, financial, health, credentials). Track records affected. Classify data sensitivity. Assess regulatory notification requirements.",
			AssessmentMethods:      []string{"Data Breach Quantification", "Regulatory Notification Audit", "Data Classification Review"},
		},
		{
			Framework: FrameworkID, ControlID: "VERIS-ATR-1.2",
			Title: "Attribute: Integrity Breach", Family: "Attributes",
			Description:            "Tracks incidents where data or system integrity was compromised, including unauthorized data modification, configuration tampering, and data corruption.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-345", "CWE-348"},
			References:             []grc.Reference{{Source: "VERIS Framework", URL: "https://veriscommunity.net/", Section: "I: Integrity"}},
			ImplementationGuidance: "Track integrity breaches by scope and impact. Assess data restoration requirements. Review backup integrity. Document recovery timeline.",
			AssessmentMethods:      []string{"Integrity Assessment", "Backup Validation", "Recovery Timeline Analysis"},
		},
		{
			Framework: FrameworkID, ControlID: "VERIS-ATR-1.3",
			Title: "Attribute: Availability Breach", Family: "Attributes",
			Description:            "Tracks incidents where system or data availability was compromised, including duration of outage, business impact, and recovery method.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-400", "CWE-770"},
			References:             []grc.Reference{{Source: "VERIS Framework", URL: "https://veriscommunity.net/", Section: "A: Availability"}},
			ImplementationGuidance: "Track availability breaches by duration and business impact. Quantify revenue and productivity loss. Review BCP/DRP effectiveness. Document recovery actions.",
			AssessmentMethods:      []string{"Downtime Analysis", "Business Impact Assessment", "BCP/DRP Effectiveness Review"},
		},
		{
			Framework: FrameworkID, ControlID: "VERIS-DSC-1.1",
			Title: "Disclosure: External Discovery", Family: "Disclosure",
			Description:            "Tracks how incidents were discovered externally, including by external researchers, law enforcement, customers, or other third parties notifying the organization.",
			Level:                  "medium",
			RelatedCWEs:            []string{"CWE-16"},
			References:             []grc.Reference{{Source: "VERIS Framework", URL: "https://veriscommunity.net/", Section: "D: Disclosure"}, {Source: "DBIR", URL: "https://www.verizon.com/business/resources/reports/dbir/", Section: "Discovery"}},
			ImplementationGuidance: "Track discovery source distribution. Measure mean time to detect (MTTD). Improve internal detection capabilities to reduce reliance on external discovery.",
			AssessmentMethods:      []string{"Discovery Source Analysis", "MTTD Metrics", "Detection Capability Gap Assessment"},
		},
		{
			Framework: FrameworkID, ControlID: "VERIS-DSC-1.2",
			Title: "Disclosure: Internal Discovery", Family: "Disclosure",
			Description:            "Tracks incidents discovered internally through security monitoring, employee reports, audit findings, or automated security controls triggering alerts.",
			Level:                  "medium",
			RelatedCWEs:            []string{"CWE-16"},
			References:             []grc.Reference{{Source: "VERIS Framework", URL: "https://veriscommunity.net/", Section: "D: Internal Discovery"}, {Source: "DBIR", URL: "https://www.verizon.com/business/resources/reports/dbir/", Section: "Discovery"}},
			ImplementationGuidance: "Track internal discovery rates by detection method. Measure MTTD by control type. Optimize detection rules based on incident patterns. Celebrate and reward internal discovery.",
			AssessmentMethods:      []string{"Detection Method Analysis", "MTTD by Control Type", "Detection Rule Effectiveness"},
		},
		{
			Framework: FrameworkID, ControlID: "VERIS-DSC-1.3",
			Title: "Disclosure: Partner Disclosure", Family: "Disclosure",
			Description:            "Tracks incidents disclosed by business partners, suppliers, or customers who discovered the breach affecting shared data or interconnected systems.",
			Level:                  "medium",
			RelatedCWEs:            []string{"CWE-16"},
			References:             []grc.Reference{{Source: "VERIS Framework", URL: "https://veriscommunity.net/", Section: "D: Partner Disclosure"}, {Source: "DBIR", URL: "https://www.verizon.com/business/resources/reports/dbir/", Section: "Discovery"}},
			ImplementationGuidance: "Track partner-discovered incidents. Assess supply chain monitoring gaps. Improve partner security communication channels. Review data sharing agreements.",
			AssessmentMethods:      []string{"Partner Discovery Analysis", "Supply Chain Security Review", "Communication Channel Assessment"},
		},
		{
			Framework: FrameworkID, ControlID: "VERIS-VEC-1.1",
			Title: "Vector: Web Application", Family: "Vector",
			Description:            "Tracks the web application attack vector, including the specific application exploited, vulnerability exploited, and web application firewall effectiveness.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-20", "CWE-78", "CWE-22"},
			References:             []grc.Reference{{Source: "VERIS Framework", URL: "https://veriscommunity.net/", Section: "V: Web Application"}, {Source: "OWASP", URL: "https://owasp.org/", Section: "Web Security"}},
			ImplementationGuidance: "Track web application incidents by application and vulnerability type. Assess WAF effectiveness. Correlate with application security testing results. Prioritize remediation.",
			AssessmentMethods:      []string{"Web Application Incident Analysis", "WAF Effectiveness Metrics", "Application Security Correlation"},
		},
		{
			Framework: FrameworkID, ControlID: "VERIS-VEC-1.2",
			Title: "Vector: Email", Family: "Vector",
			Description:            "Tracks email as an attack vector including phishing, business email compromise (BEC), malicious attachments, and email account compromise.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-451", "CWE-94"},
			References:             []grc.Reference{{Source: "VERIS Framework", URL: "https://veriscommunity.net/", Section: "V: Email"}, {Source: "IC3 BEC Reports", URL: "https://www.ic3.gov/", Section: "BEC"}},
			ImplementationGuidance: "Track email-vector incidents by type (phishing, BEC, malware delivery). Assess email security controls effectiveness. Monitor BEC targeting patterns.",
			AssessmentMethods:      []string{"Email Vector Analysis", "Email Security Control Metrics", "BEC Pattern Analysis"},
		},
		{
			Framework: FrameworkID, ControlID: "VERIS-VEC-1.3",
			Title: "Vector: Insider Threat", Family: "Vector",
			Description:            "Tracks incidents originating from insider threats including disgruntled employees, negligent staff, and departing employees who misuse authorized access.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-269", "CWE-284", "CWE-285"},
			References:             []grc.Reference{{Source: "VERIS Framework", URL: "https://veriscommunity.net/", Section: "V: Insider"}, {Source: "MITRE ATT&CK", URL: "https://attack.mitre.org/", Section: "Insider Threat"}},
			ImplementationGuidance: "Track insider threat incidents by motivation (financial, grudges, negligence). Monitor UEBA alerts. Correlate with HR events (termination, disciplinary). Review offboarding procedures.",
			AssessmentMethods:      []string{"Insider Threat Analytics", "UEBA Alert Correlation", "HR Event Cross-reference"},
		},
		{
			Framework: FrameworkID, ControlID: "VERIS-VEC-1.4",
			Title: "Vector: Third Party", Family: "Vector",
			Description:            "Tracks incidents originating from or facilitated by third-party suppliers, service providers, or business partners, including supply chain compromises and vendor data breaches.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-829", "CWE-1357"},
			References:             []grc.Reference{{Source: "VERIS Framework", URL: "https://veriscommunity.net/", Section: "V: Third Party"}, {Source: "DBIR", URL: "https://www.verizon.com/business/resources/reports/dbir/", Section: "Supply Chain"}},
			ImplementationGuidance: "Track third-party originated incidents. Map supply chain attack paths. Review vendor security assessments. Assess downstream impact. Update vendor risk scores.",
			AssessmentMethods:      []string{"Third-Party Incident Analysis", "Supply Chain Risk Mapping", "Vendor Risk Assessment Update"},
		},
	}
}
