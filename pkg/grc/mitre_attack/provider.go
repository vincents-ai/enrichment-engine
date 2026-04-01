package mitre_attack

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/shift/enrichment-engine/pkg/grc"
	"github.com/shift/enrichment-engine/pkg/storage"
)

const FrameworkID = "MITRE_ATTACK_V14"
const CatalogURL = ""

type Provider struct {
	store  storage.Backend
	logger *slog.Logger
}

func New(store storage.Backend, logger *slog.Logger) *Provider {
	return &Provider{store: store, logger: logger}
}

func (p *Provider) Name() string { return "mitre_attack" }

func (p *Provider) Run(ctx context.Context) (int, error) {
	return p.writeEmbeddedControls(ctx)
}

func (p *Provider) writeEmbeddedControls(ctx context.Context) (int, error) {
	p.logger.Info("using embedded MITRE ATT&CK v14 defensive controls")
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
	p.logger.Info("wrote embedded MITRE ATT&CK controls to storage", "count", count)
	return count, nil
}

func embeddedControls() []grc.Control {
	type c struct{ id, title, desc, family, tactic string }
	items := []struct {
		family string
		items  []c
	}{
		{"Initial Access", []c{
			{"DC-TA0001-T1566", "Phishing Detection and Prevention", "Implement email security controls including SPF, DKIM, DMARC, and anti-phishing filters to detect and block phishing attempts (T1566).", "Initial Access", "TA0001"},
			{"DC-TA0001-T1190", "Public-Facing Application Exploitation Defense", "Deploy WAF, input validation, and regular vulnerability scanning to prevent exploitation of public-facing applications (T1190).", "Initial Access", "TA0001"},
			{"DC-TA0001-T1078", "Valid Accounts Monitoring", "Implement privileged access management and monitor for suspicious use of valid accounts for initial access (T1078).", "Initial Access", "TA0001"},
			{"DC-TA0001-T1133", "External Remote Services Control", "Restrict and monitor external remote services including VPN and RDP gateways with MFA enforcement (T1133).", "Initial Access", "TA0001"},
			{"DC-TA0001-T1195", "Supply Chain Compromise Detection", "Verify software supply chain integrity through SBOM analysis and signed artifact verification (T1195).", "Initial Access", "TA0001"},
		}},
		{"Execution", []c{
			{"DC-TA0002-T1059", "Command Interpreter Monitoring", "Monitor command-line interpreter usage including PowerShell, cmd.exe, and shell for suspicious execution patterns (T1059).", "Execution", "TA0002"},
			{"DC-TA0002-T1053", "Scheduled Task/Job Monitoring", "Monitor creation and modification of scheduled tasks and cron jobs for unauthorized persistence (T1053).", "Execution", "TA0002"},
			{"DC-TA0002-T1204", "User Execution Controls", "Implement application whitelisting and user awareness training to reduce user-initiated execution (T1204).", "Execution", "TA0002"},
			{"DC-TA0002-T1059.001", "PowerShell Restriction", "Constrain PowerShell with constrained language mode, script block logging, and execution policy enforcement (T1059.001).", "Execution", "TA0002"},
			{"DC-TA0002-T1569", "System Services Execution Monitoring", "Monitor system service execution and limit service configuration to authorized administrators (T1569).", "Execution", "TA0002"},
		}},
		{"Persistence", []c{
			{"DC-TA0003-T1053.005", "Scheduled Task Persistence Detection", "Detect and alert on creation of scheduled tasks with suspicious commands or atypical schedules (T1053.005).", "Persistence", "TA0003"},
			{"DC-TA0003-T1543", "System Process Creation Monitoring", "Monitor for creation or modification of system processes, services, and daemons used for persistence (T1543).", "Persistence", "TA0003"},
			{"DC-TA0003-T1547", "Boot Autostart Monitoring", "Monitor boot or logon autostart execution registry keys, scripts, and configuration files (T1547).", "Persistence", "TA0003"},
			{"DC-TA0003-T1136", "Account Creation Monitoring", "Monitor for creation of new accounts especially with administrative privileges (T1136).", "Persistence", "TA0003"},
			{"DC-TA0003-T1078.002", "Domain Account Persistence", "Monitor domain account creation and privilege escalation for persistence via valid domain accounts (T1078.002).", "Persistence", "TA0003"},
		}},
		{"Privilege Escalation", []c{
			{"DC-TA0004-T1068", "Exploitation for Privilege Escalation Detection", "Apply security patches promptly and monitor for exploitation attempts targeting local privilege escalation vulnerabilities (T1068).", "Privilege Escalation", "TA0004"},
			{"DC-TA0004-T1548", "Abuse Elevation Control Mitigation", "Implement UAC restrictions, token manipulation detection, and sudo configuration auditing (T1548).", "Privilege Escalation", "TA0004"},
			{"DC-TA0004-T1548.001", "Setuid and Setgid Monitoring", "Monitor for creation or modification of setuid/setgid binaries that could be abused for privilege escalation (T1548.001).", "Privilege Escalation", "TA0004"},
			{"DC-TA0004-T1574", "Hijack Execution Flow Detection", "Monitor DLL search order hijacking, DLL side-loading, and dynamic linker hijacking (T1574).", "Privilege Escalation", "TA0004"},
		}},
		{"Defense Evasion", []c{
			{"DC-TA0005-T1027", "Obfuscated Files Detection", "Deploy file integrity monitoring and analyze files for obfuscation indicators including packed executables (T1027).", "Defense Evasion", "TA0005"},
			{"DC-TA0005-T1055", "Process Injection Detection", "Monitor for process injection techniques including DLL injection, process hollowing, and APC injection (T1055).", "Defense Evasion", "TA0005"},
			{"DC-TA0005-T1070", "Indicator Removal Monitoring", "Implement centralized logging and monitor for indicator removal including log clearing and file deletion (T1070).", "Defense Evasion", "TA0005"},
			{"DC-TA0005-T1562", "Impair Defenses Detection", "Monitor for attempts to disable security tools, antivirus, and endpoint detection and response (T1562).", "Defense Evasion", "TA0005"},
			{"DC-TA0005-T1036", "Masquerading Detection", "Monitor for file name and location masquerading including renaming tools to legitimate names (T1036).", "Defense Evasion", "TA0005"},
		}},
		{"Credential Access", []c{
			{"DC-TA0006-T1110", "Brute Force Detection", "Implement account lockout policies and detect brute force attempts against authentication endpoints (T1110).", "Credential Access", "TA0006"},
			{"DC-TA0006-T1552", "Unsecured Credentials Detection", "Discover and secure unsecured credentials in files, registries, environment variables, and source code (T1552).", "Credential Access", "TA0006"},
			{"DC-TA0006-T1558", "Kerberoasting Detection", "Monitor for Kerberoasting attacks including unusual service ticket requests and encryption type anomalies (T1558).", "Credential Access", "TA0006"},
			{"DC-TA0006-T1003", "OS Credential Dumping Detection", "Monitor for credential dumping tools and access to credential stores like LSASS, SAM database, and keychain (T1003).", "Credential Access", "TA0006"},
			{"DC-TA0006-T1056", "Input Capture Detection", "Monitor for keylogging, clipboard capture, and other input interception mechanisms (T1056).", "Credential Access", "TA0006"},
		}},
		{"Discovery", []c{
			{"DC-TA0007-T1046", "Network Service Discovery Detection", "Monitor for network scanning activity using port scans, service enumeration, and ARP requests (T1046).", "Discovery", "TA0007"},
			{"DC-TA0007-T1082", "System Information Discovery Monitoring", "Monitor for system information gathering commands and API calls for OS, hardware, and software enumeration (T1082).", "Discovery", "TA0007"},
			{"DC-TA0007-T1083", "File Discovery Monitoring", "Monitor for file and directory discovery including recursive file listing in sensitive locations (T1083).", "Discovery", "TA0007"},
			{"DC-TA0007-T1087", "Account Discovery Detection", "Monitor for account and group enumeration commands including net user, dsquery, and LDAP queries (T1087).", "Discovery", "TA0007"},
			{"DC-TA0007-T1018", "Remote System Discovery Monitoring", "Monitor for remote system discovery using ping sweeps, SMB enumeration, and DNS queries (T1018).", "Discovery", "TA0007"},
		}},
		{"Lateral Movement", []c{
			{"DC-TA0008-T1021", "Remote Services Monitoring", "Monitor and restrict remote service usage including RDP, SSH, SMB, and WinRM (T1021).", "Lateral Movement", "TA0008"},
			{"DC-TA0008-T1534", "Certified Executable Detection", "Monitor for use of certified executables for lateral movement including signed binary abuse (T1534).", "Lateral Movement", "TA0008"},
			{"DC-TA0008-T1570", "Lateral Tool Transfer Detection", "Monitor for lateral tool transfer using file shares, remote copy, and encoded commands (T1570).", "Lateral Movement", "TA0008"},
			{"DC-TA0008-T1550", "Alternate Authentication Material", "Monitor for use of alternate authentication materials including pass-the-hash, pass-the-ticket, and golden tickets (T1550).", "Lateral Movement", "TA0008"},
		}},
		{"Collection", []c{
			{"DC-TA0009-T1005", "Data from Local System Detection", "Monitor for data collection from local systems including file staging, compression, and encryption (T1005).", "Collection", "TA0009"},
			{"DC-TA0009-T1039", "Network Share Data Collection", "Monitor for unusual access to network shares for data collection purposes (T1039).", "Collection", "TA0009"},
			{"DC-TA0009-T1114", "Email Collection Detection", "Monitor for email collection from local mail clients and webmail for data staging (T1114).", "Collection", "TA0009"},
		}},
		{"Exfiltration", []c{
			{"DC-TA0010-T1041", "C2 Channel Exfiltration Detection", "Monitor network traffic for data exfiltration over command and control channels including encoded data (T1041).", "Exfiltration", "TA0010"},
			{"DC-TA0010-T1048", "Alternative Protocol Exfiltration", "Monitor for data exfiltration over alternative protocols including DNS, ICMP, and HTTP (T1048).", "Exfiltration", "TA0010"},
			{"DC-TA0010-T1567", "Web Service Exfiltration Detection", "Monitor for data exfiltration via web services including cloud storage and social media (T1567).", "Exfiltration", "TA0010"},
		}},
		{"Command and Control", []c{
			{"DC-TA0011-T1071", "Application Layer Protocol Detection", "Monitor for command and control communication over application layer protocols (T1071).", "Command and Control", "TA0011"},
			{"DC-TA0011-T1573", "Encrypted Channel Detection", "Monitor for use of encrypted channels for C2 communication including SSL/TLS with anomalous certificates (T1573).", "Command and Control", "TA0011"},
			{"DC-TA0011-T1105", "Remote File Copy Detection", "Monitor for remote file download including from external infrastructure for tool deployment (T1105).", "Command and Control", "TA0011"},
			{"DC-TA0011-T1095", "Non-Application Layer Protocol", "Monitor for C2 communication over non-application layer protocols (T1095).", "Command and Control", "TA0011"},
		}},
		{"Impact", []c{
			{"DC-TA0040-T1486", "Ransomware Detection", "Implement file integrity monitoring and behavioral detection for ransomware indicators including mass file encryption (T1486).", "Impact", "TA0040"},
			{"DC-TA0040-T1489", "Service Stop Detection", "Monitor for service termination targeting security controls and critical business services (T1489).", "Impact", "TA0040"},
			{"DC-TA0040-T1490", "Inhibit System Recovery Detection", "Monitor for deletion of backups, shadow copies, and recovery partitions (T1490).", "Impact", "TA0040"},
			{"DC-TA0040-T1498", "Network Denial of Service Detection", "Implement DDoS mitigation and monitor for network flooding attacks (T1498).", "Impact", "TA0040"},
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
				Level:       "standard",
				References:  []grc.Reference{{Source: "MITRE ATT&CK v14 Enterprise", Section: c.tactic}},
			})
		}
	}
	return controls
}
