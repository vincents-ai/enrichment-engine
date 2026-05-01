package disa_stigs

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/vincents-ai/enrichment-engine/pkg/grc"
	"github.com/vincents-ai/enrichment-engine/pkg/storage"
)

const FrameworkID = "DISA_STIGS_V2R1"
const CatalogURL = ""

type Provider struct {
	store  storage.Backend
	logger *slog.Logger
}

func New(store storage.Backend, logger *slog.Logger) *Provider {
	return &Provider{store: store, logger: logger}
}

func (p *Provider) Name() string { return "disa_stigs" }

func (p *Provider) Run(ctx context.Context) (int, error) {
	return p.writeEmbeddedControls(ctx)
}

func (p *Provider) writeEmbeddedControls(ctx context.Context) (int, error) {
	p.logger.Info("using embedded DISA STIGs controls")
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
	p.logger.Info("wrote embedded DISA STIGs controls to storage", "count", count)
	return count, nil
}

var disaCWEMap = map[string][]string{
	"WS-2022.1.2":  {"CWE-521", "CWE-265"},
	"WS-2022.1.3":  {"CWE-521"},
	"WS-2022.2.1":  {"CWE-307", "CWE-287"},
	"WS-2022.2.2":  {"CWE-307", "CWE-287"},
	"WS-2022.3.1":  {"CWE-778"},
	"WS-2022.3.2":  {"CWE-778"},
	"WS-2022.3.3":  {"CWE-778"},
	"WS-2022.4.1":  {"CWE-287", "CWE-319"},
	"WS-2022.5.1":  {"CWE-284", "CWE-668"},
	"WS-2022.6.1":  {"CWE-345", "CWE-319"},
	"WS-2022.7.1":  {"CWE-16", "CWE-1188", "CWE-78", "CWE-119", "CWE-502"},
	"RHEL-8.1.1":   {"CWE-732", "CWE-284"},
	"RHEL-8.1.2":   {"CWE-287", "CWE-798"},
	"RHEL-8.1.3":   {"CWE-319", "CWE-287"},
	"RHEL-8.2.1":   {"CWE-521", "CWE-265"},
	"RHEL-8.2.2":   {"CWE-521"},
	"RHEL-8.2.3":   {"CWE-307", "CWE-287"},
	"RHEL-8.3.1":   {"CWE-778"},
	"RHEL-8.3.2":   {"CWE-778"},
	"RHEL-8.4.1":   {"CWE-284", "CWE-668"},
	"RHEL-8.5.1":   {"CWE-693"},
	"RHEL-8.6.1":   {"CWE-16", "CWE-1188", "CWE-78", "CWE-119", "CWE-502"},
	"APACHE-2.1.1": {"CWE-200"},
	"APACHE-2.1.2": {"CWE-200"},
	"APACHE-2.2.1": {"CWE-319", "CWE-326"},
	"APACHE-2.3.1": {"CWE-200", "CWE-538", "CWE-22"},
	"APACHE-2.4.1": {"CWE-778"},
	"NGINX-1.1":    {"CWE-200"},
	"NGINX-1.2":    {"CWE-319", "CWE-326"},
	"ORACLE-1.1":   {"CWE-521", "CWE-287"},
	"ORACLE-1.2":   {"CWE-798", "CWE-254"},
	"ORACLE-1.3":   {"CWE-778"},
}

func disaCWEs(controlID string) []string {
	return disaCWEMap[controlID]
}

func embeddedControls() []grc.Control {
	type c struct{ id, title, desc, family, severity string }
	items := []struct {
		family string
		items  []c
	}{
		{"Windows Server", []c{
			{"WS-2022.1.1", "Windows Password Policy - Maximum Age", "Ensure the maximum password age is configured to 60 days or less. This prevents passwords from being used indefinitely and reduces the window of opportunity for credential compromise.", "Windows Server", "medium"},
			{"WS-2022.1.2", "Windows Password Policy - Minimum Length", "Ensure the minimum password length is set to 14 characters or greater. Shorter passwords are more susceptible to brute force and dictionary attacks.", "Windows Server", "high"},
			{"WS-2022.1.3", "Windows Password Policy - Complexity", "Ensure password complexity is enabled requiring uppercase, lowercase, digits, and special characters to increase password entropy.", "Windows Server", "medium"},
			{"WS-2022.2.1", "Windows Account Lockout Policy", "Ensure the account lockout threshold is set to a value between 3 and 5 failed attempts. This mitigates brute force attacks against user accounts.", "Windows Server", "high"},
			{"WS-2022.2.2", "Windows Account Lockout Duration", "Ensure the account lockout duration is set to 15 minutes or greater to prevent sustained brute force attacks.", "Windows Server", "medium"},
			{"WS-2022.3.1", "Windows Audit Policy - Logon Events", "Ensure audit policy is configured to log successful and failed logon events for accountability and intrusion detection.", "Windows Server", "high"},
			{"WS-2022.3.2", "Windows Audit Policy - Object Access", "Ensure audit policy is configured to log object access including file system and registry access for sensitive objects.", "Windows Server", "medium"},
			{"WS-2022.3.3", "Windows Audit Policy - Policy Change", "Ensure audit policy is configured to log policy changes to detect unauthorized modifications to system security settings.", "Windows Server", "high"},
			{"WS-2022.4.1", "Windows Remote Desktop Security", "Ensure Remote Desktop Services require Network Level Authentication (NLA) to prevent man-in-the-middle attacks during RDP connections.", "Windows Server", "high"},
			{"WS-2022.5.1", "Windows Firewall Configuration", "Ensure Windows Firewall is enabled on all network profiles with default deny inbound rules to block unauthorized network access.", "Windows Server", "high"},
			{"WS-2022.6.1", "Windows SMB Signing", "Ensure SMB server requires message signing to prevent man-in-the-middle attacks on SMB sessions.", "Windows Server", "high"},
			{"WS-2022.7.1", "Windows Services - Unnecessary Services", "Ensure unnecessary Windows services are disabled to reduce attack surface including Telnet, FTP, and PowerShell v2.", "Windows Server", "medium"},
		}},
		{"Red Hat Enterprise Linux", []c{
			{"RHEL-8.1.1", "RHEL File Permissions - SSH Config", "Ensure SSH server configuration file permissions are set to 600 owned by root to prevent unauthorized modification of SSH settings.", "Red Hat Enterprise Linux", "high"},
			{"RHEL-8.1.2", "RHEL SSH Root Login", "Ensure SSH daemon does not permit root login with password (PermitRootLogin set to prohibit-password or no).", "Red Hat Enterprise Linux", "high"},
			{"RHEL-8.1.3", "RHEL SSH Protocol Version", "Ensure SSH protocol version 2 is enforced and protocol version 1 is disabled due to known vulnerabilities.", "Red Hat Enterprise Linux", "high"},
			{"RHEL-8.2.1", "RHEL Password Policy - Minimum Length", "Ensure login.defs sets minimum password length (PASS_MIN_LEN) to 14 characters or pam_pwquality enforces it.", "Red Hat Enterprise Linux", "high"},
			{"RHEL-8.2.2", "RHEL Password Policy - Complexity", "Ensure pam_pwquality module enforces password complexity including retry, minlen, dcredit, ucredit, lcredit, and ocredit.", "Red Hat Enterprise Linux", "medium"},
			{"RHEL-8.2.3", "RHEL Password Policy - Lockout", "Ensure pam_faillock is configured to lock accounts after 5 failed authentication attempts.", "Red Hat Enterprise Linux", "high"},
			{"RHEL-8.3.1", "RHEL Audit Configuration", "Ensure auditd is installed, enabled, and configured to collect system call, file access, and user action audit events.", "Red Hat Enterprise Linux", "high"},
			{"RHEL-8.3.2", "RHEL Audit Rules - System Calls", "Ensure audit rules are configured for key system calls including execve, openat, and mount to detect privilege escalation and file access.", "Red Hat Enterprise Linux", "medium"},
			{"RHEL-8.4.1", "RHEL Firewall - firewalld", "Ensure firewalld is active with default zone set to drop or block incoming traffic and only required services are enabled.", "Red Hat Enterprise Linux", "high"},
			{"RHEL-8.4.2", "RHEL IPv6 Configuration", "Ensure IPv6 is either disabled or properly configured with firewall rules if not required for operational needs.", "Red Hat Enterprise Linux", "medium"},
			{"RHEL-8.5.1", "RHEL Kernel Parameters - ASLR", "Ensure kernel.randomize_va_space is set to 2 to enable full Address Space Layout Randomization.", "Red Hat Enterprise Linux", "high"},
			{"RHEL-8.5.2", "RHEL Kernel Parameters - ExecShield", "Ensure kernel.exec-shield is enabled and kernel.kexec_load is restricted to prevent kernel-level attacks.", "Red Hat Enterprise Linux", "medium"},
			{"RHEL-8.6.1", "RHEL Unnecessary Services", "Ensure unnecessary network services including telnet, rsh, rlogin, and tftp are disabled or removed.", "Red Hat Enterprise Linux", "high"},
		}},
		{"Application", []c{
			{"APACHE-2.1.1", "Apache Server Tokens", "Ensure ServerTokens is set to Prod to minimize information disclosure in HTTP response headers.", "Application", "medium"},
			{"APACHE-2.1.2", "Apache Server Signature", "Ensure ServerSignature is set to Off to prevent Apache version disclosure on error pages.", "Application", "medium"},
			{"APACHE-2.2.1", "Apache TLS Configuration", "Ensure Apache is configured with TLS 1.2 minimum, strong cipher suites, and HSTS header to protect data in transit.", "Application", "high"},
			{"APACHE-2.3.1", "Apache Directory Listing", "Ensure directory listing is disabled (Options -Indexes) to prevent information disclosure of directory contents.", "Application", "medium"},
			{"APACHE-2.4.1", "Apache Access Logging", "Ensure Apache access logging is enabled with combined log format including referer and user agent for forensic analysis.", "Application", "low"},
			{"NGINX-1.1", "Nginx Server Tokens", "Ensure server_tokens directive is set to off to prevent Nginx version disclosure in response headers.", "Application", "medium"},
			{"NGINX-1.2", "Nginx TLS Configuration", "Ensure Nginx SSL protocols are set to TLSv1.2 and TLSv1.3 only with strong cipher suites and HSTS.", "Application", "high"},
			{"ORACLE-1.1", "Oracle Listener Password", "Ensure Oracle TNS listener is configured with a strong password and restricted to authorized access.", "Application", "high"},
			{"ORACLE-1.2", "Oracle Default Accounts", "Ensure Oracle default accounts are locked, expired, or removed to prevent unauthorized database access.", "Application", "high"},
			{"ORACLE-1.3", "Oracle Audit Trail", "Ensure Oracle audit trail is enabled for privileged actions including DDL, DML by DBAs, and login failures.", "Application", "medium"},
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
				Level:       c.severity,
				RelatedCWEs: disaCWEs(c.id),
				References:  []grc.Reference{{Source: "DISA STIGs", Section: c.id}},
			})
		}
	}
	return controls
}
