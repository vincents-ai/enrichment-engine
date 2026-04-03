package scap_xccdf

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/shift/enrichment-engine/pkg/grc"
	"github.com/shift/enrichment-engine/pkg/storage"
)

const FrameworkID = "SCAP_XCCDF_1_3"
const CatalogURL = ""

type Provider struct {
	store  storage.Backend
	logger *slog.Logger
}

func New(store storage.Backend, logger *slog.Logger) *Provider {
	return &Provider{store: store, logger: logger}
}

func (p *Provider) Name() string { return "scap_xccdf" }

func (p *Provider) Run(ctx context.Context) (int, error) {
	return p.writeEmbeddedControls(ctx)
}

func (p *Provider) writeEmbeddedControls(ctx context.Context) (int, error) {
	p.logger.Info("using embedded SCAP/XCCDF controls")
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
	p.logger.Info("wrote embedded SCAP/XCCDF controls to storage", "count", count)
	return count, nil
}

var scapCWEMap = map[string][]string{
	"SCAP-RHEL-8-1.1":  {"CWE-778"},
	"SCAP-RHEL-8-1.2":  {"CWE-284", "CWE-250"},
	"SCAP-RHEL-8-1.3":  {"CWE-693"},
	"SCAP-RHEL-8-1.4":  {"CWE-693"},
	"SCAP-RHEL-8-1.5":  {"CWE-250", "CWE-269", "CWE-22"},
	"SCAP-RHEL-8-2.1":  {"CWE-287", "CWE-250"},
	"SCAP-RHEL-8-2.2":  {"CWE-287", "CWE-521"},
	"SCAP-RHEL-8-2.3":  {"CWE-250", "CWE-778"},
	"SCAP-RHEL-8-2.4":  {"CWE-319"},
	"SCAP-RHEL-8-2.5":  {"CWE-287", "CWE-798"},
	"SCAP-RHEL-8-2.6":  {"CWE-521"},
	"SCAP-RHEL-8-2.7":  {"CWE-307", "CWE-287"},
	"SCAP-RHEL-8-3.1":  {"CWE-284", "CWE-668"},
	"SCAP-RHEL-8-3.5":  {"CWE-345"},
	"SCAP-RHEL-8-4.1":  {"CWE-778"},
	"SCAP-RHEL-8-4.2":  {"CWE-778"},
	"SCAP-RHEL-8-4.3":  {"CWE-778"},
	"SCAP-RHEL-8-4.4":  {"CWE-778"},
	"SCAP-RHEL-8-4.5":  {"CWE-778", "CWE-319"},
	"SCAP-RHEL-8-5.1":  {"CWE-16", "CWE-78", "CWE-319"},
	"SCAP-RHEL-8-5.2":  {"CWE-16", "CWE-78", "CWE-319"},
	"SCAP-RHEL-8-5.3":  {"CWE-16", "CWE-284"},
	"SCAP-RHEL-8-6.1":  {"CWE-345", "CWE-1104"},
	"SCAP-RHEL-8-6.2":  {"CWE-1104"},
	"SCAP-RHEL-8-6.3":  {"CWE-345", "CWE-353"},
	"SCAP-RHEL-8-6.4":  {"CWE-345", "CWE-353"},
	"SCAP-WS-2022-1.1": {"CWE-284", "CWE-668"},
	"SCAP-WS-2022-1.2": {"CWE-287", "CWE-319"},
	"SCAP-WS-2022-1.3": {"CWE-778"},
	"SCAP-WS-2022-1.4": {"CWE-778"},
}

func scapCWEs(controlID string) []string {
	return scapCWEMap[controlID]
}

func embeddedControls() []grc.Control {
	type c struct{ id, title, desc, family string }
	items := []struct {
		family string
		items  []c
	}{
		{"System Settings", []c{
			{"SCAP-RHEL-8-1.1", "Time Synchronization - chrony", "Ensure chrony is configured to synchronize system time with authoritative NTP servers and uses restricted access controls.", "System Settings"},
			{"SCAP-RHEL-8-1.2", "SELinux Enforcement", "Ensure SELinux is enabled and enforcing to provide mandatory access control and limit the impact of compromised services.", "System Settings"},
			{"SCAP-RHEL-8-1.3", "Kernel Parameters - ASLR", "Ensure kernel parameter kernel.randomize_va_space is set to 2 to enable full Address Space Layout Randomization.", "System Settings"},
			{"SCAP-RHEL-8-1.4", "Kernel Parameters - Exec Shield", "Ensure kernel parameter kernel.exec-shield is enabled to prevent code execution in data memory areas.", "System Settings"},
			{"SCAP-RHEL-8-1.5", "File System - Noexec on /tmp", "Ensure /tmp is mounted with noexec option to prevent execution of binaries from temporary directories.", "System Settings"},
		}},
		{"Access Control", []c{
			{"SCAP-RHEL-8-2.1", "User and Group Management - UID 0", "Ensure only root has UID 0 and no unauthorized accounts have superuser privileges.", "Access Control"},
			{"SCAP-RHEL-8-2.2", "User and Group Management - Empty Passwords", "Ensure no accounts have empty passwords by configuring PAM to reject null passwords.", "Access Control"},
			{"SCAP-RHEL-8-2.3", "Sudo Configuration", "Ensure sudo is configured with use_pty, logfile, and timestamp_timeout to provide audit trail and session control.", "Access Control"},
			{"SCAP-RHEL-8-2.4", "SSH Hardening - Protocol", "Ensure SSH is configured to use Protocol 2 only and disable weak ciphers, MACs, and key exchange algorithms.", "Access Control"},
			{"SCAP-RHEL-8-2.5", "SSH Hardening - Root Login", "Ensure SSH root login is disabled by setting PermitRootLogin to prohibit-password or no.", "Access Control"},
			{"SCAP-RHEL-8-2.6", "PAM - Password Quality", "Ensure PAM pwquality module is configured with minlen=14, dcredit=-1, ucredit=-1, lcredit=-1, ocredit=-1.", "Access Control"},
			{"SCAP-RHEL-8-2.7", "PAM - Account Lockout", "Ensure PAM faillock is configured with deny=5, unlock_time=900, and fail_interval=900.", "Access Control"},
		}},
		{"Network", []c{
			{"SCAP-RHEL-8-3.1", "Firewall - Default Deny", "Ensure firewalld default zone is set to drop incoming traffic and only explicitly required services are allowed.", "Network"},
			{"SCAP-RHEL-8-3.2", "Network Parameters - IP Forwarding", "Ensure IPv4 and IPv6 packet forwarding is disabled unless the system functions as a router.", "Network"},
			{"SCAP-RHEL-8-3.3", "Network Parameters - Source Routing", "Ensure source routed packets are rejected by setting net.ipv4.conf.all.accept_source_route to 0.", "Network"},
			{"SCAP-RHEL-8-3.4", "Network Parameters - ICMP Redirects", "Ensure ICMP redirects are not accepted by setting net.ipv4.conf.all.accept_redirects to 0.", "Network"},
			{"SCAP-RHEL-8-3.5", "Network Parameters - Reverse Path Filtering", "Ensure reverse path filtering is enabled to prevent IP spoofing via asymmetric routing.", "Network"},
		}},
		{"Logging", []c{
			{"SCAP-RHEL-8-4.1", "Audit Daemon - Installation", "Ensure auditd package is installed and the auditd service is enabled to collect security event logs.", "Logging"},
			{"SCAP-RHEL-8-4.2", "Audit Rules - System Calls", "Ensure audit rules are configured for critical system calls including execve, openat, mount, and umount2.", "Logging"},
			{"SCAP-RHEL-8-4.3", "Audit Rules - File Access", "Ensure audit rules monitor access to critical files including /etc/passwd, /etc/shadow, and /etc/sudoers.", "Logging"},
			{"SCAP-RHEL-8-4.4", "Audit Log Retention", "Ensure audit log retention policy is configured with maximum_log_file_action set to rotate or keep_logs.", "Logging"},
			{"SCAP-RHEL-8-4.5", "Rsyslog Configuration", "Ensure rsyslog is configured to send logs to a remote log server with TLS encryption for tamper-resistant storage.", "Logging"},
		}},
		{"Services", []c{
			{"SCAP-RHEL-8-5.1", "Disable Unused Services - telnet", "Ensure telnet server is not installed or enabled to prevent unencrypted remote shell access.", "Services"},
			{"SCAP-RHEL-8-5.2", "Disable Unused Services - rsh", "Ensure rsh, rlogin, and rexec services are disabled to prevent unencrypted remote command execution.", "Services"},
			{"SCAP-RHEL-8-5.3", "Disable Unused Services - tftp", "Ensure TFTP server daemon is disabled to prevent unauthorized file transfer without authentication.", "Services"},
			{"SCAP-RHEL-8-5.4", "Service Hardening - systemd", "Ensure systemd services have security hardening options including NoNewPrivileges, ProtectSystem, and PrivateTmp.", "Services"},
		}},
		{"Software", []c{
			{"SCAP-RHEL-8-6.1", "Package Management - GPG Verification", "Ensure package manager is configured to verify GPG signatures on all installed packages to prevent supply chain attacks.", "Software"},
			{"SCAP-RHEL-8-6.2", "Package Updates - Security Patches", "Ensure the system is configured to automatically apply security updates or has a process for timely manual patching.", "Software"},
			{"SCAP-RHEL-8-6.3", "File Integrity - AIDE", "Ensure AIDE (Advanced Intrusion Detection Environment) is installed and configured to detect unauthorized file modifications.", "Software"},
			{"SCAP-RHEL-8-6.4", "File Integrity - AIDE Cron", "Ensure AIDE is scheduled to run periodically via cron or systemd timer to continuously verify file integrity.", "Software"},
		}},
		{"Windows System", []c{
			{"SCAP-WS-2022-1.1", "Windows Firewall - Profile Configuration", "Ensure Windows Firewall is enabled on Domain, Private, and Public profiles with inbound connections blocked by default.", "Windows System"},
			{"SCAP-WS-2022-1.2", "Windows Remote Desktop - NLA", "Ensure Network Level Authentication is required for Remote Desktop connections to prevent MITM attacks.", "Windows System"},
			{"SCAP-WS-2022-1.3", "Windows PowerShell Logging", "Ensure PowerShell script block logging and module logging are enabled to capture PowerShell-based attacks.", "Windows System"},
			{"SCAP-WS-2022-1.4", "Windows Event Log - Security", "Ensure Security event log is configured with sufficient size and retention to preserve forensic evidence.", "Windows System"},
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
				Level:       "medium",
				RelatedCWEs: scapCWEs(c.id),
				References:  []grc.Reference{{Source: "SCAP/XCCDF 1.3", Section: c.id}},
			})
		}
	}
	return controls
}
