package cis_benchmarks

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/shift/enrichment-engine/pkg/grc"
	"github.com/shift/enrichment-engine/pkg/storage"
)

const FrameworkID = "CIS_BENCHMARKS_V2"
const CatalogURL = ""

type Provider struct {
	store  storage.Backend
	logger *slog.Logger
}

func New(store storage.Backend, logger *slog.Logger) *Provider {
	return &Provider{store: store, logger: logger}
}

func (p *Provider) Name() string { return "cis_benchmarks" }

func (p *Provider) Run(ctx context.Context) (int, error) {
	return p.writeEmbeddedControls(ctx)
}

func (p *Provider) writeEmbeddedControls(ctx context.Context) (int, error) {
	p.logger.Info("using embedded CIS Benchmarks controls")
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
	p.logger.Info("wrote embedded CIS Benchmarks controls to storage", "count", count)
	return count, nil
}

var cisBenchCWEMap = map[string][]string{
	"OS-1.2": {"CWE-250", "CWE-269", "CWE-22"},
	"OS-1.3": {"CWE-250", "CWE-269"},
	"OS-2.1": {"CWE-319"},
	"OS-2.2": {"CWE-778"},
	"OS-2.3": {"CWE-287", "CWE-798"},
	"OS-2.4": {"CWE-287", "CWE-521"},
	"OS-3.1": {"CWE-521", "CWE-265"},
	"OS-3.2": {"CWE-521"},
	"OS-3.3": {"CWE-307", "CWE-287"},
	"OS-4.1": {"CWE-250", "CWE-269"},
	"OS-4.2": {"CWE-693", "CWE-78", "CWE-119"},
	"OS-5.1": {"CWE-778", "CWE-311"},
	"OS-5.2": {"CWE-778"},
	"OS-5.3": {"CWE-778", "CWE-250"},
	"CT-1.1": {"CWE-284", "CWE-668", "CWE-319"},
	"CT-1.2": {"CWE-778"},
	"CT-2.1": {"CWE-250", "CWE-78", "CWE-269", "CWE-284"},
	"CT-2.2": {"CWE-1104", "CWE-345"},
	"CT-2.3": {"CWE-284", "CWE-668"},
	"CT-3.1": {"CWE-732", "CWE-284"},
	"CT-3.2": {"CWE-250", "CWE-269"},
	"KS-1.1": {"CWE-287", "CWE-306"},
	"KS-1.2": {"CWE-778"},
	"KS-2.1": {"CWE-311", "CWE-312", "CWE-319"},
	"KS-2.2": {"CWE-494", "CWE-311"},
	"KS-3.1": {"CWE-319", "CWE-287"},
	"KS-3.2": {"CWE-319"},
	"KS-4.1": {"CWE-287", "CWE-250"},
	"KS-4.2": {"CWE-250", "CWE-269", "CWE-284"},
	"KS-5.1": {"CWE-284", "CWE-668"},
	"KS-5.2": {"CWE-311", "CWE-284", "CWE-285"},
	"DB-1.1": {"CWE-287", "CWE-521"},
	"DB-1.2": {"CWE-284", "CWE-319"},
	"DB-1.3": {"CWE-778"},
	"DB-2.1": {"CWE-798", "CWE-287"},
	"DB-2.2": {"CWE-284", "CWE-319"},
	"DB-3.1": {"CWE-287", "CWE-306"},
	"DB-3.2": {"CWE-284", "CWE-319"},
}

func cisBenchCWEs(controlID string) []string {
	return cisBenchCWEMap[controlID]
}

func embeddedControls() []grc.Control {
	type c struct{ id, title, desc, family string }
	items := []struct {
		family string
		items  []c
	}{
		{"Operating System", []c{
			{"OS-1.1", "Filesystem Configuration", "Ensure mounting of cramfs, freevxfs, jffs2, hfs, hfsplus, squashfs, udf, and FAT filesystems is disabled to prevent loading of unnecessary kernel modules.", "Operating System"},
			{"OS-1.2", "Temporary Directory Configuration", "Ensure noexec, nosuid, and nodev options are set on /tmp to prevent execution of binaries and privilege escalation from temporary directories.", "Operating System"},
			{"OS-1.3", "Var Mount Options", "Ensure noexec, nosuid, and nodev options are set on /var to restrict execution and privilege escalation from variable data directories.", "Operating System"},
			{"OS-2.1", "SSH Protocol Configuration", "Ensure SSH Protocol is set to 2 to disable the legacy SSHv1 protocol which has known security vulnerabilities.", "Operating System"},
			{"OS-2.2", "SSH LogLevel", "Ensure SSH LogLevel is set to INFO or VERBOSE to enable logging of authentication attempts and user activities.", "Operating System"},
			{"OS-2.3", "SSH Root Login", "Ensure SSH root login is disabled (PermitRootLogin no) to prevent direct root access via SSH.", "Operating System"},
			{"OS-2.4", "SSH Empty Passwords", "Ensure SSH does not permit empty passwords (PermitEmptyPasswords no) to prevent unauthorized access.", "Operating System"},
			{"OS-3.1", "Password Minimum Length", "Ensure minimum password length is 14 characters or more to resist brute force attacks.", "Operating System"},
			{"OS-3.2", "Password Complexity", "Ensure password complexity requirements include uppercase, lowercase, digits, and special characters.", "Operating System"},
			{"OS-3.3", "Password Lockout Policy", "Ensure account lockout is configured after 5 failed attempts to prevent brute force attacks.", "Operating System"},
			{"OS-4.1", "Bootloader Password", "Ensure bootloader password is set to prevent unauthorized modification of boot parameters and kernel options.", "Operating System"},
			{"OS-4.2", "Kernel Parameters", "Ensure kernel parameters including exec-shield, ASLR, and reverse path filtering are configured for security hardening.", "Operating System"},
			{"OS-5.1", "Audit Log Storage", "Ensure audit logs are stored with appropriate permissions and retention to prevent tampering and ensure availability.", "Operating System"},
			{"OS-5.2", "Audit Daemon Configuration", "Ensure auditd is configured to collect sufficient audit events including system calls, file access, and user actions.", "Operating System"},
			{"OS-5.3", "Audit Rules for Privileged Commands", "Ensure audit rules are in place for all privileged commands including sudo, su, and usermod.", "Operating System"},
		}},
		{"Container", []c{
			{"CT-1.1", "Docker Daemon Configuration", "Ensure Docker daemon socket is not world-readable and TLS is enabled for remote access to prevent unauthorized container operations.", "Container"},
			{"CT-1.2", "Docker Daemon Logging", "Ensure Docker daemon is configured with appropriate logging driver and log rotation to prevent disk exhaustion and enable audit trails.", "Container"},
			{"CT-2.1", "Container Runtime Security", "Ensure containers run with non-root user, read-only root filesystem, and minimal capabilities to reduce attack surface.", "Container"},
			{"CT-2.2", "Container Image Security", "Ensure container images are scanned for vulnerabilities, signed, and pulled from trusted registries only.", "Container"},
			{"CT-2.3", "Container Network Security", "Ensure container network isolation is enforced with dedicated network namespaces and restricted inter-container communication.", "Container"},
			{"CT-3.1", "Docker Socket Permissions", "Ensure Docker socket file permissions are set to 660 or more restrictive to prevent unauthorized access.", "Container"},
			{"CT-3.2", "Docker Group Membership", "Ensure the docker group is not used for unprivileged users to prevent container escape via group-based access.", "Container"},
		}},
		{"Kubernetes", []c{
			{"KS-1.1", "API Server Authentication", "Ensure the API server is configured with strong authentication, anonymous auth disabled, and admission controllers enabled.", "Kubernetes"},
			{"KS-1.2", "API Server Audit Logging", "Ensure the API server has audit logging enabled with a policy covering all stages and verbs.", "Kubernetes"},
			{"KS-2.1", "etcd Configuration", "Ensure etcd data is encrypted at rest, access is restricted via TLS and client certificate authentication.", "Kubernetes"},
			{"KS-2.2", "etcd Backup", "Ensure etcd is regularly backed up with encrypted backups stored in a secure, separate location.", "Kubernetes"},
			{"KS-3.1", "Controller Manager Security", "Ensure the controller manager uses secure port, TLS, and service account key rotation.", "Kubernetes"},
			{"KS-3.2", "Scheduler Security", "Ensure the kube-scheduler binds to a secure port and uses TLS for API communication.", "Kubernetes"},
			{"KS-4.1", "Worker Node Hardening", "Ensure kubelet is configured with anonymous auth disabled, streaming connection idle timeout, and event recording.", "Kubernetes"},
			{"KS-4.2", "Pod Security Policies", "Ensure pod security standards are enforced including restricted privilege escalation, non-root containers, and seccomp profiles.", "Kubernetes"},
			{"KS-5.1", "Network Policies", "Ensure default deny network policies are in place for all namespaces to restrict pod-to-pod communication.", "Kubernetes"},
			{"KS-5.2", "Secrets Management", "Ensure Kubernetes secrets are encrypted at rest and access is restricted via RBAC with minimal permissions.", "Kubernetes"},
		}},
		{"Database", []c{
			{"DB-1.1", "PostgreSQL Authentication", "Ensure PostgreSQL authentication uses SCRAM-SHA-256, md5 is deprecated, and trust authentication is disabled.", "Database"},
			{"DB-1.2", "PostgreSQL Network Security", "Ensure PostgreSQL listen_addresses is restricted and SSL is required for all connections.", "Database"},
			{"DB-1.3", "PostgreSQL Logging", "Ensure PostgreSQL logging is configured to record connection attempts, failed authentications, and DDL statements.", "Database"},
			{"DB-2.1", "MySQL Authentication", "Ensure MySQL root accounts have strong passwords and anonymous accounts are removed.", "Database"},
			{"DB-2.2", "MySQL Network Security", "Ensure MySQL is not exposed on public interfaces and requires TLS for remote connections.", "Database"},
			{"DB-3.1", "MongoDB Authentication", "Ensure MongoDB authentication is enabled with SCRAM-SHA-256 and local localhost exception is disabled in production.", "Database"},
			{"DB-3.2", "MongoDB Network Security", "Ensure MongoDB binds to specific interfaces only and TLS is enabled for all connections.", "Database"},
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
				Level:       "level1",
				RelatedCWEs: cisBenchCWEs(c.id),
				References:  []grc.Reference{{Source: "CIS Benchmarks", Section: c.id}},
			})
		}
	}
	return controls
}
