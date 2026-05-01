package cyber_essentials

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/vincents-ai/enrichment-engine/pkg/grc"
	"github.com/vincents-ai/enrichment-engine/pkg/storage"
)

const FrameworkID = "NCSC_CYBER_ESSENTIALS"

type Provider struct {
	store  storage.Backend
	logger *slog.Logger
}

func New(store storage.Backend, logger *slog.Logger) *Provider {
	return &Provider{store: store, logger: logger}
}

func (p *Provider) Name() string {
	return "cyber_essentials"
}

func (p *Provider) Run(ctx context.Context) (int, error) {
	p.logger.Info("loading NCSC Cyber Essentials controls")

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

	p.logger.Info("wrote NCSC Cyber Essentials controls to storage", "count", count)
	return count, nil
}

func staticControls() []grc.Control {
	ref := func(section string) []grc.Reference {
		return []grc.Reference{
			{
				Source:  "NCSC Cyber Essentials v3.1",
				URL:     "https://www.ncsc.gov.uk/cyberessentials/overview",
				Section: section,
			},
		}
	}

	return []grc.Control{

		// ── Theme 1: Firewalls and Internet Gateways ──────────────────────
		{
			Framework:              FrameworkID,
			ControlID:              "CE-1.1",
			Title:                  "Boundary Firewalls Deployment",
			Family:                 "Firewalls",
			Description:            "A firewall must be deployed at every network boundary that connects to an untrusted network, including the internet. Host-based firewalls should also be enabled on all end-user devices to provide defence in depth when devices are used outside the corporate network.",
			Level:                  "standard",
			RelatedCWEs:            []string{"CWE-284", "CWE-345"},
			Tags:                   []string{"network", "perimeter", "access-control"},
			References:             ref("CE-1.1"),
			ImplementationGuidance: "Deploy a boundary firewall (hardware or software) at every internet-facing network edge. Enable host-based firewalls on laptops and desktops. Document firewall placements in network architecture diagrams.",
			AssessmentMethods: []string{
				"Interview: confirm firewalls exist at all network boundaries",
				"Examine: review network diagrams for firewall placement",
				"Test: verify host-based firewall is enabled on a sample of devices",
			},
		},
		{
			Framework:              FrameworkID,
			ControlID:              "CE-1.2",
			Title:                  "Default Deny Firewall Rules",
			Family:                 "Firewalls",
			Description:            "All firewall rules must default to denying inbound connections. Only traffic that is explicitly required for business operations should be permitted. This ensures that any undocumented or forgotten service is not inadvertently exposed to the internet.",
			Level:                  "standard",
			RelatedCWEs:            []string{"CWE-284", "CWE-668"},
			Tags:                   []string{"network", "access-control", "least-privilege"},
			References:             ref("CE-1.2"),
			ImplementationGuidance: "Configure the default inbound rule to deny all. Add explicit allow rules only for services that must be reachable from untrusted networks. Periodically audit the rule base to confirm no overly broad rules exist.",
			AssessmentMethods: []string{
				"Examine: review firewall rule base for default-deny configuration",
				"Examine: confirm no rules use 'any-any' patterns unnecessarily",
				"Test: attempt to connect to non-permitted services from outside the network",
			},
		},
		{
			Framework:              FrameworkID,
			ControlID:              "CE-1.3",
			Title:                  "Firewall Rule Management",
			Family:                 "Firewalls",
			Description:            "Firewall rules must be reviewed at least annually to identify and remove rules that are no longer required. Stale rules accumulate over time and can expose services that were temporarily needed but have since been decommissioned, widening the attack surface unnecessarily.",
			Level:                  "standard",
			RelatedCWEs:            []string{"CWE-345"},
			Tags:                   []string{"network", "governance", "housekeeping"},
			References:             ref("CE-1.3"),
			ImplementationGuidance: "Schedule annual firewall rule reviews with named owners. Maintain a change log documenting when rules were added and the business justification. Automate detection of unused rules where possible using firewall log analysis.",
			AssessmentMethods: []string{
				"Interview: confirm a review schedule exists and has been followed",
				"Examine: review change logs for firewall rule modifications",
				"Examine: verify unused rules have been identified and removed",
			},
		},
		{
			Framework:              FrameworkID,
			ControlID:              "CE-1.4",
			Title:                  "Administrative Interfaces Not Exposed to Public Internet",
			Family:                 "Firewalls",
			Description:            "Administrative interfaces such as remote desktop, SSH, management consoles, and configuration portals must not be directly accessible from the public internet. Exposing these interfaces provides a direct path for attackers to attempt brute-force or credential-stuffing attacks against privileged access points.",
			Level:                  "standard",
			RelatedCWEs:            []string{"CWE-284", "CWE-306"},
			Tags:                   []string{"network", "access-control", "remote-access"},
			References:             ref("CE-1.4"),
			ImplementationGuidance: "Block all management protocols (RDP, SSH, Telnet, HTTP management) at the boundary firewall for inbound connections from the internet. Use a VPN or jump host with MFA for remote administrative access.",
			AssessmentMethods: []string{
				"Examine: review firewall rules for management port exposure",
				"Test: attempt to connect to common management ports from an external IP",
				"Interview: confirm how remote admin access is provisioned",
			},
		},
		{
			Framework:              FrameworkID,
			ControlID:              "CE-1.5",
			Title:                  "Firewall Denial of Service Protection",
			Family:                 "Firewalls",
			Description:            "Firewalls must be configured to protect against denial of service attacks by limiting connection rates and rejecting malformed packets. Rate limiting prevents brute-force attacks on exposed services, and dropping malformed packets stops common network-layer exploitation techniques.",
			Level:                  "standard",
			RelatedCWEs:            []string{"CWE-400", "CWE-770"},
			Tags:                   []string{"network", "availability", "denial-of-service"},
			References:             ref("CE-1.5"),
			ImplementationGuidance: "Enable SYN flood protection and connection rate limiting on the boundary firewall. Configure the firewall to drop malformed packets and ICMP floods. Consider enabling geo-blocking if services are only needed from specific regions.",
			AssessmentMethods: []string{
				"Examine: review firewall configuration for rate-limiting rules",
				"Examine: verify malformed packet handling is enabled",
				"Test: simulate connection flooding to validate rate limits",
			},
		},

		// ── Theme 2: Secure Configuration ─────────────────────────────────
		{
			Framework:              FrameworkID,
			ControlID:              "CE-2.1",
			Title:                  "Secure Baseline Configuration Standards",
			Family:                 "Secure Configuration",
			Description:            "All computers and network devices must be configured using documented secure baseline settings. A baseline defines the minimum security standard for every system, covering user account policies, logging levels, service configurations, and cryptographic settings, ensuring consistency across the estate.",
			Level:                  "standard",
			RelatedCWEs:            []string{"CWE-254", "CWE-927"},
			Tags:                   []string{"hardening", "configuration-management", "governance"},
			References:             ref("CE-2.1"),
			ImplementationGuidance: "Create a secure configuration baseline for each operating system and device type used in the organisation. Use CIS Benchmarks or vendor hardening guides as a starting point. Automate baseline application using configuration management tools.",
			AssessmentMethods: []string{
				"Examine: review documented baseline configuration standards",
				"Examine: compare a sample of systems against the baseline",
				"Interview: confirm how baselines are maintained and applied to new systems",
			},
		},
		{
			Framework:              FrameworkID,
			ControlID:              "CE-2.2",
			Title:                  "Removal of Unnecessary User Accounts",
			Family:                 "Secure Configuration",
			Description:            "Default, guest, and unnecessary user accounts must be removed or disabled on all systems. Unused accounts provide attackers with pre-existing identities that may have forgotten permissions, reducing the effort required to escalate privileges or move laterally through the network.",
			Level:                  "standard",
			RelatedCWEs:            []string{"CWE-254", "CWE-287"},
			Tags:                   []string{"access-control", "identity", "housekeeping"},
			References:             ref("CE-2.2"),
			ImplementationGuidance: "Audit all systems for default accounts (e.g., guest, admin, test). Disable or remove any account that is not actively required. Implement a process to review accounts on a regular cadence, particularly after staff departures.",
			AssessmentMethods: []string{
				"Examine: list user accounts on a sample of systems and verify each is required",
				"Interview: confirm the process for removing accounts when staff leave",
				"Examine: verify guest accounts are disabled or removed",
			},
		},
		{
			Framework:              FrameworkID,
			ControlID:              "CE-2.3",
			Title:                  "Disabling Unnecessary Services and Software",
			Family:                 "Secure Configuration",
			Description:            "All unnecessary services, daemons, and software applications must be removed or disabled. Every additional piece of software increases the attack surface; services that are not needed for business operations should be eliminated to minimise the number of potential vulnerabilities an attacker could exploit.",
			Level:                  "standard",
			RelatedCWEs:            []string{"CWE-927", "CWE-1109"},
			Tags:                   []string{"hardening", "vulnerability-management", "housekeeping"},
			References:             ref("CE-2.3"),
			ImplementationGuidance: "Identify all running services on each system and determine which are required for business operations. Disable or uninstall services that are not needed. Use server core or minimal installation options where available.",
			AssessmentMethods: []string{
				"Examine: list installed services and running processes on a sample of systems",
				"Interview: confirm which services are required and why",
				"Examine: verify unnecessary services have been disabled or removed",
			},
		},
		{
			Framework:              FrameworkID,
			ControlID:              "CE-2.4",
			Title:                  "Changing Default Passwords",
			Family:                 "Secure Configuration",
			Description:            "All default passwords on devices, software, and services must be changed before deployment to a production or internet-facing environment. Default credentials are widely documented and are among the first things an attacker will try, making them trivially exploitable if left unchanged.",
			Level:                  "standard",
			RelatedCWEs:            []string{"CWE-254", "CWE-521"},
			Tags:                   []string{"authentication", "hardening", "credentials"},
			References:             ref("CE-2.4"),
			ImplementationGuidance: "Maintain a checklist of all devices and software that ship with default credentials. Before any device goes live, verify that all default passwords have been changed to strong, unique values. Store credentials in a secrets manager.",
			AssessmentMethods: []string{
				"Examine: review deployment procedures for default password handling",
				"Interview: confirm awareness of default credential risks",
				"Test: attempt to log in to a sample of devices using known default credentials",
			},
		},
		{
			Framework:              FrameworkID,
			ControlID:              "CE-2.5",
			Title:                  "Documented Hardening Standards",
			Family:                 "Secure Configuration",
			Description:            "The organisation must maintain documented hardening standards that specify how each type of system should be securely configured. Without documented standards, configuration drift occurs and new systems may be deployed with weaker settings than intended, undermining the overall security posture.",
			Level:                  "standard",
			RelatedCWEs:            []string{"CWE-927", "CWE-1109"},
			Tags:                   []string{"governance", "configuration-management", "documentation"},
			References:             ref("CE-2.5"),
			ImplementationGuidance: "Create and maintain hardening guides for each operating system and application in use. Version control these documents and review them at least annually. Automate compliance checking against the documented standards.",
			AssessmentMethods: []string{
				"Examine: review hardening documentation for completeness and currency",
				"Interview: confirm the review and update cycle for hardening standards",
				"Examine: compare a sample of deployed systems against documented standards",
			},
		},

		// ── Theme 3: Access Control ───────────────────────────────────────
		{
			Framework:              FrameworkID,
			ControlID:              "CE-3.1",
			Title:                  "User Authentication",
			Family:                 "Access Control",
			Description:            "All users must authenticate before being granted access to systems and applications. Authentication verifies the identity of the user and is the foundational control that enables accountability and prevents unauthorised individuals from accessing sensitive data or critical systems.",
			Level:                  "standard",
			RelatedCWEs:            []string{"CWE-287", "CWE-306"},
			Tags:                   []string{"authentication", "access-control", "identity"},
			References:             ref("CE-3.1"),
			ImplementationGuidance: "Implement authentication on all systems and applications. Where possible, use a centralised identity provider to enforce consistent authentication policies. Disable anonymous access unless explicitly required and documented.",
			AssessmentMethods: []string{
				"Examine: verify authentication is required on all systems",
				"Test: attempt unauthenticated access to a sample of systems",
				"Interview: confirm the authentication mechanism in use",
			},
		},
		{
			Framework:              FrameworkID,
			ControlID:              "CE-3.2",
			Title:                  "Least Privilege Access",
			Family:                 "Access Control",
			Description:            "Users must be granted the minimum level of access necessary to perform their role. Least privilege limits the damage that can be caused by a compromised account, as the attacker is constrained to the permissions of the user whose credentials were stolen.",
			Level:                  "standard",
			RelatedCWEs:            []string{"CWE-284", "CWE-269"},
			Tags:                   []string{"access-control", "least-privilege", "authorization"},
			References:             ref("CE-3.2"),
			ImplementationGuidance: "Conduct an access rights review to identify and remove excessive permissions. Implement role-based access control (RBAC) aligned with job functions. Use just-in-time access for elevated privileges where feasible.",
			AssessmentMethods: []string{
				"Examine: review user permission assignments against role requirements",
				"Interview: confirm the process for granting and reviewing access rights",
				"Examine: verify separation of duties for sensitive functions",
			},
		},
		{
			Framework:              FrameworkID,
			ControlID:              "CE-3.3",
			Title:                  "Administrative Account Controls",
			Family:                 "Access Control",
			Description:            "Administrative accounts must only be used for administrative tasks and must not be used for day-to-day activities such as email or web browsing. Using admin accounts for routine tasks increases the risk of credential compromise through phishing or drive-by downloads, which could give an attacker full system control.",
			Level:                  "standard",
			RelatedCWEs:            []string{"CWE-250", "CWE-269"},
			Tags:                   []string{"access-control", "privilege-management", "credentials"},
			References:             ref("CE-3.3"),
			ImplementationGuidance: "Issue separate standard user accounts for daily activities. Reserve administrative accounts solely for system management tasks. Use privileged access management (PAM) tools to control and audit admin sessions.",
			AssessmentMethods: []string{
				"Interview: confirm users have separate standard and admin accounts",
				"Examine: verify admin accounts are not used for non-administrative activities",
				"Examine: review admin account inventory and justification for each",
			},
		},
		{
			Framework:              FrameworkID,
			ControlID:              "CE-3.4",
			Title:                  "Multi-Factor Authentication for Remote Access",
			Family:                 "Access Control",
			Description:            "Multi-factor authentication (MFA) must be enforced for all remote access to the corporate network and cloud services. Passwords alone are insufficient protection for remote access, which is routinely targeted by attackers using credential stuffing, brute force, and phishing campaigns.",
			Level:                  "standard",
			RelatedCWEs:            []string{"CWE-287", "CWE-308"},
			Tags:                   []string{"authentication", "remote-access", "mfa"},
			References:             ref("CE-3.4"),
			ImplementationGuidance: "Deploy MFA on all VPN, remote desktop, and cloud service access points. Use authenticator apps or hardware tokens rather than SMS where possible. Ensure MFA cannot be bypassed through alternative access paths.",
			AssessmentMethods: []string{
				"Examine: verify MFA is configured on all remote access entry points",
				"Test: attempt remote access with only a password to confirm MFA is enforced",
				"Interview: confirm the MFA methods in use and any bypass paths",
			},
		},
		{
			Framework:              FrameworkID,
			ControlID:              "CE-3.5",
			Title:                  "Multi-Factor Authentication for Administrative Access",
			Family:                 "Access Control",
			Description:            "MFA must be required for all administrative access to systems, regardless of whether access is local or remote. Administrative accounts represent high-value targets, and MFA provides an additional layer of defence that significantly reduces the risk of unauthorised privilege escalation.",
			Level:                  "standard",
			RelatedCWEs:            []string{"CWE-287", "CWE-250"},
			Tags:                   []string{"authentication", "privilege-management", "mfa"},
			References:             ref("CE-3.5"),
			ImplementationGuidance: "Enable MFA on all systems that support it for administrative login. For systems that do not natively support MFA, use a privileged access management (PAM) solution that enforces MFA at the gateway. Document any exceptions with compensating controls.",
			AssessmentMethods: []string{
				"Examine: verify MFA is required for admin access on all systems",
				"Test: attempt administrative login without MFA to confirm enforcement",
				"Interview: confirm how MFA is enforced for systems without native support",
			},
		},
		{
			Framework:              FrameworkID,
			ControlID:              "CE-3.6",
			Title:                  "Access Rights Review on Role Change or Departure",
			Family:                 "Access Control",
			Description:            "Access rights must be reviewed and updated promptly when staff change roles or leave the organisation. Delayed revocation of permissions creates orphaned accounts that can be exploited by insiders or attackers who have obtained former employee credentials.",
			Level:                  "standard",
			RelatedCWEs:            []string{"CWE-284", "CWE-639"},
			Tags:                   []string{"access-control", "governance", "lifecycle"},
			References:             ref("CE-3.6"),
			ImplementationGuidance: "Integrate access provisioning and deprovisioning into HR onboarding and offboarding workflows. Conduct periodic access reviews (at least quarterly) to catch any discrepancies. Automate account deactivation triggered by HR systems where possible.",
			AssessmentMethods: []string{
				"Interview: confirm the process for revoking access on staff departure",
				"Examine: review a sample of recent departures for timely access removal",
				"Examine: verify access review records exist and are up to date",
			},
		},

		// ── Theme 4: Malware Protection ───────────────────────────────────
		{
			Framework:              FrameworkID,
			ControlID:              "CE-4.1",
			Title:                  "Anti-Malware Software Deployment",
			Family:                 "Malware Protection",
			Description:            "Anti-malware software must be installed and active on all computers and laptops within the organisation. This includes endpoints running Windows, macOS, and Linux where supported. Anti-malware provides a critical layer of defence by detecting and blocking known malicious software before it can execute.",
			Level:                  "standard",
			RelatedCWEs:            []string{"CWE-927", "CWE-506"},
			Tags:                   []string{"malware", "endpoint-protection", "detection"},
			References:             ref("CE-4.1"),
			ImplementationGuidance: "Deploy an enterprise anti-malware solution to all endpoints. Ensure coverage includes servers, workstations, and laptops. Use a centrally managed console to monitor deployment status and verify all endpoints are reporting in.",
			AssessmentMethods: []string{
				"Examine: verify anti-malware is installed on a representative sample of endpoints",
				"Examine: confirm central management console shows full endpoint coverage",
				"Interview: confirm the anti-malware solution in use and how it is managed",
			},
		},
		{
			Framework:              FrameworkID,
			ControlID:              "CE-4.2",
			Title:                  "Anti-Malware Signature Updates",
			Family:                 "Malware Protection",
			Description:            "Anti-malware software must be configured to update its detection signatures automatically, at least daily. Signature-based detection is only effective if the signature database is current; stale definitions leave endpoints vulnerable to recently discovered malware that older signatures cannot identify.",
			Level:                  "standard",
			RelatedCWEs:            []string{"CWE-927", "CWE-254"},
			Tags:                   []string{"malware", "endpoint-protection", "configuration-management"},
			References:             ref("CE-4.2"),
			ImplementationGuidance: "Configure anti-malware to pull signature updates at least every 24 hours. Use a central management server to push updates if endpoints cannot reach update servers directly. Monitor for endpoints that fail to update and remediate promptly.",
			AssessmentMethods: []string{
				"Examine: verify anti-malware signature update frequency configuration",
				"Examine: check last update timestamps on a sample of endpoints",
				"Interview: confirm the process for monitoring and remediating update failures",
			},
		},
		{
			Framework:              FrameworkID,
			ControlID:              "CE-4.3",
			Title:                  "On-Access Malware Scanning",
			Family:                 "Malware Protection",
			Description:            "Anti-malware must be configured to scan files automatically when they are accessed, downloaded, or opened. On-access scanning provides real-time protection by intercepting files before they can execute, catching malware that may have bypassed perimeter defences through email attachments, web downloads, or removable media.",
			Level:                  "standard",
			RelatedCWEs:            []string{"CWE-927", "CWE-506"},
			Tags:                   []string{"malware", "endpoint-protection", "detection"},
			References:             ref("CE-4.3"),
			ImplementationGuidance: "Enable real-time or on-access scanning in the anti-malware configuration. Ensure scanning covers all file types, including executables, documents, and archives. Configure exceptions sparingly and document any exclusions with justification.",
			AssessmentMethods: []string{
				"Examine: verify on-access scanning is enabled on a sample of endpoints",
				"Examine: review any scan exclusions and their justifications",
				"Test: download an EICAR test file to confirm real-time detection triggers",
			},
		},
		{
			Framework:              FrameworkID,
			ControlID:              "CE-4.4",
			Title:                  "Application Whitelisting",
			Family:                 "Malware Protection",
			Description:            "On systems that perform a fixed set of functions, application whitelisting must be used to prevent unauthorised software from executing. Whitelisting is more effective than blacklisting because it denies execution by default, blocking zero-day malware and fileless attacks that signature-based detection cannot identify.",
			Level:                  "standard",
			RelatedCWEs:            []string{"CWE-94", "CWE-749"},
			Tags:                   []string{"malware", "whitelisting", "execution-control"},
			References:             ref("CE-4.4"),
			ImplementationGuidance: "Identify systems with a fixed function set (e.g., kiosks, POS terminals, SCADA workstations). Implement application whitelisting using built-in OS features (e.g., Windows AppLocker, macOS Gatekeeper) or third-party solutions. Maintain the whitelist as part of change management.",
			AssessmentMethods: []string{
				"Examine: identify systems suitable for whitelisting and verify it is enabled",
				"Test: attempt to execute an unauthorised binary on a whitelisted system",
				"Interview: confirm the whitelist maintenance and update process",
			},
		},
		{
			Framework:              FrameworkID,
			ControlID:              "CE-4.5",
			Title:                  "Sandboxing and Execution Restrictions",
			Family:                 "Malware Protection",
			Description:            "Where application whitelisting is not feasible, sandboxing or execution restriction mechanisms must be used to limit the impact of malware. Sandboxing isolates untrusted code, preventing it from accessing sensitive system resources or spreading to other parts of the network.",
			Level:                  "standard",
			RelatedCWEs:            []string{"CWE-94", "CWE-265"},
			Tags:                   []string{"malware", "sandboxing", "isolation"},
			References:             ref("CE-4.5"),
			ImplementationGuidance: "Enable browser sandboxing and content isolation features. Use containerisation or virtualisation for high-risk activities. Restrict email client handling of macros and active content. Consider sandboxing solutions for file processing servers.",
			AssessmentMethods: []string{
				"Examine: verify sandboxing or execution restrictions are in place",
				"Examine: review browser and email client security configurations",
				"Interview: confirm the approach used where whitelisting is not applied",
			},
		},

		// ── Theme 5: Patch Management ─────────────────────────────────────
		{
			Framework:              FrameworkID,
			ControlID:              "CE-5.1",
			Title:                  "Software and Operating System Updates",
			Family:                 "Patch Management",
			Description:            "All software running on devices within the organisation must be kept up to date. This includes operating systems, firmware, and third-party applications. Unpatched software contains known vulnerabilities that are routinely exploited by automated scanning tools and opportunistic attackers.",
			Level:                  "standard",
			RelatedCWEs:            []string{"CWE-1109", "CWE-927"},
			Tags:                   []string{"patching", "vulnerability-management", "lifecycle"},
			References:             ref("CE-5.1"),
			ImplementationGuidance: "Enable automatic updates for operating systems and applications where supported. Use a centralised patch management system to track and deploy updates across the estate. Maintain an inventory of all software to ensure nothing is missed.",
			AssessmentMethods: []string{
				"Examine: review patch management tool deployment and coverage",
				"Examine: check patch status of a sample of systems against latest available updates",
				"Interview: confirm the patching process and update frequency",
			},
		},
		{
			Framework:              FrameworkID,
			ControlID:              "CE-5.2",
			Title:                  "High-Risk Vulnerability Patching Within 14 Days",
			Family:                 "Patch Management",
			Description:            "Security patches for high-risk or widely exploited vulnerabilities must be applied within 14 days of release. The 14-day window balances the urgency of closing known exploits against the need for testing, but should be treated as a maximum rather than a target for the most critical issues.",
			Level:                  "standard",
			RelatedCWEs:            []string{"CWE-345", "CWE-927"},
			Tags:                   []string{"patching", "vulnerability-management", "timeliness"},
			References:             ref("CE-5.2"),
			ImplementationGuidance: "Subscribe to vendor security advisories and vulnerability intelligence feeds. Establish a rapid patching process with pre-staged test environments for critical patches. Track patch deployment against the 14-day SLA and escalate delays to management.",
			AssessmentMethods: []string{
				"Examine: review patching records for compliance with the 14-day window",
				"Interview: confirm the escalation process for missed patching deadlines",
				"Examine: verify vulnerability intelligence feeds are being monitored",
			},
		},
		{
			Framework:              FrameworkID,
			ControlID:              "CE-5.3",
			Title:                  "Firmware Updates",
			Family:                 "Patch Management",
			Description:            "Firmware on all devices, including routers, switches, firewalls, IoT devices, and peripherals, must be kept up to date with the latest security patches. Firmware vulnerabilities are particularly dangerous because they execute at a low level and can persist through operating system reinstalls.",
			Level:                  "standard",
			RelatedCWEs:            []string{"CWE-119", "CWE-1109"},
			Tags:                   []string{"patching", "firmware", "iot"},
			References:             ref("CE-5.3"),
			ImplementationGuidance: "Maintain an inventory of all firmware versions across network devices and endpoints. Subscribe to vendor security advisories for firmware updates. Test firmware updates in a lab environment before deployment to production.",
			AssessmentMethods: []string{
				"Examine: review firmware version inventory against latest available versions",
				"Interview: confirm the firmware update process and cadence",
				"Examine: verify firmware update testing procedures exist",
			},
		},
		{
			Framework:              FrameworkID,
			ControlID:              "CE-5.4",
			Title:                  "Removal of Unsupported Software",
			Family:                 "Patch Management",
			Description:            "Software and operating systems that are no longer supported by the vendor must be identified and removed from the network. Unsupported software does not receive security patches, meaning any vulnerability discovered in it will remain unpatched indefinitely, providing a permanent target for attackers.",
			Level:                  "standard",
			RelatedCWEs:            []string{"CWE-1109", "CWE-927"},
			Tags:                   []string{"patching", "lifecycle", "vulnerability-management"},
			References:             ref("CE-5.4"),
			ImplementationGuidance: "Maintain a software lifecycle register that tracks end-of-support dates. Plan migrations well in advance of vendor support ending. Where unsupported software cannot be immediately replaced, implement compensating controls and document the risk acceptance.",
			AssessmentMethods: []string{
				"Examine: review the software lifecycle register for end-of-support tracking",
				"Examine: scan the network for unsupported operating systems or applications",
				"Interview: confirm the process for managing unsupported software exceptions",
			},
		},
		{
			Framework:              FrameworkID,
			ControlID:              "CE-5.5",
			Title:                  "Documented Patching Process",
			Family:                 "Patch Management",
			Description:            "The organisation must have a documented patching process that defines how patches are evaluated, tested, approved, and deployed. A documented process ensures consistency, enables auditing, and provides a clear escalation path when patching cannot meet the required timeline.",
			Level:                  "standard",
			RelatedCWEs:            []string{"CWE-1109", "CWE-927"},
			Tags:                   []string{"patching", "governance", "documentation"},
			References:             ref("CE-5.5"),
			ImplementationGuidance: "Document the end-to-end patching workflow including vulnerability monitoring, patch evaluation, testing, approval, deployment, and verification. Define SLAs for different severity levels. Include procedures for emergency patching when zero-day vulnerabilities are disclosed.",
			AssessmentMethods: []string{
				"Examine: review documented patching process for completeness",
				"Interview: confirm the process is followed and understood by relevant staff",
				"Examine: verify patching SLAs are defined and tracked",
			},
		},
	}
}
