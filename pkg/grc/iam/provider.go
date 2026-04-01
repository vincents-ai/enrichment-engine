package iam

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/shift/enrichment-engine/pkg/grc"
	"github.com/shift/enrichment-engine/pkg/storage"
)

const (
	FrameworkID = "IAM_V1"
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
	return "iam"
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
		p.logger.Info("wrote IAM controls", "count", count)
	}
	return count, nil
}

func embeddedControls() []grc.Control {
	return []grc.Control{
		{
			Framework: FrameworkID, ControlID: "IAM-AD-1.1",
			Title: "Domain Controller Security Baseline", Family: "Active Directory",
			Description:            "Ensure domain controllers are secured with a baseline configuration including restricted network access, Windows Firewall rules, and automatic security updates. Domain controllers hold the master copy of the Active Directory database.",
			Level:                  "critical",
			RelatedCWEs:            []string{"CWE-284", "CWE-269"},
			References:             []grc.Reference{{Source: "CIS Microsoft Windows Server Benchmark", URL: "https://www.cisecurity.org/benchmark/microsoft_windows_server", Section: "Domain Controller"}},
			ImplementationGuidance: "Apply CIS Windows Server Benchmark to all domain controllers. Restrict RPC, SMB, and RDP access to authorized subnets only. Enable Windows Defender Credential Guard.",
			AssessmentMethods:      []string{"CIS Benchmark Audit", "Group Policy Results", "Manual Review"},
		},
		{
			Framework: FrameworkID, ControlID: "IAM-AD-1.2",
			Title: "Kerberos Policy Configuration", Family: "Active Directory",
			Description:            "Ensure Kerberos policies are configured with strong encryption types (AES-256), maximum service ticket lifetime of 600 minutes, and maximum user ticket lifetime of 10 hours.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-326", "CWE-327"},
			References:             []grc.Reference{{Source: "Microsoft Security Baseline", URL: "https://docs.microsoft.com/windows-server/security/kerberos/kerberos-authentication-overview", Section: "Kerberos"}},
			ImplementationGuidance: "Set 'Maximum service ticket lifetime' to 600 minutes. Enforce AES-256 encryption. Disable RC4 in domain Group Policy.",
			AssessmentMethods:      []string{"Group Policy Editor", "PowerShell: Get-ADDomain", "Manual Review"},
		},
		{
			Framework: FrameworkID, ControlID: "IAM-AD-1.3",
			Title: "Active Directory Password Policy", Family: "Active Directory",
			Description:            "Ensure that Active Directory fine-grained password policies enforce minimum 14 character passwords, complexity requirements, and a maximum password age of 60 days for privileged accounts.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-521", "CWE-526"},
			References:             []grc.Reference{{Source: "NIST SP 800-63B", URL: "https://pages.nist.gov/800-63-3/sp800-63b.html", Section: "Password Policies"}},
			ImplementationGuidance: "Create fine-grained password policies (PSOs) for privileged groups. Enforce 14+ character minimum, no password reuse for last 24, lockout after 5 failed attempts.",
			AssessmentMethods:      []string{"Active Directory Administrative Center", "PowerShell: Get-ADFineGrainedPasswordPolicy"},
		},
		{
			Framework: FrameworkID, ControlID: "IAM-AD-1.4",
			Title: "LDAP Signing and Channel Binding", Family: "Active Directory",
			Description:            "Ensure that LDAP signing is required and LDAP channel binding is enforced to prevent LDAP relay attacks.",
			Level:                  "critical",
			RelatedCWEs:            []string{"CWE-287", "CWE-346"},
			References:             []grc.Reference{{Source: "Microsoft Security Advisory", URL: "https://docs.microsoft.com/windows-server/security/kerberos/ldap-channel-binding", Section: "LDAP Security"}},
			ImplementationGuidance: "Set 'Domain controller: LDAP server signing requirements' to Require Signing. Enable LDAP channel binding via registry. Patch systems against CVE-2021-42278 and CVE-2021-42287.",
			AssessmentMethods:      []string{"Group Policy Settings", "Registry Audit", "Manual Review"},
		},
		{
			Framework: FrameworkID, ControlID: "IAM-AD-1.5",
			Title: "Privileged Group Monitoring", Family: "Active Directory",
			Description:            "Ensure that changes to privileged Active Directory groups (Domain Admins, Enterprise Admins, Schema Admins) are monitored and alerted in real-time.",
			Level:                  "critical",
			RelatedCWEs:            []string{"CWE-269", "CWE-284"},
			References:             []grc.Reference{{Source: "MITRE ATT&CK T1098", URL: "https://attack.mitre.org/techniques/T1098/", Section: "Account Manipulation"}},
			ImplementationGuidance: "Enable Windows Event Log 4728-4735 (member added to global group) and 4746-4751 (member added to universal group). Forward events to SIEM with real-time alerting.",
			AssessmentMethods:      []string{"SIEM Rules", "Windows Event Log Audit", "Manual Review"},
		},
		{
			Framework: FrameworkID, ControlID: "IAM-ENTRA-2.1",
			Title: "Conditional Access Policies Configured", Family: "Entra ID",
			Description:            "Ensure that Azure AD (Entra ID) Conditional Access policies require MFA for all users, block legacy authentication, and enforce device compliance for sensitive applications.",
			Level:                  "critical",
			RelatedCWEs:            []string{"CWE-287", "CWE-306"},
			References:             []grc.Reference{{Source: "CIS Microsoft Azure Benchmark", URL: "https://docs.microsoft.com/azure/active-directory/conditional-access/", Section: "Conditional Access"}},
			ImplementationGuidance: "Create Conditional Access policies: Require MFA for all users, block legacy authentication protocols, require compliant devices for Exchange/SharePoint access.",
			AssessmentMethods:      []string{"Azure AD Conditional Access Report", "Sign-in Logs", "Manual Review"},
		},
		{
			Framework: FrameworkID, ControlID: "IAM-ENTRA-2.2",
			Title: "MFA Enforcement for All Users", Family: "Entra ID",
			Description:            "Ensure that multi-factor authentication is enforced for all users in Azure AD, including admin accounts, with phishing-resistant methods (FIDO2) for privileged users.",
			Level:                  "critical",
			RelatedCWEs:            []string{"CWE-287"},
			References:             []grc.Reference{{Source: "NIST SP 800-63B", URL: "https://pages.nist.gov/800-63-3/sp800-63b.html", Section: "MFA"}},
			ImplementationGuidance: "Enable per-user MFA or use Conditional Access. Deploy FIDO2 security keys for privileged accounts. Configure Microsoft Authenticator with number matching.",
			AssessmentMethods:      []string{"Azure AD MFA Report", "Conditional Access Evaluation", "Manual Review"},
		},
		{
			Framework: FrameworkID, ControlID: "IAM-ENTRA-2.3",
			Title: "App Registration Security Review", Family: "Entra ID",
			Description:            "Ensure that all Azure AD app registrations have valid credentials, appropriate API permissions, and are reviewed regularly for continued necessity.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-284", "CWE-639"},
			References:             []grc.Reference{{Source: "Azure AD App Management", URL: "https://docs.microsoft.com/azure/active-directory/develop/app-objects-and-service-principals", Section: "App Registrations"}},
			ImplementationGuidance: "Audit all app registrations quarterly. Remove unused apps. Ensure API permissions use least privilege. Rotate client secrets every 90 days. Use certificate-based auth where possible.",
			AssessmentMethods:      []string{"Azure AD App Registrations", "Certificate Expiry Report", "Manual Review"},
		},
		{
			Framework: FrameworkID, ControlID: "IAM-ENTRA-2.4",
			Title: "Privileged Identity Management Enabled", Family: "Entra ID",
			Description:            "Ensure that Azure AD Privileged Identity Management (PIM) is enabled for all eligible privileged roles, requiring just-in-time activation with approval workflows.",
			Level:                  "critical",
			RelatedCWEs:            []string{"CWE-269", "CWE-284"},
			References:             []grc.Reference{{Source: "Azure AD PIM", URL: "https://docs.microsoft.com/azure/active-directory/privileged-identity-management/", Section: "PIM"}},
			ImplementationGuidance: "Enable PIM for Global Administrator, Security Administrator, and other privileged roles. Configure maximum activation duration of 4 hours. Require approval for activation.",
			AssessmentMethods:      []string{"Azure AD PIM Audit Logs", "PIM Settings Review", "Manual Review"},
		},
		{
			Framework: FrameworkID, ControlID: "IAM-ENTRA-2.5",
			Title: "Guest User Access Restricted", Family: "Entra ID",
			Description:            "Ensure that Azure AD guest (B2B) users are reviewed regularly and have restricted permissions. Guest accounts should not have permanent elevated access.",
			Level:                  "medium",
			RelatedCWEs:            []string{"CWE-284", "CWE-862"},
			References:             []grc.Reference{{Source: "Azure AD B2B", URL: "https://docs.microsoft.com/azure/active-directory/b2b/", Section: "Guest Access"}},
			ImplementationGuidance: "Create Access Reviews for all guest users. Restrict guest permissions via Conditional Access. Block guest access to sensitive applications.",
			AssessmentMethods:      []string{"Azure AD Access Reviews", "Guest User Report", "Manual Review"},
		},
		{
			Framework: FrameworkID, ControlID: "IAM-OKTA-3.1",
			Title: "SSO Configuration Security", Family: "Okta",
			Description:            "Ensure that Okta SSO configurations use SAML with signed assertions and encrypted responses. OIDC applications must use PKCE and valid redirect URIs.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-287", "CWE-346"},
			References:             []grc.Reference{{Source: "Okta SSO Documentation", URL: "https://developer.okta.com/docs/concepts/saml/", Section: "SAML Configuration"}},
			ImplementationGuidance: "Enable 'SAML Assertion Signed' and 'SAML Response Encrypted' for all SAML apps. Validate OIDC redirect URIs. Disable 'Allow unsafe logout' on all apps.",
			AssessmentMethods:      []string{"Okta Admin Console", "SAML Assertion Validator", "Manual Review"},
		},
		{
			Framework: FrameworkID, ControlID: "IAM-OKTA-3.2",
			Title: "MFA Policies Enforced", Family: "Okta",
			Description:            "Ensure that Okta MFA policies require at least one factor from multiple factor categories (knowledge, possession, biometric) for all user access.",
			Level:                  "critical",
			RelatedCWEs:            []string{"CWE-287"},
			References:             []grc.Reference{{Source: "Okta MFA Documentation", URL: "https://help.okta.com/oie/en-us/Content/Topics/Security/mfa/mfa-overview.htm", Section: "MFA Policies"}},
			ImplementationGuidance: "Create global MFA policy requiring any two factors. Create additional policies for admin access requiring FIDO2/WebAuthn. Disable SMS as standalone factor for privileged users.",
			AssessmentMethods:      []string{"Okta Policy Reports", "Sign-in Logs", "Manual Review"},
		},
		{
			Framework: FrameworkID, ControlID: "IAM-OKTA-3.3",
			Title: "API Access Management", Family: "Okta",
			Description:            "Ensure that Okta API access is restricted to authorized applications and services only, with scoped OAuth 2.0 tokens and rate limiting enabled.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-284", "CWE-862"},
			References:             []grc.Reference{{Source: "Okta API Security", URL: "https://developer.okta.com/docs/reference/api-overview/", Section: "API Access"}},
			ImplementationGuidance: "Create API scopes with least privilege. Use OAuth 2.0 client credentials flow for service-to-service auth. Enable API rate limiting. Monitor API usage via Okta System Log.",
			AssessmentMethods:      []string{"Okta System Log", "API Token Audit", "Manual Review"},
		},
		{
			Framework: FrameworkID, ControlID: "IAM-OKTA-3.4",
			Title: "User Lifecycle Management", Family: "Okta",
			Description:            "Ensure that Okta user lifecycle processes include automated provisioning/deprovisioning via SCIM, suspended state for inactive users, and timely deactivation upon employment termination.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-284", "CWE-639"},
			References:             []grc.Reference{{Source: "Okta Lifecycle Management", URL: "https://help.okta.com/Content/Topics/Provisioning/SCIM/scim-overview.htm", Section: "SCIM"}},
			ImplementationGuidance: "Configure SCIM provisioning integrations with HR systems. Set automatic deactivation for users not active in 30 days. Create termination workflow that deactivates Okta account immediately.",
			AssessmentMethods:      []string{"Okta User Reports", "SCIM Sync Logs", "Manual Review"},
		},
		{
			Framework: FrameworkID, ControlID: "IAM-GEN-4.1",
			Title: "Least Privilege Enforcement", Family: "General IAM",
			Description:            "Ensure that all identities (human and machine) are granted only the minimum permissions required to perform their assigned functions, with regular permission reviews.",
			Level:                  "critical",
			RelatedCWEs:            []string{"CWE-284", "CWE-862", "CWE-269"},
			References:             []grc.Reference{{Source: "NIST SP 800-53 AC-6", URL: "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final", Section: "AC-6"}},
			ImplementationGuidance: "Implement role-based access control (RBAC) with defined permission sets. Conduct quarterly access reviews. Use just-in-time (JIT) access for elevated privileges. Automate permission analysis.",
			AssessmentMethods:      []string{"Access Review Reports", "Permission Analysis Tools", "Manual Review"},
		},
		{
			Framework: FrameworkID, ControlID: "IAM-GEN-4.2",
			Title: "Separation of Duties", Family: "General IAM",
			Description:            "Ensure that no single identity has conflicting permissions that could allow unauthorized actions without detection (e.g., ability to both create and approve requests).",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-778", "CWE-284"},
			References:             []grc.Reference{{Source: "SOX Section 404", URL: "https://www.sec.gov/rules/final/33-8238.htm", Section: "Segregation of Duties"}},
			ImplementationGuidance: "Define and enforce SoD matrices. Use access governance tools to detect conflicting role assignments. Implement approval workflows for sensitive operations.",
			AssessmentMethods:      []string{"SoD Matrix Analysis", "Access Governance Reports", "Manual Review"},
		},
		{
			Framework: FrameworkID, ControlID: "IAM-GEN-4.3",
			Title: "Periodic Access Reviews", Family: "General IAM",
			Description:            "Ensure that all access rights are reviewed at least quarterly by resource owners, with evidence of review and remediation of unauthorized access.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-284", "CWE-639"},
			References:             []grc.Reference{{Source: "ISO 27001 A.9.2", URL: "https://www.iso.org/standard/27001", Section: "User Access Rights"}},
			ImplementationGuidance: "Schedule quarterly access reviews with reminders. Require managers to certify or revoke access. Track completion rates. Escalate non-compliance.",
			AssessmentMethods:      []string{"Access Review Audit Trail", "Compliance Reports", "Manual Review"},
		},
		{
			Framework: FrameworkID, ControlID: "IAM-GEN-4.4",
			Title: "Credential Rotation Policy", Family: "General IAM",
			Description:            "Ensure that all credentials (passwords, API keys, certificates, tokens) are rotated on a defined schedule and immediately upon suspected compromise.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-798", "CWE-326"},
			References:             []grc.Reference{{Source: "NIST SP 800-63B", URL: "https://pages.nist.gov/800-63-3/sp800-63b.html", Section: "Credential Lifecycle"}},
			ImplementationGuidance: "Automate password rotation for service accounts (90 days max). Rotate API keys quarterly. Implement certificate lifecycle management with 90-day expiry. Use secret managers for all credentials.",
			AssessmentMethods:      []string{"Credential Expiry Reports", "Secret Manager Audit", "Manual Review"},
		},
		{
			Framework: FrameworkID, ControlID: "IAM-GEN-4.5",
			Title: "SSO Federation Security", Family: "General IAM",
			Description:            "Ensure that SAML and OIDC federation configurations are secured with proper signing, encryption, audience restrictions, and metadata validation.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-287", "CWE-345", "CWE-346"},
			References:             []grc.Reference{{Source: "NIST SP 800-63", URL: "https://pages.nist.gov/800-63-3/", Section: "Federation"}},
			ImplementationGuidance: "Validate SAML metadata URLs are HTTPS. Enable assertion encryption. Restrict allowed audiences. Monitor federation partner configurations for unauthorized changes.",
			AssessmentMethods:      []string{"Federation Metadata Review", "SAML/OIDC Security Audit", "Manual Review"},
		},
		{
			Framework: FrameworkID, ControlID: "IAM-GEN-4.6",
			Title: "Just-in-Time Access", Family: "General IAM",
			Description:            "Ensure that privileged access is granted on-demand with time-limited windows and approval workflows, rather than standing privileged access.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-269", "CWE-284"},
			References:             []grc.Reference{{Source: "NIST SP 800-53 AC-17", URL: "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final", Section: "AC-17"}},
			ImplementationGuidance: "Implement JIT access via PIM (Azure AD), SSM Session Manager (AWS), or HashiCorp Boundary. Limit elevation windows to 4 hours. Require approval for production access.",
			AssessmentMethods:      []string{"PIM Activation Logs", "Privileged Access Audit", "Manual Review"},
		},
		{
			Framework: FrameworkID, ControlID: "IAM-GEN-4.7",
			Title: "Break-Glass Procedures", Family: "General IAM",
			Description:            "Ensure that break-glass emergency access procedures exist, are documented, tested quarterly, and monitored with automated alerting on any break-glass activation.",
			Level:                  "critical",
			RelatedCWEs:            []string{"CWE-778", "CWE-284"},
			References:             []grc.Reference{{Source: "NIST SP 800-53 AC-2(7)", URL: "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final", Section: "Emergency Accounts"}},
			ImplementationGuidance: "Create dedicated break-glass accounts with MFA. Store credentials in a secure escrow with dual-custody access. Monitor all break-glass activations and require post-incident review within 24 hours.",
			AssessmentMethods:      []string{"Break-Glass Account Audit", "Incident Review Records", "Manual Review"},
		},
	}
}
