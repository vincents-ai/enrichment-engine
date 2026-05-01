package psd2_rts

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/vincents-ai/enrichment-engine/pkg/grc"
	"github.com/vincents-ai/enrichment-engine/pkg/storage"
)

const FrameworkID = "PSD2_RTS_SCA"

// Provider implements the PSD2 RTS on Strong Customer Authentication
// (Commission Delegated Regulation (EU) 2018/389).
type Provider struct {
	store  storage.Backend
	logger *slog.Logger
}

// New creates a new PSD2 RTS SCA provider.
func New(store storage.Backend, logger *slog.Logger) *Provider {
	return &Provider{
		store:  store,
		logger: logger,
	}
}

// Name returns the provider identifier.
func (p *Provider) Name() string {
	return "psd2_rts"
}

// Run writes all PSD2 RTS SCA controls to storage.
func (p *Provider) Run(ctx context.Context) (int, error) {
	p.logger.Info("loading PSD2 RTS SCA controls")

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

	p.logger.Info("wrote PSD2 RTS SCA controls to storage", "count", count)
	return count, nil
}

func staticControls() []grc.Control {
	ref := func(article string) []grc.Reference {
		return []grc.Reference{{
			Source:  "Commission Delegated Regulation (EU) 2018/389",
			URL:     "https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32018R0389",
			Section: article,
		}}
	}

	return []grc.Control{
		{
			Framework:   FrameworkID,
			ControlID:   "ART-3",
			Title:       "Strong Customer Authentication Elements",
			Family:      "General Authentication Requirements",
			Description: "Payment service providers must implement strong customer authentication (SCA) using at least two independent elements categorised as knowledge, possession, or inherence. The authentication design must ensure that a breach of one element does not compromise the reliability of the others, preventing single-point-of-failure attacks. This control directly addresses the risk of account takeover in payment APIs through inadequate multi-factor authentication.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-308"},
			Tags:        []string{"authentication", "access-control"},
			References:  ref("Article 3"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "ART-4",
			Title:       "Review of SCA Application",
			Family:      "General Authentication Requirements",
			Description: "Payment service providers must perform regular reviews of their SCA implementation to ensure it remains effective against evolving threats. The review process must assess whether SCA is applied consistently across all applicable payment scenarios and interfaces. Continuous governance of the authentication mechanism ensures compliance obligations are maintained as the threat landscape changes.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-308"},
			Tags:        []string{"authentication", "governance"},
			References:  ref("Article 4"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "ART-5",
			Title:       "Authentication Code",
			Family:      "General Authentication Requirements",
			Description: "The authentication code generated during SCA must be computed using approved cryptographic algorithms and must be unique, unpredictable, and resistant to forgery. Codes must expire within a short time window and must not be reusable, mitigating replay and brute-force attacks. Weak or predictable code generation exposes payment APIs to credential theft and transaction fraud.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-327", "CWE-330"},
			Tags:        []string{"authentication", "cryptography"},
			References:  ref("Article 5"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "ART-6",
			Title:       "Dynamic Linking",
			Family:      "General Authentication Requirements",
			Description: "For payment transactions, the authentication code must be dynamically linked to the specific transaction amount and payee so that any alteration invalidates the code. This binding prevents man-in-the-middle and transaction manipulation attacks where an attacker modifies transaction details after authentication. Payment APIs must cryptographically verify the integrity of the linked transaction data during authorisation.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-327", "CWE-345"},
			Tags:        []string{"authentication", "cryptography", "integrity"},
			References:  ref("Article 6"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "ART-7",
			Title:       "Requirements on Elements Categorised as Knowledge",
			Family:      "General Authentication Requirements",
			Description: "Knowledge-based authentication elements such as passwords and PINs must meet minimum length and complexity requirements and must be protected against guessing and brute-force attacks. Storage must use strong one-way hashing with salting, and transmission must occur only over encrypted channels. Poor password policies are a leading cause of compromised payment credentials and must be addressed through both technical and procedural controls.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-521", "CWE-255"},
			Tags:        []string{"authentication"},
			References:  ref("Article 7"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "ART-8",
			Title:       "Requirements on Elements Categorised as Possession",
			Family:      "General Authentication Requirements",
			Description: "Possession-based authentication elements such as hardware tokens, smart cards, or mobile devices must generate unique and time-limited codes that cannot be cloned or replicated. The issuance and revocation of possession elements must be controlled by a secure process to prevent unauthorised provisioning. Payment service providers must detect and respond to attempts to duplicate or transfer possession elements.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-287", "CWE-308"},
			Tags:        []string{"authentication"},
			References:  ref("Article 8"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "ART-9",
			Title:       "Requirements on Devices and Software Linked to Possession",
			Family:      "General Authentication Requirements",
			Description: "Devices and software applications used as possession elements must be protected against cloning and unauthorised use through device-binding and cryptographic attestation mechanisms. The confidentiality and integrity of the cryptographic material stored on the device must be preserved using hardware-backed secure enclaves where available. Compromise of device-linked credentials allows full impersonation of payment service users.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-287", "CWE-326"},
			Tags:        []string{"authentication", "cryptography"},
			References:  ref("Article 9"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "ART-10",
			Title:       "Requirements on Elements Categorised as Inherence",
			Family:      "General Authentication Requirements",
			Description: "Biometric and other inherence-based authentication elements must use algorithms that achieve sufficiently low false acceptance rates and must be resistant to spoofing attacks using artificial artefacts. Payment service providers must monitor and adapt biometric thresholds in response to newly discovered presentation attack vectors. Biometric data must be stored and processed in a manner that prevents its use outside the authentication system.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-308"},
			Tags:        []string{"authentication"},
			References:  ref("Article 10"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "ART-11",
			Title:       "Transaction Risk Analysis Exemption",
			Family:      "Exemptions",
			Description: "Payment service providers may apply a transaction risk analysis (TRA) exemption to waive SCA for individual transactions that fall below defined fraud rate thresholds and reference fraud rates. The TRA must be performed in real time, taking into account risk indicators such as abnormal spending patterns, unusual device information, and known fraud scenarios. Exemptions must be continuously reviewed and revoked when fraud thresholds are exceeded.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-693"},
			Tags:        []string{"authentication", "governance"},
			References:  ref("Article 11"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "ART-12",
			Title:       "Low Value Contactless Transactions",
			Family:      "Exemptions",
			Description: "SCA may be waived for contactless point-of-sale transactions below defined individual and cumulative value thresholds to reduce friction for low-risk payments. Payment service providers must track cumulative transaction values and transaction counts since the last SCA event and must reinstate SCA when either threshold is reached. Failure to enforce cumulative limits creates exposure to contactless card fraud through small repeated transactions.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-308"},
			Tags:        []string{"authentication"},
			References:  ref("Article 12"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "ART-15",
			Title:       "Contactless Payments at Point of Sale",
			Family:      "Exemptions",
			Description: "Payment terminals processing contactless SCA-exempt transactions must enforce the regulatory value and cumulative count limits at the device level to prevent abuse of the contactless exemption. Terminal firmware and payment application logic must be certified and tested to confirm that SCA is correctly triggered when thresholds are met. Inadequate terminal-level enforcement undermines the risk management framework for contactless payments.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-308"},
			Tags:        []string{"authentication"},
			References:  ref("Article 15"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "ART-17",
			Title:       "Corporate Payments",
			Family:      "Exemptions",
			Description: "Payment service providers serving corporate customers may apply an exemption to SCA where the payer uses dedicated corporate payment processes and protocols that provide equivalent security assurance. The corporate payment channel must implement strong access controls ensuring that only authorised individuals within the corporate entity can initiate or approve payments. Misconfigured corporate payment entitlements represent a significant fraud vector in business payment APIs.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-287"},
			Tags:        []string{"authentication", "access-control"},
			References:  ref("Article 17"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "ART-19",
			Title:       "Dedicated Interface",
			Family:      "Dedicated Interface",
			Description: "Payment service providers that operate a dedicated interface for third-party payment service providers (TPPs) must ensure that the interface provides at least the same level of availability and performance as the interface made available to payment service users. Access to the dedicated interface must be restricted to registered and authorised TPPs and must be protected by strong authentication mechanisms. Insecure or unavailable dedicated interfaces violate open banking obligations and create systemic access-control risks.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-284", "CWE-287"},
			Tags:        []string{"access-control", "authentication"},
			References:  ref("Article 19"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "ART-20",
			Title:       "Contingency Measures for Dedicated Interface",
			Family:      "Dedicated Interface",
			Description: "Where the dedicated interface experiences technical difficulties or an unplanned outage, payment service providers must have contingency measures in place to ensure continuity of access for TPPs without requiring fallback to the customer-facing interface. Contingency access must be subject to equivalent access controls and must not expose customer data beyond what is necessary for the payment service being provided. Poorly designed fallback mechanisms can inadvertently bypass the access-control model of the dedicated interface.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-284"},
			Tags:        []string{"access-control", "network"},
			References:  ref("Article 20"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "ART-21",
			Title:       "Transparency",
			Family:      "Dedicated Interface",
			Description: "Payment service providers must publish statistics on the availability and performance of their dedicated interface on a quarterly basis to enable TPPs and competent authorities to assess compliance with service level obligations. Transparency reporting must include data on uptime, response times, and the number of successful and failed transaction attempts. Accurate and timely public reporting supports the accountability framework for open banking infrastructure.",
			Level:       "standard",
			RelatedCWEs: []string{},
			Tags:        []string{"governance"},
			References:  ref("Article 21"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "ART-22",
			Title:       "Communication Standards Security",
			Family:      "Communication Security",
			Description: "All communication between payment service providers, TPPs, and payment service users must be secured using open, widely accepted standards such as TLS with current cipher suites, and certificates must be validated to prevent man-in-the-middle attacks. Payment APIs must reject connections that do not meet the minimum protocol version and cipher requirements to prevent downgrade attacks. Failure to validate certificates (CWE-295) or transmitting sensitive data in cleartext (CWE-319) directly undermines the confidentiality and integrity of payment messages.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-295", "CWE-319"},
			Tags:        []string{"cryptography", "network"},
			References:  ref("Article 22"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "ART-25",
			Title:       "Identification of Payment Service Providers",
			Family:      "Communication Security",
			Description: "Payment service providers and TPPs must use qualified certificates for website authentication or electronic seals, as defined under the eIDAS Regulation, to establish mutual trust and non-repudiation in API communications. Certificate validation must be performed on every connection attempt, and revoked or expired certificates must be rejected immediately to prevent impersonation attacks. Failure to verify counterparty identity enables fraudulent actors to intercept or inject payment instructions.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-295", "CWE-287"},
			Tags:        []string{"authentication", "cryptography"},
			References:  ref("Article 25"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "ART-26",
			Title:       "Traceability",
			Family:      "Audit and Monitoring",
			Description: "Payment service providers must maintain audit logs that allow all payment transactions and authentication events to be fully traced from initiation to settlement, including the identity of the initiating party and the channel used. Log records must be tamper-evident and retained for the minimum period required by applicable law to support fraud investigations and regulatory enquiries. Absence of adequate traceability (CWE-778) impedes forensic analysis and regulatory supervision of payment fraud incidents.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-778"},
			Tags:        []string{"logging"},
			References:  ref("Article 26"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "ART-27",
			Title:       "Logging",
			Family:      "Audit and Monitoring",
			Description: "Payment service providers must implement comprehensive logging of all authentication attempts, access events, and payment transactions, capturing sufficient context to detect and investigate security incidents. Log data must be protected against unauthorised access and accidental disclosure, ensuring that sensitive authentication details are masked or excluded from log output. Insufficient logging (CWE-778) combined with accidental exposure of credentials in logs (CWE-532) represents a dual risk to both detection capability and data confidentiality.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-778", "CWE-532"},
			Tags:        []string{"logging"},
			References:  ref("Article 27"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "ART-28",
			Title:       "Monitoring",
			Family:      "Audit and Monitoring",
			Description: "Payment service providers must implement real-time monitoring of their payment and authentication infrastructure to detect anomalous behaviour, fraud patterns, and security incidents in a timely manner. Monitoring systems must generate alerts for threshold breaches and must be integrated with an incident response process that enables prompt investigation and containment. Continuous monitoring is a governance obligation that underpins both fraud prevention and regulatory reporting capabilities.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-778"},
			Tags:        []string{"logging", "governance"},
			References:  ref("Article 28"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "ART-29",
			Title:       "Exemption Based on Transaction Risk Analysis",
			Family:      "Exemptions",
			Description: "Payment service providers applying the TRA-based SCA exemption must demonstrate compliance with the reference fraud rates specified in the regulation for the relevant transaction value band and must cease applying the exemption immediately if their fraud rate exceeds the applicable threshold. The TRA model must incorporate a broad set of risk indicators and must be subject to regular independent review to ensure its continued effectiveness. Governance of the TRA exemption is critical to preventing its misuse as a mechanism to reduce friction at the expense of security.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-693"},
			Tags:        []string{"governance"},
			References:  ref("Article 29"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "ART-34",
			Title:       "Audit",
			Family:      "Audit and Monitoring",
			Description: "Payment service providers must subject their security measures, including SCA implementations and dedicated interfaces, to regular independent audits to verify compliance with the RTS requirements. Audit findings must be documented and tracked to resolution, and the audit trail must be retained to demonstrate ongoing compliance to competent authorities. Inadequate audit logging (CWE-778) compromises the ability to evidence regulatory compliance and identify systemic weaknesses in the payment security architecture.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-778"},
			Tags:        []string{"logging", "governance"},
			References:  ref("Article 34"),
		},
	}
}
