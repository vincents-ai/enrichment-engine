package misp

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/shift/enrichment-engine/pkg/grc"
	"github.com/shift/enrichment-engine/pkg/storage"
)

const (
	FrameworkID = "MISP_THREAT_V2"
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
	return "misp"
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
		p.logger.Info("wrote MISP controls", "count", count)
	}
	return count, nil
}

func embeddedControls() []grc.Control {
	return []grc.Control{
		{
			Framework: FrameworkID, ControlID: "MISP-IOC-1.1",
			Title: "IPv4/IPv6 Address IOC Collection", Family: "IoC Categories",
			Description:            "Collect and validate IPv4 and IPv6 address indicators of compromise from MISP events. Ensure IP addresses are enriched with geolocation, ASN, and reputation data before ingestion into security systems.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-20"},
			References:             []grc.Reference{{Source: "MISP Taxonomy", URL: "https://www.misp-project.org/taxonomies.html", Section: "MISP Object Template: ip-port"}},
			ImplementationGuidance: "Configure MISP to auto-enrich IP addresses via free APIs (AbuseIPDB, VirusTotal). Validate CIDR ranges. Deduplicate across feeds. Apply confidence scoring based on source reliability.",
			AssessmentMethods:      []string{"MISP Event Audit", "IOC Quality Metrics", "Enrichment Pipeline Review"},
		},
		{
			Framework: FrameworkID, ControlID: "MISP-IOC-1.2",
			Title: "Domain IOC Collection", Family: "IoC Categories",
			Description:            "Collect and validate domain indicators of compromise from MISP events. Domains should be enriched with WHOIS, DNS resolution, passive DNS, and certificate transparency data.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-20"},
			References:             []grc.Reference{{Source: "MISP Taxonomy", URL: "https://www.misp-project.org/taxonomies.html", Section: "MISP Object Template: domain-ip"}},
			ImplementationGuidance: "Configure MISP domain enrichment modules. Apply FQDN normalization. Track newly registered domains. Cross-reference with DGA detection algorithms.",
			AssessmentMethods:      []string{"Domain IOC Quality Review", "Enrichment Coverage Audit", "Manual Review"},
		},
		{
			Framework: FrameworkID, ControlID: "MISP-IOC-1.3",
			Title: "URL IOC Collection", Family: "IoC Categories",
			Description:            "Collect and validate URL indicators of compromise from MISP events. URLs should be enriched with HTTP response analysis, screenshot capture, and content hash verification.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-20"},
			References:             []grc.Reference{{Source: "MISP Taxonomy", URL: "https://www.misp-project.org/taxonomies.html", Section: "MISP Object Template: url"}},
			ImplementationGuidance: "Configure MISP URL enrichment (VirusTotal URL scan, URLhaus, PhishTank). Capture screenshots of malicious URLs. Normalize URL encoding. Apply takedown tracking.",
			AssessmentMethods:      []string{"URL IOC Quality Review", "Screenshot Archive Audit", "Manual Review"},
		},
		{
			Framework: FrameworkID, ControlID: "MISP-IOC-1.4",
			Title: "File Hash IOC Collection", Family: "IoC Categories",
			Description:            "Collect and validate file hash indicators (MD5, SHA1, SHA256) from MISP events. File hashes should be enriched with AV scan results, first/last seen dates, and file metadata.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-20"},
			References:             []grc.Reference{{Source: "MISP Taxonomy", URL: "https://www.misp-project.org/taxonomies.html", Section: "MISP Object Template: file"}},
			ImplementationGuidance: "Prioritize SHA256 hashes. Enrich via VirusTotal, MalwareBazaar, Hybrid Analysis. Track file hash relationships. Deprecate MD5-only indicators where SHA256 is available.",
			AssessmentMethods:      []string{"Hash IOC Quality Review", "AV Detection Rate Analysis", "Manual Review"},
		},
		{
			Framework: FrameworkID, ControlID: "MISP-IOC-1.5",
			Title: "Email Address IOC Collection", Family: "IoC Categories",
			Description:            "Collect and validate email address indicators from MISP events including sender addresses, reply-to addresses, and compromised account indicators.",
			Level:                  "medium",
			RelatedCWEs:            []string{"CWE-20"},
			References:             []grc.Reference{{Source: "MISP Taxonomy", URL: "https://www.misp-project.org/taxonomies.html", Section: "MISP Object Template: email"}},
			ImplementationGuidance: "Enrich email addresses with Have I Been Pwned, domain reputation. Track compromised account indicators separately from threat actor emails. Normalize email case.",
			AssessmentMethods:      []string{"Email IOC Quality Review", "Enrichment Coverage Audit", "Manual Review"},
		},
		{
			Framework: FrameworkID, ControlID: "MISP-IOC-1.6",
			Title: "Windows Registry Key IOC Collection", Family: "IoC Categories",
			Description:            "Collect Windows registry key indicators of compromise from MISP events related to malware persistence, privilege escalation, and configuration changes.",
			Level:                  "medium",
			RelatedCWEs:            []string{"CWE-20"},
			References:             []grc.Reference{{Source: "MISP Taxonomy", URL: "https://www.misp-project.org/taxonomies.html", Section: "MISP Object Template: registry-key"}},
			ImplementationGuidance: "Normalize registry key paths to HKLM/HKCU format. Track persistence locations (Run keys, Services, Scheduled Tasks). Correlate with MITRE ATT&CK techniques.",
			AssessmentMethods:      []string{"Registry IOC Quality Review", "ATT&CK Mapping Audit", "Manual Review"},
		},
		{
			Framework: FrameworkID, ControlID: "MISP-IOC-1.7",
			Title: "File Name and Mutex IOC Collection", Family: "IoC Categories",
			Description:            "Collect file name, mutex name, named pipe, and user-agent string indicators from MISP events for malware behavioral analysis and detection rule generation.",
			Level:                  "medium",
			RelatedCWEs:            []string{"CWE-20"},
			References:             []grc.Reference{{Source: "MISP Taxonomy", URL: "https://www.misp-project.org/taxonomies.html", Section: "MISP Object Templates"}},
			ImplementationGuidance: "Normalize file paths across OS platforms. Track mutex naming conventions per malware family. Monitor named pipe patterns for C2 communication. Extract user-agent strings from HTTP-based malware.",
			AssessmentMethods:      []string{"Behavioral IOC Quality Review", "Detection Rule Coverage", "Manual Review"},
		},
		{
			Framework: FrameworkID, ControlID: "MISP-THREAT-2.1",
			Title: "Ransomware Threat Tracking", Family: "Threat Types",
			Description:            "Track ransomware threat intelligence in MISP including ransomware families, attack vectors, encryption methods, ransom demands, and indicators associated with active ransomware campaigns.",
			Level:                  "critical",
			RelatedCWEs:            []string{"CWE-20"},
			References:             []grc.Reference{{Source: "MISP Galaxy", URL: "https://www.misp-project.org/galaxy.html", Section: "Ransomware Galaxy"}},
			ImplementationGuidance: "Create MISP galaxy clusters for ransomware families. Tag events with ransomware-specific taxonomy. Track ransom payment addresses and negotiation emails. Correlate with initial access indicators.",
			AssessmentMethods:      []string{"Ransomware Event Audit", "Galaxy Cluster Completeness", "Manual Review"},
		},
		{
			Framework: FrameworkID, ControlID: "MISP-THREAT-2.2",
			Title: "Phishing Threat Tracking", Family: "Threat Types",
			Description:            "Track phishing threat intelligence including phishing kit identifiers, credential harvesting URLs, phishing email campaigns, and brand abuse indicators.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-20"},
			References:             []grc.Reference{{Source: "MISP Galaxy", URL: "https://www.misp-project.org/galaxy.html", Section: "Phishing Galaxy"}},
			ImplementationGuidance: "Integrate PhishTank and OpenPhish feeds. Track phishing kit versions and infrastructure. Monitor brand abuse. Create correlation rules between phishing indicators and credential stuffing.",
			AssessmentMethods:      []string{"Phishing Feed Quality Review", "Brand Monitoring Audit", "Manual Review"},
		},
		{
			Framework: FrameworkID, ControlID: "MISP-THREAT-2.3",
			Title: "APT Group Tracking", Family: "Threat Types",
			Description:            "Track Advanced Persistent Threat (APT) group activity in MISP using threat actor galaxies, mapping observed TTPs to MITRE ATT&CK framework, and tracking campaign attribution.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-20"},
			References:             []grc.Reference{{Source: "MISP Galaxy", URL: "https://www.misp-project.org/galaxy.html", Section: "Threat Actor Galaxy"}, {Source: "MITRE ATT&CK", URL: "https://attack.mitre.org/", Section: "Threat Groups"}},
			ImplementationGuidance: "Use MISP Threat Actor and Attack Pattern galaxies. Map all APT events to ATT&CK techniques. Track tooling, infrastructure, and targeting patterns per group. Cross-reference with national CSIRT advisories.",
			AssessmentMethods:      []string{"APT Event Audit", "ATT&CK Mapping Coverage", "Attribution Quality Review"},
		},
		{
			Framework: FrameworkID, ControlID: "MISP-THREAT-2.4",
			Title: "Supply Chain Attack Tracking", Family: "Threat Types",
			Description:            "Track supply chain threat intelligence including compromised software components, malicious package indicators, build system compromises, and affected downstream products.",
			Level:                  "critical",
			RelatedCWEs:            []string{"CWE-20", "CWE-829", "CWE-1357"},
			References:             []grc.Reference{{Source: "MISP Galaxy", URL: "https://www.misp-project.org/galaxy.html", Section: "Tool Galaxy"}},
			ImplementationGuidance: "Track software supply chain events with SBOM correlations. Monitor package registries (npm, PyPI, Maven) for malicious packages. Create supply chain-specific tagging taxonomy.",
			AssessmentMethods:      []string{"Supply Chain Event Audit", "SBOM Correlation Review", "Package Registry Monitoring"},
		},
		{
			Framework: FrameworkID, ControlID: "MISP-EU-3.1",
			Title: "CERT-EU Advisory Integration", Family: "EU-Specific Feeds",
			Description:            "Integrate CERT-EU advisory feeds into MISP for EU institutional threat intelligence sharing, including alerts on active threats targeting EU entities and cross-border campaigns.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-20"},
			References:             []grc.Reference{{Source: "CERT-EU", URL: "https://cert.europa.eu/", Section: "Advisories"}},
			ImplementationGuidance: "Configure MISP feed for CERT-EU advisories. Set up automated event creation for high-severity advisories. Map to internal taxonomy. Enable bidirectional sharing with national CSIRTs.",
			AssessmentMethods:      []string{"Feed Sync Status", "Advisory Coverage Review", "Manual Review"},
		},
		{
			Framework: FrameworkID, ControlID: "MISP-EU-3.2",
			Title: "ENISA Threat Campaign Tracking", Family: "EU-Specific Feeds",
			Description:            "Track ENISA threat landscape reports and campaign intelligence relevant to EU cybersecurity, including the ENISA Threat Landscape report findings and EU-specific threat campaigns.",
			Level:                  "medium",
			RelatedCWEs:            []string{"CWE-20"},
			References:             []grc.Reference{{Source: "ENISA", URL: "https://www.enisa.europa.eu/topics/threat-risk-management", Section: "Threat Landscape"}},
			ImplementationGuidance: "Incorporate ENISA threat landscape findings into MISP taxonomies. Track EU-specific campaigns targeting critical infrastructure. Share indicators via EU CSIRT network.",
			AssessmentMethods:      []string{"ENISA Integration Review", "Campaign Tracking Coverage", "Manual Review"},
		},
		{
			Framework: FrameworkID, ControlID: "MISP-EU-3.3",
			Title: "National CSIRT Feed Integration", Family: "EU-Specific Feeds",
			Description:            "Integrate national CSIRT feeds from EU member states into MISP for cross-border threat intelligence sharing under the NIS2 Directive cooperation framework.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-20"},
			References:             []grc.Reference{{Source: "NIS2 Directive", URL: "https://digital-strategy.ec.europa.eu/en/policies/nis2-directive", Section: "CSIRT Cooperation"}},
			ImplementationGuidance: "Configure MISP synchronisation with national CSIRTs. Use trusted circles for controlled sharing. Implement EU-CSIRT taxonomy for classification. Track sharing group memberships.",
			AssessmentMethods:      []string{"CSIRT Feed Sync Status", "Sharing Group Audit", "NIS2 Compliance Review"},
		},
		{
			Framework: FrameworkID, ControlID: "MISP-FEED-2.1",
			Title: "Feed Management and Validation", Family: "Operational",
			Description:            "Implement structured feed management for all MISP threat intelligence feeds including automated validation, deduplication, quality scoring, and feed health monitoring.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-20", "CWE-345"},
			References:             []grc.Reference{{Source: "MISP Documentation", URL: "https://www.misp-project.org/data-feeds.html", Section: "Feed Management"}},
			ImplementationGuidance: "Configure feed pull intervals per priority. Validate all incoming feed data against MISP schema. Implement feed quality scoring. Alert on feed failures. Track feed coverage metrics.",
			AssessmentMethods:      []string{"Feed Health Dashboard", "Quality Score Metrics", "Validation Log Review"},
		},
		{
			Framework: FrameworkID, ControlID: "MISP-FEED-2.2",
			Title: "Sighting Validation and Feedback", Family: "Operational",
			Description:            "Implement sighting validation to confirm IoC observations, including false positive tracking, sighting confidence scoring, and feedback loops to improve indicator quality.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-345"},
			References:             []grc.Reference{{Source: "MISP Documentation", URL: "https://www.misp-project.org/sightings.html", Section: "Sightings"}},
			ImplementationGuidance: "Enable sighting submission from detection systems. Track false positive rates per source. Use sighting data to adjust confidence scores. Create decay rules for unconfirmed indicators.",
			AssessmentMethods:      []string{"Sighting Coverage Metrics", "False Positive Rate Analysis", "Confidence Score Accuracy"},
		},
		{
			Framework: FrameworkID, ControlID: "MISP-TAX-3.1",
			Title: "ADGAL Taxonomy Tagging", Family: "Taxonomy",
			Description:            "Apply the ADGAL (Analytical Data Gathering and Linking) taxonomy for structured tagging of MISP events, enabling consistent classification across threat intelligence sharing communities.",
			Level:                  "medium",
			RelatedCWEs:            []string{"CWE-20"},
			References:             []grc.Reference{{Source: "MISP ADGAL Taxonomy", URL: "https://www.misp-project.org/taxonomies.html#adgal", Section: "ADGAL"}},
			ImplementationGuidance: "Enable ADGAL taxonomy in MISP instance. Train analysts on ADGAL classification. Implement automated tagging rules. Audit taxonomy usage consistency.",
			AssessmentMethods:      []string{"Taxonomy Usage Metrics", "Tagging Consistency Review", "Manual Review"},
		},
		{
			Framework: FrameworkID, ControlID: "MISP-TAX-3.2",
			Title: "EU CSIRT Taxonomy Compliance", Family: "Taxonomy",
			Description:            "Apply the EU CSIRT taxonomy for consistent incident and indicator classification across EU national CSIRTs, supporting NIS2-mandated information sharing requirements.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-20"},
			References:             []grc.Reference{{Source: "MISP EU CSIRT Taxonomy", URL: "https://www.misp-project.org/taxonomies.html#eu-csirt", Section: "EU CSIRT Taxonomy"}},
			ImplementationGuidance: "Enable EU CSIRT taxonomy. Map all incidents to EU CSIRT categories. Ensure shared events comply with EU CSIRT classification standards. Support automated classification.",
			AssessmentMethods:      []string{"EU CSIRT Compliance Audit", "Classification Coverage Review", "Manual Review"},
		},
		{
			Framework: FrameworkID, ControlID: "MISP-TAX-3.3",
			Title: "VERIS Taxonomy Integration", Family: "Taxonomy",
			Description:            "Apply the VERIS (Vocabulary for Event Recording and Incident Sharing) taxonomy for structured incident classification, enabling data-driven analysis of security incidents.",
			Level:                  "medium",
			RelatedCWEs:            []string{"CWE-20"},
			References:             []grc.Reference{{Source: "MISP VERIS Taxonomy", URL: "https://www.misp-project.org/taxonomies.html#veris", Section: "VERIS"}},
			ImplementationGuidance: "Enable VERIS taxonomy in MISP. Map incidents to VERIS A4 (Actions), A5 (Assets), and A6 (Attributes) dimensions. Use for statistical analysis and benchmarking.",
			AssessmentMethods:      []string{"VERIS Classification Audit", "Incident Statistics Review", "Manual Review"},
		},
		{
			Framework: FrameworkID, ControlID: "MISP-OPS-4.1",
			Title: "ZMQ and API Automation", Family: "Operational",
			Description:            "Implement MISP automation via ZeroMQ (ZMQ) for real-time event publishing and the REST API for automated IOC extraction, enabling integration with SIEM, EDR, and SOAR platforms.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-20"},
			References:             []grc.Reference{{Source: "MISP ZMQ Documentation", URL: "https://www.misp-project.org/zmq/", Section: "ZMQ"}, {Source: "MISP API", URL: "https://www.misp-project.org/api/", Section: "REST API"}},
			ImplementationGuidance: "Configure ZMQ for real-time event publishing to SIEM. Implement API-based IOC extraction with authentication. Use MISP modules for automated enrichment. Monitor API usage and rate limits.",
			AssessmentMethods:      []string{"ZMQ Integration Test", "API Authentication Audit", "Automation Pipeline Review"},
		},
		{
			Framework: FrameworkID, ControlID: "MISP-OPS-4.2",
			Title: "Correlation Rules and Detection", Family: "Operational",
			Description:            "Implement MISP correlation rules and automated detection logic to identify related indicators, link disparate events, and generate high-confidence composite indicators.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-20"},
			References:             []grc.Reference{{Source: "MISP Correlation Engine", URL: "https://www.misp-project.org/features.html", Section: "Correlation"}},
			ImplementationGuidance: "Configure MISP correlation engine thresholds. Implement overcorrelation detection. Create composite indicator rules (e.g., IP + domain + hash from same event). Export detection rules to Sigma/YARA.",
			AssessmentMethods:      []string{"Correlation Rule Audit", "False Positive Rate Analysis", "Detection Rule Coverage"},
		},
		{
			Framework: FrameworkID, ControlID: "MISP-OPS-4.3",
			Title: "Sharing Group Management", Family: "Operational",
			Description:            "Manage MISP sharing groups with appropriate access controls, defining who can create, share, and receive threat intelligence based on trust levels and operational needs.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-284", "CWE-285"},
			References:             []grc.Reference{{Source: "MISP Sharing Groups", URL: "https://www.misp-project.org/features.html", Section: "Sharing"}},
			ImplementationGuidance: "Define sharing groups per community and trust level. Implement tiered sharing (TLP). Audit sharing group memberships quarterly. Use sync servers for controlled distribution.",
			AssessmentMethods:      []string{"Sharing Group Audit", "TLP Compliance Review", "Access Control Review"},
		},
		{
			Framework: FrameworkID, ControlID: "MISP-OPS-4.4",
			Title: "MISP Galaxy and Cluster Mapping", Family: "Operational",
			Description:            "Utilize MISP galaxies and clusters for threat actor, tool, and attack pattern mapping, enabling visual correlation between indicators and known threat groups.",
			Level:                  "medium",
			RelatedCWEs:            []string{"CWE-20"},
			References:             []grc.Reference{{Source: "MISP Galaxy", URL: "https://www.misp-project.org/galaxy.html", Section: "Galaxy Clusters"}},
			ImplementationGuidance: "Enable relevant galaxies (threat actors, tools, attack patterns, ransomware). Tag events with galaxy clusters. Use galaxy views for threat landscape analysis. Keep galaxy data up-to-date.",
			AssessmentMethods:      []string{"Galaxy Coverage Review", "Cluster Tagging Consistency", "Visual Analysis Quality"},
		},
		{
			Framework: FrameworkID, ControlID: "MISP-THREAT-2.5",
			Title: "Zero-Day Exploit Tracking", Family: "Threat Types",
			Description:            "Track zero-day exploit intelligence in MISP including newly disclosed vulnerabilities, exploit code availability, active exploitation in the wild, and vendor patch status.",
			Level:                  "critical",
			RelatedCWEs:            []string{"CWE-20"},
			References:             []grc.Reference{{Source: "MISP Galaxy", URL: "https://www.misp-project.org/galaxy.html", Section: "Exploit Galaxy"}, {Source: "CVE/NVD", URL: "https://nvd.nist.gov/", Section: "Vulnerabilities"}},
			ImplementationGuidance: "Create high-priority MISP events for zero-days. Track CVE IDs with exploit indicators. Monitor dark web for exploit availability. Correlate with vendor advisories and patch timelines.",
			AssessmentMethods:      []string{"Zero-Day Event Audit", "CVE Correlation Review", "Exploit Availability Tracking"},
		},
	}
}
