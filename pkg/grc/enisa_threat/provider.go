package enisa_threat

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/shift/enrichment-engine/pkg/grc"
	"github.com/shift/enrichment-engine/pkg/storage"
)

const (
	FrameworkID = "ENISA_ETL_2024"
)

var CatalogURL = "https://www.enisa.europa.eu/publications/enisa-threat-landscape-2024"

// Provider fetches and parses ENISA Threat Landscape (ETL) taxonomy data.
type Provider struct {
	store  storage.Backend
	logger *slog.Logger
}

// New creates a new ENISA Threat Landscape provider.
func New(store storage.Backend, logger *slog.Logger) *Provider {
	return &Provider{
		store:  store,
		logger: logger,
	}
}

// Name returns the provider identifier.
func (p *Provider) Name() string {
	return "enisa_threat"
}

// Run fetches the ENISA threat taxonomy, parses threat categories, and writes them to storage.
func (p *Provider) Run(ctx context.Context) (int, error) {
	p.logger.Info("fetching ENISA Threat Landscape taxonomy", "url", CatalogURL)

	f, err := os.CreateTemp("", "enisa_threat_landscape_*.json")
	if err != nil {
		return 0, fmt.Errorf("create temp file: %w", err)
	}
	destPath := f.Name()
	f.Close()
	defer os.Remove(destPath)
	if err := p.download(ctx, CatalogURL, destPath); err != nil {
		p.logger.Warn("download failed, falling back to embedded taxonomy", "error", err)
		controls := p.generateEmbeddedTaxonomy()
		return p.writeControls(ctx, controls)
	}

	controls, err := p.parse(destPath)
	if err != nil {
		p.logger.Warn("parse failed, falling back to embedded taxonomy", "error", err)
		controls = p.generateEmbeddedTaxonomy()
	}

	return p.writeControls(ctx, controls)
}

func (p *Provider) download(ctx context.Context, url, dest string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("%s download: %w", p.Name(), err)
	}

	resp, err := grc.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("%s download: %w", p.Name(), err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s download: unexpected status %d", p.Name(), resp.StatusCode)
	}

	f, err := os.Create(dest)
	if err != nil {
		return fmt.Errorf("%s download: %w", p.Name(), err)
	}
	defer f.Close()

	if _, err = io.Copy(f, resp.Body); err != nil {
		return fmt.Errorf("%s download: %w", p.Name(), err)
	}
	return nil
}

// enisaCatalog represents the ENISA threat landscape JSON structure.
type enisaCatalog struct {
	ThreatCategories []enisaCategory `json:"threat_categories,omitempty"`
	Categories       []enisaCategory `json:"categories,omitempty"`
	Threats          []enisaCategory `json:"threats,omitempty"`
}

type enisaCategory struct {
	ID          string           `json:"id"`
	Name        string           `json:"name"`
	Title       string           `json:"title"`
	Family      string           `json:"family,omitempty"`
	Parent      string           `json:"parent,omitempty"`
	Description string           `json:"description"`
	Severity    string           `json:"severity,omitempty"`
	Level       string           `json:"level,omitempty"`
	Actors      []string         `json:"threat_actors,omitempty"`
	Vectors     []string         `json:"attack_vectors,omitempty"`
	CVEs        []string         `json:"related_cves,omitempty"`
	References  []enisaReference `json:"references,omitempty"`
}

type enisaReference struct {
	Source  string `json:"source,omitempty"`
	URL     string `json:"url,omitempty"`
	Section string `json:"section,omitempty"`
}

func (p *Provider) parse(path string) ([]grc.Control, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("read catalog: %w", err)
	}

	var catalog enisaCatalog
	if err := json.Unmarshal(data, &catalog); err != nil {
		return nil, fmt.Errorf("decode ENISA catalog: %w", err)
	}

	var controls []grc.Control

	for _, cat := range catalog.ThreatCategories {
		controls = append(controls, p.buildControl(cat))
	}
	for _, cat := range catalog.Categories {
		controls = append(controls, p.buildControl(cat))
	}
	for _, cat := range catalog.Threats {
		controls = append(controls, p.buildControl(cat))
	}

	return controls, nil
}

func (p *Provider) buildControl(cat enisaCategory) grc.Control {
	controlID := cat.ID
	if controlID == "" {
		controlID = strings.ToUpper(strings.ReplaceAll(cat.Name, " ", "_"))
	}

	title := cat.Title
	if title == "" {
		title = cat.Name
	}

	family := cat.Family
	if family == "" {
		family = cat.Parent
	}

	level := p.mapLevel(cat.Severity, cat.Level)

	var references []grc.Reference
	for _, ref := range cat.References {
		references = append(references, grc.Reference{
			Source:  ref.Source,
			URL:     ref.URL,
			Section: ref.Section,
		})
	}

	description := cat.Description
	if len(cat.Actors) > 0 {
		description += "\n\nThreat Actors: " + strings.Join(cat.Actors, ", ")
	}
	if len(cat.Vectors) > 0 {
		description += "\n\nAttack Vectors: " + strings.Join(cat.Vectors, ", ")
	}

	return grc.Control{
		Framework:   FrameworkID,
		ControlID:   controlID,
		Title:       title,
		Family:      family,
		Description: description,
		Level:       level,
		RelatedCVEs: cat.CVEs,
		References:  references,
	}
}

func (p *Provider) mapLevel(severity, level string) string {
	switch strings.ToLower(severity) {
	case "critical", "extreme":
		return "critical"
	case "high", "severe":
		return "high"
	case "medium", "moderate":
		return "standard"
	case "low", "minor":
		return "basic"
	}

	switch strings.ToLower(level) {
	case "critical", "extreme":
		return "critical"
	case "high", "severe":
		return "high"
	case "medium", "moderate":
		return "standard"
	case "low", "minor":
		return "basic"
	}

	return "standard"
}

func (p *Provider) writeControls(ctx context.Context, controls []grc.Control) (int, error) {
	p.logger.Info("parsed ENISA threat taxonomy", "count", len(controls))

	count := 0
	for _, ctrl := range controls {
		id := fmt.Sprintf("%s/%s", FrameworkID, ctrl.ControlID)
		if err := p.store.WriteControl(ctx, id, ctrl); err != nil {
			p.logger.Warn("failed to write control", "id", id, "error", err)
			continue
		}
		count++
	}

	p.logger.Info("wrote ENISA threat controls to storage", "count", count)
	return count, nil
}

func (p *Provider) generateEmbeddedTaxonomy() []grc.Control {
	categories := []enisaCategory{
		{
			ID:          "MALWARE",
			Name:        "Malware",
			Title:       "Malware Attacks",
			Family:      "Technical Threats",
			Description: "Malicious software designed to infiltrate, damage, or disrupt computer systems, networks, and devices. Includes viruses, worms, trojans, spyware, adware, and fileless malware variants that exploit system vulnerabilities or user behavior to gain unauthorized access.",
			Severity:    "high",
			Actors:      []string{"Cybercriminals", "Nation-state actors", "Hacktivists"},
			Vectors:     []string{"Email attachments", "Drive-by downloads", "Removable media", "Exploit kits"},
			CVEs:        []string{"CVE-2024-21762", "CVE-2023-44487"},
			References: []enisaReference{
				{Source: "ENISA", URL: "https://www.enisa.europa.eu/topics/threat-risk-management/threats-and-trends/enisa-threat-landscape", Section: "ETL 2024 - Malware"},
			},
		},
		{
			ID:          "RANSOMWARE",
			Name:        "Ransomware",
			Title:       "Ransomware Attacks",
			Family:      "Technical Threats",
			Description: "A specialized form of malware that encrypts victim data and demands payment for decryption keys. Modern ransomware operations employ double and triple extortion tactics, including data theft, DDoS threats, and harassment of customers and partners. Ransomware-as-a-Service (RaaS) has lowered the barrier to entry for threat actors.",
			Severity:    "critical",
			Actors:      []string{"RaaS affiliates", "Organized cybercrime groups", "Nation-state proxies"},
			Vectors:     []string{"Phishing emails", "RDP exploitation", "Supply chain compromise", "Vulnerability exploitation"},
			CVEs:        []string{"CVE-2024-3400", "CVE-2023-4966", "CVE-2023-28252"},
			References: []enisaReference{
				{Source: "ENISA", URL: "https://www.enisa.europa.eu/topics/threat-risk-management/threats-and-trends/enisa-threat-landscape", Section: "ETL 2024 - Ransomware"},
			},
		},
		{
			ID:          "SOCIAL_ENGINEERING",
			Name:        "Social Engineering",
			Title:       "Social Engineering Attacks",
			Family:      "Human Factor Threats",
			Description: "Psychological manipulation techniques used to deceive individuals into revealing sensitive information, performing actions, or bypassing security controls. Includes phishing, spear-phishing, whaling, vishing, smishing, and business email compromise (BEC) campaigns targeting organizational and individual victims.",
			Severity:    "high",
			Actors:      []string{"Cybercriminals", "Fraudsters", "Insider threats", "Nation-state actors"},
			Vectors:     []string{"Phishing emails", "SMS messages", "Voice calls", "Social media impersonation", "Deepfake audio/video"},
			CVEs:        []string{},
			References: []enisaReference{
				{Source: "ENISA", URL: "https://www.enisa.europa.eu/topics/threat-risk-management/threats-and-trends/enisa-threat-landscape", Section: "ETL 2024 - Social Engineering"},
			},
		},
		{
			ID:          "SUPPLY_CHAIN",
			Name:        "Supply Chain Attacks",
			Title:       "Supply Chain Compromise",
			Family:      "Technical Threats",
			Description: "Attacks targeting third-party vendors, software suppliers, and service providers to gain indirect access to primary targets. Includes software supply chain attacks (compromised updates, dependency confusion), hardware supply chain attacks, and managed service provider (MSP) compromises that cascade across multiple downstream organizations.",
			Severity:    "critical",
			Actors:      []string{"Nation-state actors", "Advanced persistent threats", "Organized cybercrime"},
			Vectors:     []string{"Compromised software updates", "Dependency injection", "Third-party credential theft", "MSP platform exploitation"},
			CVEs:        []string{"CVE-2024-3094", "CVE-2023-42793"},
			References: []enisaReference{
				{Source: "ENISA", URL: "https://www.enisa.europa.eu/topics/threat-risk-management/threats-and-trends/enisa-threat-landscape", Section: "ETL 2024 - Supply Chain"},
			},
		},
		{
			ID:          "DDOS",
			Name:        "DDoS",
			Title:       "Distributed Denial of Service",
			Family:      "Technical Threats",
			Description: "Coordinated attacks designed to overwhelm target systems, networks, or services with excessive traffic, rendering them unavailable to legitimate users. Modern DDoS attacks leverage botnets of compromised IoT devices, cloud infrastructure abuse, and application-layer attacks targeting specific service functions. Volumetric, protocol, and application-layer attack vectors are commonly combined.",
			Severity:    "high",
			Actors:      []string{"Hacktivists", "Cybercriminals", "Nation-state actors", "Stresser/booter services"},
			Vectors:     []string{"Botnet amplification", "DNS reflection", "HTTP flood", "Slowloris", "IoT botnets"},
			CVEs:        []string{"CVE-2024-21762"},
			References: []enisaReference{
				{Source: "ENISA", URL: "https://www.enisa.europa.eu/topics/threat-risk-management/threats-and-trends/enisa-threat-landscape", Section: "ETL 2024 - DDoS"},
			},
		},
		{
			ID:          "DATA_BREACH",
			Name:        "Data Breach",
			Title:       "Data Breach and Exfiltration",
			Family:      "Human Factor Threats",
			Description: "Unauthorized access, acquisition, or disclosure of sensitive or protected data. Includes breaches resulting from external intrusion, insider threats, misconfigurations, lost or stolen devices, and accidental exposure. Data breaches trigger regulatory notification obligations under GDPR, NIS2, and sector-specific frameworks.",
			Severity:    "critical",
			Actors:      []string{"Cybercriminals", "Insider threats", "Nation-state actors", "Accidental actors"},
			Vectors:     []string{"SQL injection", "Misconfigured cloud storage", "Credential stuffing", "Physical theft", "Insider abuse"},
			CVEs:        []string{"CVE-2023-4966", "CVE-2024-1709"},
			References: []enisaReference{
				{Source: "ENISA", URL: "https://www.enisa.europa.eu/topics/threat-risk-management/threats-and-trends/enisa-threat-landscape", Section: "ETL 2024 - Data Breaches"},
			},
		},
		{
			ID:          "WEB_APPLICATION",
			Name:        "Web Application Attacks",
			Title:       "Web Application Attacks",
			Family:      "Technical Threats",
			Description: "Exploitation of vulnerabilities in web applications and APIs to gain unauthorized access, manipulate data, or disrupt services. Includes injection attacks (SQLi, XSS, command injection), broken authentication, insecure direct object references, server-side request forgery (SSRF), and API-specific vulnerabilities identified in OWASP Top 10.",
			Severity:    "high",
			Actors:      []string{"Cybercriminals", "Bug bounty hunters", "Hacktivists", "Automated scanners"},
			Vectors:     []string{"SQL injection", "Cross-site scripting", "SSRF", "API abuse", "Authentication bypass"},
			CVEs:        []string{"CVE-2024-21762", "CVE-2023-44487"},
			References: []enisaReference{
				{Source: "ENISA", URL: "https://www.enisa.europa.eu/topics/threat-risk-management/threats-and-trends/enisa-threat-landscape", Section: "ETL 2024 - Web Application Attacks"},
			},
		},
		{
			ID:          "IOT_THREATS",
			Name:        "IoT Threats",
			Title:       "Internet of Things Threats",
			Family:      "Technical Threats",
			Description: "Threats targeting Internet of Things devices and ecosystems including smart home devices, industrial IoT (IIoT), medical devices, and connected vehicles. IoT devices often lack security-by-design, have weak authentication, unpatched firmware, and insecure communication protocols, making them attractive targets for botnet recruitment and lateral movement.",
			Severity:    "high",
			Actors:      []string{"Botnet operators", "Cybercriminals", "Nation-state actors"},
			Vectors:     []string{"Default credentials", "Unpatched firmware", "Insecure protocols", "Physical access", "OTA update compromise"},
			CVEs:        []string{"CVE-2024-21762", "CVE-2023-28252"},
			References: []enisaReference{
				{Source: "ENISA", URL: "https://www.enisa.europa.eu/topics/threat-risk-management/threats-and-trends/enisa-threat-landscape", Section: "ETL 2024 - IoT Threats"},
			},
		},
		{
			ID:          "CLOUD_SECURITY",
			Name:        "Cloud Security Threats",
			Title:       "Cloud Security Threats",
			Family:      "Technical Threats",
			Description: "Threats targeting cloud infrastructure, platforms, and services including IaaS, PaaS, and SaaS deployments. Encompasses misconfigurations, insecure APIs, account hijacking, shared responsibility model gaps, container escape vulnerabilities, serverless function exploitation, and multi-tenant isolation failures that expose organizational data and workloads.",
			Severity:    "high",
			Actors:      []string{"Cybercriminals", "Insider threats", "Nation-state actors", "Cloud-native threat actors"},
			Vectors:     []string{"Misconfigured S3 buckets", "Compromised IAM credentials", "Container escape", "Serverless injection", "Metadata API abuse"},
			CVEs:        []string{"CVE-2024-3400", "CVE-2023-42793"},
			References: []enisaReference{
				{Source: "ENISA", URL: "https://www.enisa.europa.eu/topics/threat-risk-management/threats-and-trends/enisa-threat-landscape", Section: "ETL 2024 - Cloud Security"},
			},
		},
		{
			ID:          "PHISHING",
			Name:        "Phishing",
			Title:       "Phishing Campaigns",
			Family:      "Human Factor Threats",
			Description: "Deceptive communications designed to trick recipients into revealing credentials, downloading malware, or transferring funds. Includes mass phishing, spear-phishing (targeted at specific individuals), whaling (targeting executives), and clone phishing. Modern campaigns leverage AI-generated content, brand impersonation, and infrastructure-as-a-service platforms to evade detection.",
			Severity:    "high",
			Actors:      []string{"Cybercriminals", "Ransomware operators", "BEC fraudsters", "Nation-state actors"},
			Vectors:     []string{"Email phishing", "SMS phishing (smishing)", "Voice phishing (vishing)", "Social media phishing", "QR code phishing (quishing)"},
			CVEs:        []string{},
			References: []enisaReference{
				{Source: "ENISA", URL: "https://www.enisa.europa.eu/topics/threat-risk-management/threats-and-trends/enisa-threat-landscape", Section: "ETL 2024 - Phishing"},
			},
		},
		{
			ID:          "INSIDER_THREAT",
			Name:        "Insider Threat",
			Title:       "Insider Threats",
			Family:      "Human Factor Threats",
			Description: "Threats originating from individuals within the organization who have authorized access to systems, data, or facilities. Includes malicious insiders (disgruntled employees, recruited staff), negligent insiders (unintentional policy violations, misconfigurations), and compromised insiders (credential theft, coercion). Insider threats are particularly challenging to detect due to legitimate access patterns.",
			Severity:    "high",
			Actors:      []string{"Disgruntled employees", "Negligent staff", "Compromised accounts", "Recruited insiders"},
			Vectors:     []string{"Privilege abuse", "Data exfiltration", "Sabotage", "Credential sharing", "Policy circumvention"},
			CVEs:        []string{},
			References: []enisaReference{
				{Source: "ENISA", URL: "https://www.enisa.europa.eu/topics/threat-risk-management/threats-and-trends/enisa-threat-landscape", Section: "ETL 2024 - Insider Threats"},
			},
		},
		{
			ID:          "APT",
			Name:        "Advanced Persistent Threat",
			Title:       "Advanced Persistent Threats",
			Family:      "Technical Threats",
			Description: "Sophisticated, long-term cyber operations typically conducted by nation-state actors or well-resourced groups. APTs employ multiple attack phases including initial reconnaissance, weaponization, delivery, exploitation, installation, command-and-control, and actions on objectives. They utilize zero-day exploits, custom malware, and living-off-the-land techniques to maintain persistent access while evading detection.",
			Severity:    "critical",
			Actors:      []string{"Nation-state actors", "State-sponsored groups", "Advanced cybercrime syndicates"},
			Vectors:     []string{"Zero-day exploits", "Watering hole attacks", "Spear-phishing", "Supply chain compromise", "Living-off-the-land"},
			CVEs:        []string{"CVE-2024-21762", "CVE-2023-44487", "CVE-2023-4966"},
			References: []enisaReference{
				{Source: "ENISA", URL: "https://www.enisa.europa.eu/topics/threat-risk-management/threats-and-trends/enisa-threat-landscape", Section: "ETL 2024 - APT"},
			},
		},
	}

	var controls []grc.Control
	for _, cat := range categories {
		controls = append(controls, p.buildControl(cat))
	}

	return controls
}
