package nis2_implementing_acts

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/shift/enrichment-engine/pkg/storage"
)

const (
	FrameworkID = "NIS2_IMP_ACTS_2024"
	CatalogURL  = ""
)

type Control struct {
	Framework              string      `json:"Framework"`
	ControlID              string      `json:"ControlID"`
	Title                  string      `json:"Title"`
	Family                 string      `json:"Family,omitempty"`
	Description            string      `json:"Description,omitempty"`
	Level                  string      `json:"Level,omitempty"`
	RelatedCWEs            []string    `json:"RelatedCWEs,omitempty"`
	RelatedCVEs            []string    `json:"RelatedCVEs,omitempty"`
	References             []Reference `json:"References,omitempty"`
	ImplementationGuidance string      `json:"ImplementationGuidance,omitempty"`
	AssessmentMethods      []string    `json:"AssessmentMethods,omitempty"`
}

type Reference struct {
	Source  string `json:"source,omitempty"`
	URL     string `json:"url,omitempty"`
	Section string `json:"section,omitempty"`
}

type Provider struct {
	store  storage.Backend
	logger *slog.Logger
}

func New(store storage.Backend, logger *slog.Logger) *Provider {
	return &Provider{
		store:  store,
		logger: logger,
	}
}

func (p *Provider) Name() string {
	return "nis2_implementing_acts"
}

func (p *Provider) Run(ctx context.Context) (int, error) {
	return p.writeEmbeddedControls(ctx)
}

func (p *Provider) writeEmbeddedControls(ctx context.Context) (int, error) {
	p.logger.Info("using embedded NIS2 Implementing Acts controls")

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

	p.logger.Info("wrote embedded NIS2 Implementing Acts controls to storage", "count", count)
	return count, nil
}

func embeddedControls() []Control {
	controls := []Control{}

	sectoralBaselinesAnnexI := []struct {
		id, title, desc, family string
	}{
		{"NIS2IA-SEC-1.1", "Energy sector baseline requirements", "Essential entities in the energy sector shall implement baseline cybersecurity measures covering SCADA/ICS network segmentation, real-time intrusion detection, secure remote access with mandatory MFA, and supply chain security for operational technology components.", "Sectoral Baselines (Annex I)"},
		{"NIS2IA-SEC-1.2", "Transport sector baseline requirements", "Essential entities in the transport sector shall implement cybersecurity measures covering signalling system protection, air traffic management security, maritime AIS/VTM security, and rail signalling communication integrity.", "Sectoral Baselines (Annex I)"},
		{"NIS2IA-SEC-1.3", "Banking sector baseline requirements", "Essential entities in the banking sector shall implement baseline measures covering real-time payment system security, SWIFT messaging integrity, API gateway protection, and continuous transaction monitoring for fraud detection.", "Sectoral Baselines (Annex I)"},
		{"NIS2IA-SEC-1.4", "Financial market infrastructure baseline", "Essential entities operating financial market infrastructure shall implement measures covering trading platform resilience, clearing and settlement system integrity, market data feed security, and cross-border payment system protection.", "Sectoral Baselines (Annex I)"},
		{"NIS2IA-SEC-1.5", "Health sector baseline requirements", "Essential entities in the health sector shall implement baseline measures covering electronic health record protection, medical device cybersecurity, telemedicine platform security, and clinical research data integrity.", "Sectoral Baselines (Annex I)"},
		{"NIS2IA-SEC-1.6", "Digital infrastructure baseline requirements", "Essential entities providing digital infrastructure shall implement measures covering DNS security, internet exchange point resilience, cloud service availability, and content delivery network security.", "Sectoral Baselines (Annex I)"},
		{"NIS2IA-SEC-1.7", "Public administration baseline requirements", "Essential entities in public administration shall implement baseline measures covering citizen data protection, e-government service continuity, cross-border digital service interoperability, and election infrastructure security.", "Sectoral Baselines (Annex I)"},
	}

	sectoralBaselinesAnnexII := []struct {
		id, title, desc, family string
	}{
		{"NIS2IA-SEC-2.1", "Postal and courier services baseline", "Important entities providing postal and courier services shall implement cybersecurity measures covering parcel tracking system integrity, customer data protection, and logistics network resilience.", "Sectoral Baselines (Annex II)"},
		{"NIS2IA-SEC-2.2", "Waste management baseline requirements", "Important entities in waste management shall implement measures covering hazardous waste tracking systems, SCADA security for treatment facilities, and environmental monitoring data integrity.", "Sectoral Baselines (Annex II)"},
		{"NIS2IA-SEC-2.3", "Chemical manufacturing baseline requirements", "Important entities in chemical manufacturing shall implement measures covering process control system security, hazardous material tracking, and safety instrumented system integrity.", "Sectoral Baselines (Annex II)"},
		{"NIS2IA-SEC-2.4", "Food production and distribution baseline", "Important entities in food production and distribution shall implement measures covering supply chain traceability systems, cold chain monitoring security, and food safety data integrity.", "Sectoral Baselines (Annex II)"},
		{"NIS2IA-SEC-2.5", "Critical products manufacturing baseline", "Important entities manufacturing critical products shall implement measures covering industrial control system security, bill of materials integrity, and counterfeit detection systems.", "Sectoral Baselines (Annex II)"},
		{"NIS2IA-SEC-2.6", "Digital provider baseline requirements", "Important entities providing digital services shall implement measures covering online marketplace security, search engine integrity, social network data protection, and cloud computing service resilience.", "Sectoral Baselines (Annex II)"},
	}

	technicalMeasures := []struct {
		id, title, desc, family string
	}{
		{"NIS2IA-TECH-2.1", "Network security architecture requirements", "Entities shall implement defense-in-depth network security architecture including network segmentation between IT and OT environments, zero-trust network access principles, and micro-segmentation for critical assets.", "Technical Measures"},
		{"NIS2IA-TECH-2.2", "Encryption standards", "All sensitive data at rest shall be encrypted using AES-256 or equivalent algorithms approved by ENISA. Data in transit shall use TLS 1.3 or equivalent. Key management shall follow NIST SP 800-57 guidelines.", "Technical Measures"},
		{"NIS2IA-TECH-2.3", "Multi-factor authentication requirements", "All user access to critical systems and administrative interfaces shall require multi-factor authentication. Hardware tokens or FIDO2/WebAuthn shall be preferred over SMS-based OTP.", "Technical Measures"},
		{"NIS2IA-TECH-2.4", "Vulnerability management timelines", "Critical vulnerabilities shall be patched within 24 hours of available fix. High-severity vulnerabilities within 72 hours. Medium-severity within 14 days. Low-severity within 30 days. Risk-based exceptions require documented approval.", "Technical Measures"},
		{"NIS2IA-TECH-2.5", "Incident detection capabilities", "Entities shall deploy SIEM systems with real-time correlation, EDR on all endpoints, and NDR for network traffic analysis. Detection rules shall be updated within 24 hours of new threat intelligence.", "Technical Measures"},
		{"NIS2IA-TECH-2.6", "Logging and audit trail requirements", "Entities shall maintain centralised logging with tamper-evident storage. Logs shall be retained for a minimum of 24 months. All privileged actions, authentication events, and data access shall be logged with immutable timestamps.", "Technical Measures"},
		{"NIS2IA-TECH-2.7", "Backup and recovery standards", "Entities shall maintain the 3-2-1 backup rule minimum. Recovery time objectives shall not exceed 4 hours for critical systems. Backup integrity shall be verified weekly. Full disaster recovery tests shall be conducted quarterly.", "Technical Measures"},
		{"NIS2IA-TECH-2.8", "Supply chain security", "Entities shall implement software bill of materials (SBOM) requirements, conduct vendor security assessments, and verify integrity of third-party software components before deployment.", "Technical Measures"},
	}

	governanceMeasures := []struct {
		id, title, desc, family string
	}{
		{"NIS2IA-GOV-3.1", "CSIRT reporting formats", "Entities shall use the standardised incident reporting formats adopted by ENISA, including the initial notification template, intermediate update template, and final incident report template.", "Governance Measures"},
		{"NIS2IA-GOV-3.2", "Cross-border cooperation procedures", "Entities operating in multiple member states shall establish cross-border cooperation procedures with relevant national CSIRTs, including designated points of contact and agreed communication channels.", "Governance Measures"},
		{"NIS2IA-GOV-3.3", "Supervisory measures framework", "Competent authorities shall conduct regular risk-based assessments of essential and important entities, including on-site inspections, document reviews, and technical testing of security controls.", "Governance Measures"},
		{"NIS2IA-GOV-3.4", "Penalty framework", "Member states shall establish effective, proportionate, and dissuasive penalties for non-compliance, including fines up to EUR 10 million or 2% of global turnover for essential entities and EUR 7 million or 1.4% for important entities.", "Governance Measures"},
		{"NIS2IA-GOV-3.5", "Board-level cybersecurity accountability", "Management bodies of essential and important entities shall approve cybersecurity risk management measures, oversee their implementation, and receive regular briefings on the entity's cybersecurity posture.", "Governance Measures"},
	}

	sectorSpecific := []struct {
		id, title, desc, family string
	}{
		{"NIS2IA-ENERGY-4.1", "SCADA/ICS security for energy sector", "Energy entities shall implement dedicated SCADA/ICS security measures including air-gapped safety systems, unidirectional gateways for data diodes, industrial protocol deep packet inspection, and OT-specific intrusion detection.", "Sector-Specific Requirements"},
		{"NIS2IA-HEALTH-5.1", "Medical device cybersecurity", "Health entities shall ensure medical devices comply with MDR 2017/745 cybersecurity requirements, maintain device inventory with vulnerability tracking, and implement network segmentation isolating medical device networks.", "Sector-Specific Requirements"},
		{"NIS2IA-TRANSPORT-6.1", "Signalling system security", "Transport entities shall implement security measures for signalling systems including ERTMS/ETCS rail signalling, air traffic control communication (CPDLC/ADCP), and maritime vessel traffic management systems.", "Sector-Specific Requirements"},
		{"NIS2IA-SPACE-7.1", "Space infrastructure cybersecurity", "Space entities shall implement measures covering satellite communication link security, ground station protection, space segment command and control integrity, and launch infrastructure security.", "Sector-Specific Requirements"},
		{"NIS2IA-WATER-8.1", "Water supply cybersecurity", "Drinking water and wastewater entities shall implement measures covering SCADA security for treatment plants, chemical dosing system integrity, distribution network monitoring, and early warning systems for contamination.", "Sector-Specific Requirements"},
	}

	for _, c := range sectoralBaselinesAnnexI {
		controls = append(controls, Control{
			Framework:   FrameworkID,
			ControlID:   c.id,
			Title:       c.title,
			Family:      c.family,
			Description: c.desc,
			Level:       "essential",
			References: []Reference{
				{Source: "NIS2 Implementing Acts (2024)", Section: "Annex I"},
			},
		})
	}

	for _, c := range sectoralBaselinesAnnexII {
		controls = append(controls, Control{
			Framework:   FrameworkID,
			ControlID:   c.id,
			Title:       c.title,
			Family:      c.family,
			Description: c.desc,
			Level:       "important",
			References: []Reference{
				{Source: "NIS2 Implementing Acts (2024)", Section: "Annex II"},
			},
		})
	}

	for _, c := range technicalMeasures {
		controls = append(controls, Control{
			Framework:   FrameworkID,
			ControlID:   c.id,
			Title:       c.title,
			Family:      c.family,
			Description: c.desc,
			Level:       "standard",
			References: []Reference{
				{Source: "NIS2 Implementing Acts (2024)", Section: "Art. 21(2)"},
			},
		})
	}

	for _, c := range governanceMeasures {
		controls = append(controls, Control{
			Framework:   FrameworkID,
			ControlID:   c.id,
			Title:       c.title,
			Family:      c.family,
			Description: c.desc,
			Level:       "standard",
			References: []Reference{
				{Source: "NIS2 Implementing Acts (2024)", Section: "Art. 21-24"},
			},
		})
	}

	for _, c := range sectorSpecific {
		controls = append(controls, Control{
			Framework:   FrameworkID,
			ControlID:   c.id,
			Title:       c.title,
			Family:      c.family,
			Description: c.desc,
			Level:       "standard",
			References: []Reference{
				{Source: "NIS2 Implementing Acts (2024)", Section: "Art. 21(2) Sectoral"},
			},
		})
	}

	return controls
}
