package ropa

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/shift/enrichment-engine/pkg/grc"
	"github.com/shift/enrichment-engine/pkg/storage"
)

const (
	FrameworkID = "ROPA_GDPR_ART30"
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
	return "ropa"
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
		p.logger.Info("wrote RoPA controls", "count", count)
	}
	return count, nil
}

func embeddedControls() []grc.Control {
	return []grc.Control{
		{
			Framework: FrameworkID, ControlID: "ROPA-CTL-1.1",
			Title: "Controller Record: Purposes of Processing", Family: "Controller Records",
			Description:            "The controller shall maintain a record of processing activities under its responsibility, including the name and contact details of the controller, the purposes of the processing, and a description of the categories of data subjects and personal data.",
			Level:                  "critical",
			RelatedCWEs:            []string{"CWE-16"},
			References:             []grc.Reference{{Source: "GDPR Article 30(1)", URL: "https://gdpr-info.eu/art-30-gdpr/", Section: "Article 30(1)(a)"}},
			ImplementationGuidance: "Create a structured RoPA template documenting all processing purposes. Maintain version control. Review and update whenever processing activities change.",
			AssessmentMethods:      []string{"RoPA Review", "DPO Interview", "Process Mapping Audit"},
		},
		{
			Framework: FrameworkID, ControlID: "ROPA-CTL-1.2",
			Title: "Controller Record: Categories of Personal Data", Family: "Controller Records",
			Description:            "The controller shall document all categories of personal data processed, including special categories of data (Article 9), identifying numbers, and online identifiers.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-200"},
			References:             []grc.Reference{{Source: "GDPR Article 30(1)", URL: "https://gdpr-info.eu/art-30-gdpr/", Section: "Article 30(1)(b)"}},
			ImplementationGuidance: "Categorize all personal data by type: basic identity data, contact data, financial data, health data, biometric data, location data, online identifiers. Map data categories to each processing activity.",
			AssessmentMethods:      []string{"Data Inventory Review", "System Audit", "Manual Review"},
		},
		{
			Framework: FrameworkID, ControlID: "ROPA-CTL-1.3",
			Title: "Controller Record: Categories of Recipients", Family: "Controller Records",
			Description:            "The controller shall document all categories of recipients to whom personal data has been or will be disclosed, including processors, public authorities, and third-party organizations.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-200", "CWE-359"},
			References:             []grc.Reference{{Source: "GDPR Article 30(1)", URL: "https://gdpr-info.eu/art-30-gdpr/", Section: "Article 30(1)(d)"}},
			ImplementationGuidance: "List all data recipients per processing activity: internal departments, processors (with DPA reference), public authorities, third parties. Update when new recipients are added.",
			AssessmentMethods:      []string{"DPA Registry Review", "Data Flow Analysis", "Manual Review"},
		},
		{
			Framework: FrameworkID, ControlID: "ROPA-CTL-1.4",
			Title: "Controller Record: International Transfers", Family: "Controller Records",
			Description:            "The controller shall document all transfers of personal data to third countries or international organizations, including the safeguards used (SCCs, adequacy decisions, BCRs, or derogations).",
			Level:                  "critical",
			RelatedCWEs:            []string{"CWE-359", "CWE-200"},
			References:             []grc.Reference{{Source: "GDPR Article 30(1)", URL: "https://gdpr-info.eu/art-30-gdpr/", Section: "Article 30(1)(e)"}},
			ImplementationGuidance: "Map all international data flows. Document safeguards: adequacy decisions, Standard Contractual Clauses (2021/914), Binding Corporate Rules, or Article 49 derogations. Conduct Transfer Impact Assessments.",
			AssessmentMethods:      []string{"Transfer Impact Assessment Review", "SCC Audit", "Data Flow Mapping"},
		},
		{
			Framework: FrameworkID, ControlID: "ROPA-CTL-1.5",
			Title: "Controller Record: Retention Periods", Family: "Controller Records",
			Description:            "The controller shall document the intended retention periods for each category of personal data, including the criteria used to determine those retention periods.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-16"},
			References:             []grc.Reference{{Source: "GDPR Article 30(1)", URL: "https://gdpr-info.eu/art-30-gdpr/", Section: "Article 30(1)(f)"}},
			ImplementationGuidance: "Define retention periods per data category based on legal requirements, contractual obligations, and legitimate purposes. Implement automated deletion mechanisms. Document the criteria used.",
			AssessmentMethods:      []string{"Retention Schedule Review", "Data Lifecycle Audit", "Manual Review"},
		},
		{
			Framework: FrameworkID, ControlID: "ROPA-CTL-1.6",
			Title: "Controller Record: Technical and Organizational Measures", Family: "Controller Records",
			Description:            "The controller shall describe the general technical and organizational security measures implemented to ensure appropriate protection of personal data processing.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-16"},
			References:             []grc.Reference{{Source: "GDPR Article 30(1)", URL: "https://gdpr-info.eu/art-30-gdpr/", Section: "Article 30(1)(g)"}},
			ImplementationGuidance: "Reference the TOMs (Technical and Organizational Measures) catalog. Include encryption, access controls, pseudonymization, backup, training, and incident response. Link to detailed documentation.",
			AssessmentMethods:      []string{"TOMs Catalog Review", "Security Audit", "ISO 27001 Certification Review"},
		},
		{
			Framework: FrameworkID, ControlID: "ROPA-PRC-1.1",
			Title: "Processor Record: Name and Contact of Processor and Controller", Family: "Processor Records",
			Description:            "Each processor shall maintain a record of all categories of processing activities carried out on behalf of a controller, including the name and contact details of the processor and the controller on whose behalf it acts.",
			Level:                  "critical",
			RelatedCWEs:            []string{"CWE-16"},
			References:             []grc.Reference{{Source: "GDPR Article 30(2)", URL: "https://gdpr-info.eu/art-30-gdpr/", Section: "Article 30(2)(a-b)"}},
			ImplementationGuidance: "Create processor RoPA entries for each controller engagement. Include legal entity names, addresses, DPO contacts, and DPA references.",
			AssessmentMethods:      []string{"Processor RoPA Review", "DPA Cross-reference", "Manual Review"},
		},
		{
			Framework: FrameworkID, ControlID: "ROPA-PRC-1.2",
			Title: "Processor Record: Categories of Processing", Family: "Processor Records",
			Description:            "The processor shall document all categories of processing carried out on behalf of the controller, including the nature and purpose of the processing, types of personal data, and data subjects.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-200"},
			References:             []grc.Reference{{Source: "GDPR Article 30(2)", URL: "https://gdpr-info.eu/art-30-gdpr/", Section: "Article 30(2)(c-e)"}},
			ImplementationGuidance: "Document all processing activities per controller: data processed, purpose (as instructed by controller), data subject categories. Align with controller's RoPA entries.",
			AssessmentMethods:      []string{"Processor RoPA Review", "Controller-Processor Alignment Check", "Manual Review"},
		},
		{
			Framework: FrameworkID, ControlID: "ROPA-PRC-1.3",
			Title: "Processor Record: DPO Contact and Transfers", Family: "Processor Records",
			Description:            "The processor shall document the contact details of the Data Protection Officer and any international transfers carried out, including the safeguards applied.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-359"},
			References:             []grc.Reference{{Source: "GDPR Article 30(2)", URL: "https://gdpr-info.eu/art-30-gdpr/", Section: "Article 30(2)(f-g)"}},
			ImplementationGuidance: "Include DPO name and contact in all processor RoPA entries. Document sub-processor chains and international transfers with applicable safeguards.",
			AssessmentMethods:      []string{"DPO Contact Verification", "Sub-processor List Review", "Manual Review"},
		},
		{
			Framework: FrameworkID, ControlID: "ROPA-PRC-1.4",
			Title: "Processor Record: Security Measures", Family: "Processor Records",
			Description:            "The processor shall describe the technical and organizational security measures applied to processing activities carried out on behalf of the controller.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-16"},
			References:             []grc.Reference{{Source: "GDPR Article 30(2)", URL: "https://gdpr-info.eu/art-30-gdpr/", Section: "Article 30(2)(h)"}},
			ImplementationGuidance: "Document all security measures: encryption, access control, logging, monitoring, physical security, business continuity. Align with controller's TOMs requirements in the DPA.",
			AssessmentMethods:      []string{"Security Audit Report", "SOC 2 Report Review", "ISO 27001 Certification"},
		},
		{
			Framework: FrameworkID, ControlID: "ROPA-TPL-1.1",
			Title: "Template: HR Employee Data Processing", Family: "Processing Templates",
			Description:            "RoPA template for HR processing activities including employee personal data, payroll, attendance tracking, performance management, and recruitment data processing.",
			Level:                  "medium",
			RelatedCWEs:            []string{"CWE-200"},
			References:             []grc.Reference{{Source: "GDPR Article 30", URL: "https://gdpr-info.eu/art-30-gdpr/", Section: "HR Template"}},
			ImplementationGuidance: "Use this template to document all HR data processing: purposes (payroll, benefits, performance), data categories, retention periods (employment + statutory), recipients, legal basis.",
			AssessmentMethods:      []string{"HR RoPA Review", "Employee Privacy Notice Cross-check", "Manual Review"},
		},
		{
			Framework: FrameworkID, ControlID: "ROPA-TPL-1.2",
			Title: "Template: Marketing and Customer Data Processing", Family: "Processing Templates",
			Description:            "RoPA template for marketing processing activities including direct marketing, email campaigns, analytics, CRM data, and customer profiling.",
			Level:                  "medium",
			RelatedCWEs:            []string{"CWE-200"},
			References:             []grc.Reference{{Source: "GDPR Article 30", URL: "https://gdpr-info.eu/art-30-gdpr/", Section: "Marketing Template"}},
			ImplementationGuidance: "Document marketing processing: purposes (direct marketing, analytics, profiling), data categories, consent/legitimate interest basis, opt-out mechanisms, recipients (marketing platforms).",
			AssessmentMethods:      []string{"Marketing RoPA Review", "Consent Records Audit", "Manual Review"},
		},
		{
			Framework: FrameworkID, ControlID: "ROPA-TPL-1.3",
			Title: "Template: Vendor and Sub-processor Management", Family: "Processing Templates",
			Description:            "RoPA template for documenting all data processing activities carried out by vendors, sub-processors, and third-party service providers.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-359"},
			References:             []grc.Reference{{Source: "GDPR Article 28", URL: "https://gdpr-info.eu/art-28-gdpr/", Section: "Processor Template"}},
			ImplementationGuidance: "Document all vendor processing: processor name, DPA reference, data shared, processing purpose, sub-processor list, international transfers, audit rights exercised.",
			AssessmentMethods:      []string{"Vendor Register Review", "DPA Status Report", "Sub-processor List Audit"},
		},
		{
			Framework: FrameworkID, ControlID: "ROPA-TPL-1.4",
			Title: "Template: Analytics and Behavioral Tracking", Family: "Processing Templates",
			Description:            "RoPA template for analytics processing activities including web analytics, behavioral tracking, cookies, heatmaps, and user session recording.",
			Level:                  "medium",
			RelatedCWEs:            []string{"CWE-200"},
			References:             []grc.Reference{{Source: "ePrivacy Directive + GDPR Article 30", URL: "https://gdpr-info.eu/art-30-gdpr/", Section: "Analytics Template"}},
			ImplementationGuidance: "Document analytics processing: purposes (optimization, UX improvement), data categories (IP, device info, browsing behavior), consent mechanism, retention (26 months max for analytics), recipients.",
			AssessmentMethods:      []string{"Cookie Consent Audit", "Analytics RoPA Review", "Manual Review"},
		},
		{
			Framework: FrameworkID, ControlID: "ROPA-TPL-1.5",
			Title: "Template: Health and Biometric Data Processing", Family: "Processing Templates",
			Description:            "RoPA template for special category data processing including health records, biometric identification, genetic data, and wellness data requiring explicit consent or specific legal basis.",
			Level:                  "critical",
			RelatedCWEs:            []string{"CWE-200", "CWE-308"},
			References:             []grc.Reference{{Source: "GDPR Article 9", URL: "https://gdpr-info.eu/art-9-gdpr/", Section: "Special Categories Template"}},
			ImplementationGuidance: "Document special category processing: explicit consent or Article 9(2) legal basis, DPIA reference, enhanced security measures, restricted access, data minimization, retention aligned to health regulations.",
			AssessmentMethods:      []string{"DPIA Review", "Special Category Data Audit", "DPO Consultation Records"},
		},
		{
			Framework: FrameworkID, ControlID: "ROPA-TPL-1.6",
			Title: "Template: IoT and Sensor Data Processing", Family: "Processing Templates",
			Description:            "RoPA template for IoT processing activities including sensor data collection, device identification, location tracking, and smart environment data processing.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-200"},
			References:             []grc.Reference{{Source: "GDPR Article 30", URL: "https://gdpr-info.eu/art-30-gdpr/", Section: "IoT Template"}},
			ImplementationGuidance: "Document IoT processing: device types, data collected (location, usage patterns, environmental), purposes, consent/basis, data subjects (employees, visitors, public), edge processing.",
			AssessmentMethods:      []string{"IoT Data Flow Mapping", "Device Inventory Review", "Privacy Impact Assessment"},
		},
	}
}
