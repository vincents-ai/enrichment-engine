package cobit

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/vincents-ai/enrichment-engine/pkg/grc"
	"github.com/vincents-ai/enrichment-engine/pkg/storage"
)

const FrameworkID = "COBIT_2019"
const CatalogURL = ""

type Provider struct {
	store  storage.Backend
	logger *slog.Logger
}

func New(store storage.Backend, logger *slog.Logger) *Provider {
	return &Provider{store: store, logger: logger}
}

func (p *Provider) Name() string { return "cobit" }

func (p *Provider) Run(ctx context.Context) (int, error) {
	return p.writeEmbeddedControls(ctx)
}

func (p *Provider) writeEmbeddedControls(ctx context.Context) (int, error) {
	p.logger.Info("using embedded COBIT 2019 controls")
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
	p.logger.Info("wrote embedded COBIT 2019 controls to storage", "count", count)
	return count, nil
}

func embeddedControls() []grc.Control {
	type c struct{ id, title, desc, family string }
	items := []struct {
		family string
		items  []c
	}{
		{"Governance", []c{
			{"EDM01", "Ensure Governance Framework Setting and Maintenance", "Ensure that the governance framework for enterprise IT is established and maintained, providing direction and oversight for IT-related activities aligned with stakeholder needs.", "Governance"},
			{"EDM02", "Ensure Benefits Delivery", "Ensure that IT-enabled investments achieve their intended benefits and that value is optimized throughout the investment lifecycle.", "Governance"},
			{"EDM03", "Ensure Risk Optimization", "Ensure that the enterprise's risk appetite and tolerance are understood and articulated, and that IT-related risk is managed within acceptable levels.", "Governance"},
			{"EDM04", "Ensure Resource Optimization", "Ensure that IT resources are available, sufficient, and properly allocated to meet strategic objectives.", "Governance"},
			{"EDM05", "Ensure Stakeholder Engagement", "Ensure that stakeholders' needs, conditions, and expectations are understood and balanced, and that transparent communication is maintained.", "Governance"},
		}},
		{"APO - Align, Plan and Organize", []c{
			{"APO01", "Manage the IT Management Framework", "Establish and maintain an IT management framework including governance structures, policies, and standards that align IT with business objectives.", "APO - Align, Plan and Organize"},
			{"APO02", "Manage Strategy", "Define and maintain the IT strategy that enables the enterprise to achieve its goals and objectives.", "APO - Align, Plan and Organize"},
			{"APO03", "Manage Enterprise Architecture", "Establish and maintain the enterprise architecture that enables the enterprise to achieve its strategic goals.", "APO - Align, Plan and Organize"},
			{"APO04", "Manage Innovation", "Identify, evaluate, and manage opportunities for innovation in IT-enabled solutions and services.", "APO - Align, Plan and Organize"},
			{"APO05", "Manage Portfolio", "Manage the IT-enabled investment portfolio to ensure it aligns with the enterprise strategy and delivers value.", "APO - Align, Plan and Organize"},
			{"APO06", "Manage Budget and Costs", "Establish and maintain IT budget and cost management to optimize IT spending.", "APO - Align, Plan and Organize"},
			{"APO07", "Manage Human Resources", "Ensure that IT personnel have the skills, competencies, and motivation to fulfill their roles and responsibilities.", "APO - Align, Plan and Organize"},
			{"APO08", "Manage Relationships", "Manage relationships with stakeholders, vendors, and partners to ensure alignment and value delivery.", "APO - Align, Plan and Organize"},
			{"APO09", "Manage Service Agreements", "Define, negotiate, and manage service agreements to ensure quality and value of IT services.", "APO - Align, Plan and Organize"},
			{"APO10", "Manage Vendors", "Manage vendor relationships and performance to ensure delivery of quality products and services.", "APO - Align, Plan and Organize"},
			{"APO11", "Manage Quality", "Establish and maintain a quality management system for IT processes and services.", "APO - Align, Plan and Organize"},
			{"APO12", "Manage Information Security", "Define, implement, and monitor an information security management system aligned with business requirements.", "APO - Align, Plan and Organize"},
			{"APO13", "Manage Data", "Manage the enterprise data lifecycle to ensure data integrity, availability, confidentiality, and compliance.", "APO - Align, Plan and Organize"},
			{"APO14", "Manage Compliance", "Ensure compliance with applicable laws, regulations, and contractual requirements.", "APO - Align, Plan and Organize"},
		}},
		{"BAI - Build, Acquire and Implement", []c{
			{"BAI01", "Manage Programs and Projects", "Initiate, plan, execute, and close programs and projects to deliver identified benefits.", "BAI - Build, Acquire and Implement"},
			{"BAI02", "Manage Requirements Definition", "Define and maintain requirements for IT-enabled solutions that align with business needs.", "BAI - Build, Acquire and Implement"},
			{"BAI03", "Manage Solutions Identification and Build", "Identify, design, develop, or acquire IT solutions that meet business requirements.", "BAI - Build, Acquire and Implement"},
			{"BAI04", "Manage Availability and Capacity", "Ensure IT services have sufficient capacity and availability to meet business requirements.", "BAI - Build, Acquire and Implement"},
			{"BAI05", "Manage Organizational Change Enablement", "Prepare, manage, and support organizational change to achieve desired business outcomes.", "BAI - Build, Acquire and Implement"},
			{"BAI06", "Manage Changes", "Control changes to IT systems, services, and infrastructure to minimize adverse impacts.", "BAI - Build, Acquire and Implement"},
			{"BAI07", "Manage Change Acceptance and Transitioning", "Plan, manage, and transition changes to production to deliver the intended business value.", "BAI - Build, Acquire and Implement"},
			{"BAI08", "Manage Knowledge", "Plan, build, and manage knowledge assets to enable effective decision-making.", "BAI - Build, Acquire and Implement"},
			{"BAI09", "Manage Assets", "Manage IT assets throughout their lifecycle to maximize value and minimize risk.", "BAI - Build, Acquire and Implement"},
			{"BAI10", "Manage Configuration", "Define, maintain, and control configuration items to ensure accurate information about IT assets.", "BAI - Build, Acquire and Implement"},
			{"BAI11", "Manage Projects", "Plan, execute, and control IT projects to deliver objectives within time, cost, and quality constraints.", "BAI - Build, Acquire and Implement"},
		}},
		{"DSS - Deliver, Service and Support", []c{
			{"DSS01", "Manage Operations", "Execute and operate IT services, including operations management, to deliver agreed-upon service levels.", "DSS - Deliver, Service and Support"},
			{"DSS02", "Manage Service Requests and Incidents", "Receive, log, categorize, prioritize, and resolve service requests and incidents.", "DSS - Deliver, Service and Support"},
			{"DSS03", "Manage Problems", "Identify, analyze, and resolve root causes of incidents to prevent recurrence.", "DSS - Deliver, Service and Support"},
			{"DSS04", "Manage Continuity", "Establish and maintain business continuity plans and disaster recovery capabilities for IT services.", "DSS - Deliver, Service and Support"},
			{"DSS05", "Manage Security Services", "Operate and maintain security controls and services to protect information assets.", "DSS - Deliver, Service and Support"},
			{"DSS06", "Manage Business Process Controls", "Implement and maintain automated business process controls within IT applications.", "DSS - Deliver, Service and Support"},
			{"DSS07", "Manage User Identity and Access", "Manage user identity and access to IT resources to ensure appropriate authorization.", "DSS - Deliver, Service and Support"},
		}},
		{"MEA - Monitor, Evaluate and Assess", []c{
			{"MEA01", "Monitor, Evaluate and Assess Performance and Conformance", "Monitor, evaluate, and assess the performance and conformance of IT governance and management.", "MEA - Monitor, Evaluate and Assess"},
			{"MEA02", "Monitor, Evaluate and Assess the System of Internal Control", "Monitor, evaluate, and assess the system of internal controls to ensure effectiveness and efficiency.", "MEA - Monitor, Evaluate and Assess"},
			{"MEA03", "Monitor, Evaluate and Assess Compliance with Requirements", "Monitor, evaluate, and assess compliance with external laws, regulations, and internal requirements.", "MEA - Monitor, Evaluate and Assess"},
			{"MEA04", "Provide Independent Assurance", "Obtain independent assurance over governance, management, and operations.", "MEA - Monitor, Evaluate and Assess"},
			{"MEA05", "Monitor and Evaluate Stakeholder Needs", "Monitor and evaluate changes in stakeholder needs and conditions to ensure alignment.", "MEA - Monitor, Evaluate and Assess"},
			{"MEA06", "Monitor, Evaluate and Assess Knowledge", "Monitor, evaluate, and assess the organization's knowledge assets and capabilities.", "MEA - Monitor, Evaluate and Assess"},
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
				Level:       "governance",
				References:  []grc.Reference{{Source: "COBIT 2019", Section: c.id}},
			})
		}
	}
	return controls
}
