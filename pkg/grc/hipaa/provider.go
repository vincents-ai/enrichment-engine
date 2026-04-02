package hipaa

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/shift/enrichment-engine/pkg/grc"
	"github.com/shift/enrichment-engine/pkg/storage"
)

const FrameworkID = "HIPAA_SECURITY_RULE_2013"
const CatalogURL = ""

type Provider struct {
	store  storage.Backend
	logger *slog.Logger
}

func New(store storage.Backend, logger *slog.Logger) *Provider {
	return &Provider{store: store, logger: logger}
}

func (p *Provider) Name() string { return "hipaa" }

func (p *Provider) Run(ctx context.Context) (int, error) {
	return p.writeEmbeddedControls(ctx)
}

func (p *Provider) writeEmbeddedControls(ctx context.Context) (int, error) {
	p.logger.Info("using embedded HIPAA Security Rule controls")
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
	p.logger.Info("wrote embedded HIPAA controls to storage", "count", count)
	return count, nil
}

var hipaaCWEMap = map[string][]string{
	"164.308(a)(1)":        {"CWE-1104", "CWE-937", "CWE-693"},
	"164.308(a)(3)":        {"CWE-287", "CWE-798", "CWE-862"},
	"164.308(a)(4)":        {"CWE-284", "CWE-285", "CWE-862"},
	"164.308(a)(5)(i)":     {"CWE-919", "CWE-937"},
	"164.308(a)(5)(ii)(B)": {"CWE-94", "CWE-506"},
	"164.308(a)(5)(ii)(C)": {"CWE-778"},
	"164.308(a)(5)(ii)(D)": {"CWE-521", "CWE-265"},
	"164.308(a)(6)":        {"CWE-778", "CWE-693"},
	"164.308(a)(7)":        {"CWE-1007", "CWE-754"},
	"164.308(a)(7)(ii)(A)": {"CWE-494", "CWE-1007"},
	"164.308(a)(7)(ii)(B)": {"CWE-1007", "CWE-754"},
	"164.308(a)(7)(ii)(C)": {"CWE-1007", "CWE-754"},
	"164.308(a)(9)":        {"CWE-1104", "CWE-937"},
	"164.310(a)(1)":        {"CWE-668", "CWE-284"},
	"164.310(a)(2)(iii)":   {"CWE-287", "CWE-798"},
	"164.310(c)":           {"CWE-668", "CWE-284"},
	"164.310(d)(2)(i)":     {"CWE-226", "CWE-228"},
	"164.310(d)(2)(ii)":    {"CWE-226", "CWE-228"},
	"164.310(d)(2)(iv)":    {"CWE-494", "CWE-1007"},
	"164.312(a)(1)":        {"CWE-287", "CWE-798"},
	"164.312(a)(2)(i)":     {"CWE-284", "CWE-285", "CWE-862"},
	"164.312(a)(2)(iii)":   {"CWE-311", "CWE-312"},
	"164.312(b)":           {"CWE-778"},
	"164.312(c)(1)":        {"CWE-345", "CWE-353"},
	"164.312(d)":           {"CWE-287", "CWE-308", "CWE-522"},
	"164.312(e)(1)":        {"CWE-284", "CWE-285", "CWE-862"},
	"164.312(e)(2)(ii)":    {"CWE-319", "CWE-326"},
	"164.314(a)(1)":        {"CWE-1104", "CWE-937"},
}

func hipaaCWEs(controlID string) []string {
	return hipaaCWEMap[controlID]
}

func embeddedControls() []grc.Control {
	type c struct{ id, title, desc, family string }
	items := []struct {
		family string
		items  []c
	}{
		{"Administrative Safeguards", []c{
			{"164.308(a)(1)", "Security Management Process", "Implement policies and procedures to prevent, detect, contain, and correct security violations including risk analysis, risk management, sanction policy, and information system activity review.", "Administrative Safeguards"},
			{"164.308(a)(2)", "Assigned Security Responsibility", "Designate a security official responsible for developing and implementing security policies and procedures.", "Administrative Safeguards"},
			{"164.308(a)(3)", "Workforce Security", "Implement policies and procedures to ensure all workforce members have appropriate access to ePHI including authorization and/or clearance, background checks, termination procedures, and access revocation.", "Administrative Safeguards"},
			{"164.308(a)(4)", "Information Access Management", "Implement policies and procedures for authorizing access to ePHI including access authorization and access modification.", "Administrative Safeguards"},
			{"164.308(a)(5)(i)", "Security Awareness and Training", "Implement a security awareness and training program for all workforce members including periodic reminders and protection from malicious software.", "Administrative Safeguards"},
			{"164.308(a)(5)(ii)(A)", "Security Reminders", "Provide periodic security updates and reminders to workforce members.", "Administrative Safeguards"},
			{"164.308(a)(5)(ii)(B)", "Protection from Malicious Software", "Implement procedures for guarding against, detecting, and reporting malicious software.", "Administrative Safeguards"},
			{"164.308(a)(5)(ii)(C)", "Log-in Monitoring", "Implement procedures for monitoring log-in attempts and reporting discrepancies.", "Administrative Safeguards"},
			{"164.308(a)(5)(ii)(D)", "Password Management", "Implement procedures for creating, changing, and safeguarding passwords.", "Administrative Safeguards"},
			{"164.308(a)(6)", "Security Incident Procedures", "Implement policies and procedures to address security incidents including identification, response, mitigation, and documentation.", "Administrative Safeguards"},
			{"164.308(a)(7)", "Contingency Plan", "Establish policies and procedures for responding to an emergency or other occurrence that damages systems containing ePHI including data backup plan, disaster recovery plan, and emergency mode operation plan.", "Administrative Safeguards"},
			{"164.308(a)(7)(ii)(A)", "Data Backup Plan", "Implement procedures to create and maintain retrievable exact copies of ePHI.", "Administrative Safeguards"},
			{"164.308(a)(7)(ii)(B)", "Disaster Recovery Plan", "Implement procedures to restore any loss of data due to an emergency.", "Administrative Safeguards"},
			{"164.308(a)(7)(ii)(C)", "Emergency Mode Operation Plan", "Implement procedures to enable continuation of critical business processes while operating in emergency mode.", "Administrative Safeguards"},
			{"164.308(a)(8)", "Evaluation", "Perform periodic technical and nontechnical evaluations to establish and maintain compliance with security requirements.", "Administrative Safeguards"},
			{"164.308(a)(9)", "Business Associate Contracts", "Obtain satisfactory assurances from business associates that they will appropriately safeguard ePHI through contracts or other arrangements.", "Administrative Safeguards"},
		}},
		{"Physical Safeguards", []c{
			{"164.310(a)(1)", "Facility Access Controls", "Implement policies and procedures to limit physical access to electronic information systems and the facilities while ensuring properly authorized access is allowed.", "Physical Safeguards"},
			{"164.310(a)(2)(i)", "Contingency Operations", "Establish and implement procedures that allow facility access in support of restoration of lost data under the disaster recovery plan and emergency mode operations plan.", "Physical Safeguards"},
			{"164.310(a)(2)(ii)", "Facility Security Plan", "Implement policies and procedures to safeguard the facility and the equipment therein from unauthorized physical access, tampering, and theft.", "Physical Safeguards"},
			{"164.310(a)(2)(iii)", "Access Control and Validation", "Implement procedures to control and validate a person's access to facilities based on their role or function including visitor sign-in and escort.", "Physical Safeguards"},
			{"164.310(a)(2)(iv)", "Maintenance Records", "Implement policies and procedures to document repairs and modifications to the physical components of a facility related to security.", "Physical Safeguards"},
			{"164.310(b)", "Workstation Use", "Implement policies and procedures specifying the proper functions to be performed, the manner in which those functions are to be performed, and the physical attributes of the surroundings of a specific workstation.", "Physical Safeguards"},
			{"164.310(c)", "Workstation Security", "Implement physical safeguards for all workstations that access ePHI to restrict access to authorized users.", "Physical Safeguards"},
			{"164.310(d)(1)", "Device and Media Controls", "Implement policies and procedures that govern the receipt and removal of hardware and electronic media that contain ePHI.", "Physical Safeguards"},
			{"164.310(d)(2)(i)", "Disposal", "Implement policies and procedures to address the final disposition of ePHI and/or the hardware or electronic media on which it is stored.", "Physical Safeguards"},
			{"164.310(d)(2)(ii)", "Media Re-use", "Implement procedures for removal of ePHI from electronic media before the media are made available for re-use.", "Physical Safeguards"},
			{"164.310(d)(2)(iii)", "Accountability", "Maintain a record of the movements of hardware and electronic media and any person responsible therefore.", "Physical Safeguards"},
			{"164.310(d)(2)(iv)", "Data Backup and Storage", "Create a retrievable, exact copy of ePHI before moving equipment.", "Physical Safeguards"},
		}},
		{"Technical Safeguards", []c{
			{"164.312(a)(1)", "Access Control - Unique User Identification", "Assign a unique name and/or number for identifying and tracking user identity.", "Technical Safeguards"},
			{"164.312(a)(2)(i)", "Access Control - Emergency Access Procedure", "Establish procedures for obtaining necessary ePHI during an emergency.", "Technical Safeguards"},
			{"164.312(a)(2)(ii)", "Access Control - Automatic Logoff", "Implement electronic procedures that terminate an electronic session after a predetermined time of inactivity.", "Technical Safeguards"},
			{"164.312(a)(2)(iii)", "Access Control - Encryption and Decryption", "Implement a mechanism to encrypt and decrypt ePHI.", "Technical Safeguards"},
			{"164.312(b)", "Audit Controls", "Implement hardware, software, and/or procedural mechanisms that record and examine activity in information systems that contain or use ePHI.", "Technical Safeguards"},
			{"164.312(c)(1)", "Integrity - Mechanism to Authenticate ePHI", "Implement policies and procedures to protect ePHI from improper alteration or destruction.", "Technical Safeguards"},
			{"164.312(d)", "Person or Entity Authentication", "Implement procedures to verify that a person or entity seeking access to ePHI is the one claimed.", "Technical Safeguards"},
			{"164.312(e)(1)", "Transmission Security - Access Controls", "Implement technical security measures to guard against unauthorized access to ePHI being transmitted over an electronic communications network.", "Technical Safeguards"},
			{"164.312(e)(2)(ii)", "Transmission Security - Encryption", "Implement a mechanism to encrypt ePHI whenever deemed appropriate.", "Technical Safeguards"},
		}},
		{"Organizational Requirements", []c{
			{"164.314(a)(1)", "Business Associate Contracts", "Ensure contracts with business associates require appropriate safeguards for ePHI.", "Organizational Requirements"},
			{"164.314(a)(2)(i)", "Business Associate Contracts - Required Provisions", "Include specific provisions in business associate contracts regarding permitted uses and disclosures of ePHI, reporting of breaches, and compliance with security requirements.", "Organizational Requirements"},
			{"164.314(a)(2)(ii)", "Business Associate Contracts - Optional Provisions", "Include optional provisions in business associate contracts regarding return or destruction of ePHI upon termination.", "Organizational Requirements"},
			{"164.314(b)", "Requirements for Group Health Plans", "Ensure group health plans limit uses and disclosures of PHI to the plan sponsor.", "Organizational Requirements"},
			{"164.314(b)(2)(i)", "Plan Sponsor Restrictions", "Restrict the plan sponsor's uses and disclosures of PHI to those functions the plan sponsor performs for the group health plan.", "Organizational Requirements"},
		}},
		{"Policies and Procedures", []c{
			{"164.316(a)(1)", "Policies and Procedures", "Develop, document, maintain, and periodically update security policies and procedures to comply with the Security Rule.", "Policies and Procedures"},
			{"164.316(a)(2)", "Documentation", "Maintain documentation of all security policies and procedures implemented and their revision dates.", "Policies and Procedures"},
			{"164.316(b)(1)", "Retention Period", "Retain documentation required by the Security Rule for six years from the date of creation or last effective date.", "Policies and Procedures"},
			{"164.316(b)(2)", "Availability", "Make documentation available to those persons responsible for implementing the procedures to which the documentation pertains.", "Policies and Procedures"},
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
				Level:       "required",
				RelatedCWEs: hipaaCWEs(c.id),
				References:  []grc.Reference{{Source: "45 CFR Part 164", Section: c.id}},
			})
		}
	}
	return controls
}
