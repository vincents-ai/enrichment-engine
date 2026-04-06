package nist_ssdf

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/shift/enrichment-engine/pkg/grc"
	"github.com/shift/enrichment-engine/pkg/storage"
)

const FrameworkID = "NIST_SSDF"

// Provider implements the NIST Secure Software Development Framework (SP 800-218).
type Provider struct {
	store  storage.Backend
	logger *slog.Logger
}

// New creates a new NIST SSDF provider.
func New(store storage.Backend, logger *slog.Logger) *Provider {
	return &Provider{
		store:  store,
		logger: logger,
	}
}

// Name returns the provider identifier.
func (p *Provider) Name() string {
	return "nist_ssdf"
}

// Run writes all NIST SSDF controls to storage.
func (p *Provider) Run(ctx context.Context) (int, error) {
	p.logger.Info("loading NIST SSDF SP 800-218 controls")

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

	p.logger.Info("wrote NIST SSDF controls to storage", "count", count)
	return count, nil
}

func staticControls() []grc.Control {
	ref := func(section string) []grc.Reference {
		return []grc.Reference{{Source: "NIST SP 800-218", Section: section}}
	}

	return []grc.Control{
		{
			Framework:   FrameworkID,
			ControlID:   "PO.1.1",
			Title:       "Define security requirements for software",
			Family:      "Prepare the Organisation",
			Description: "Identify and document all security requirements for the software and ensure they are addressed throughout the SDLC.",
			Level:       "standard",
			RelatedCWEs: []string{},
			Tags:        []string{"supply-chain", "sdlc"},
			References:  ref("PO.1.1"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "PO.1.2",
			Title:       "Implement security criteria in acquisition",
			Family:      "Prepare the Organisation",
			Description: "Implement a process to include security requirements in software acquisition and procurement.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-1357"},
			Tags:        []string{"supply-chain"},
			References:  ref("PO.1.2"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "PO.2.1",
			Title:       "Implement roles and responsibilities",
			Family:      "Prepare the Organisation",
			Description: "Establish and maintain roles and responsibilities within the organisation for software security.",
			Level:       "standard",
			RelatedCWEs: []string{},
			Tags:        []string{"governance"},
			References:  ref("PO.2.1"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "PO.3.1",
			Title:       "Implement secure environments",
			Family:      "Prepare the Organisation",
			Description: "Use development environments with least-privilege access and separation of duties.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-250"},
			Tags:        []string{"privilege", "environment"},
			References:  ref("PO.3.1"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "PO.4.1",
			Title:       "Define and use criteria for software security checks",
			Family:      "Prepare the Organisation",
			Description: "Define and document criteria for security checks throughout the SDLC.",
			Level:       "standard",
			RelatedCWEs: []string{},
			Tags:        []string{"sdlc"},
			References:  ref("PO.4.1"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "PO.5.1",
			Title:       "Implement secure development environments",
			Family:      "Prepare the Organisation",
			Description: "Implement and maintain secure development environments with appropriate access controls.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-250", "CWE-732"},
			Tags:        []string{"environment", "privilege"},
			References:  ref("PO.5.1"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "PS.1.1",
			Title:       "Protect code from unauthorised access",
			Family:      "Protect the Software",
			Description: "Store all code in repositories with access controls to prevent unauthorised access.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-732", "CWE-284"},
			Tags:        []string{"access-control"},
			References:  ref("PS.1.1"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "PS.2.1",
			Title:       "Protect code from tampering",
			Family:      "Protect the Software",
			Description: "Use commit signing and integrity verification to detect and prevent code tampering.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-494"},
			Tags:        []string{"integrity", "supply-chain"},
			References:  ref("PS.2.1"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "PS.3.1",
			Title:       "Archive and protect releases",
			Family:      "Protect the Software",
			Description: "Archive and cryptographically protect all software releases.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-494"},
			Tags:        []string{"integrity"},
			References:  ref("PS.3.1"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "PW.1.1",
			Title:       "Train developers in security",
			Family:      "Produce Well-Secured Software",
			Description: "Provide all developers with security training appropriate to their roles.",
			Level:       "standard",
			RelatedCWEs: []string{},
			Tags:        []string{"training"},
			References:  ref("PW.1.1"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "PW.2.1",
			Title:       "Follow design patterns for security",
			Family:      "Produce Well-Secured Software",
			Description: "Use well-established, peer-reviewed security design patterns and architectures.",
			Level:       "standard",
			RelatedCWEs: []string{},
			Tags:        []string{"design"},
			References:  ref("PW.2.1"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "PW.4.1",
			Title:       "Reuse existing secure components",
			Family:      "Produce Well-Secured Software",
			Description: "Acquire and use secure, well-maintained reusable software when possible.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-1357"},
			Tags:        []string{"supply-chain"},
			References:  ref("PW.4.1"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "PW.4.4",
			Title:       "Verify third-party component integrity",
			Family:      "Produce Well-Secured Software",
			Description: "Verify the integrity of all third-party components before use.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-1357", "CWE-494"},
			Tags:        []string{"supply-chain", "integrity"},
			References:  ref("PW.4.4"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "PW.5.1",
			Title:       "Identify and mitigate vulnerabilities",
			Family:      "Produce Well-Secured Software",
			Description: "Use automated tools and manual code review to identify and mitigate vulnerabilities including memory safety issues.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-119", "CWE-787"},
			Tags:        []string{"memory", "buffer-overflow"},
			References:  ref("PW.5.1"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "PW.6.1",
			Title:       "Test executables for vulnerabilities",
			Family:      "Produce Well-Secured Software",
			Description: "Test software executables using dynamic analysis techniques to identify vulnerabilities.",
			Level:       "standard",
			RelatedCWEs: []string{},
			Tags:        []string{"testing"},
			References:  ref("PW.6.1"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "PW.6.2",
			Title:       "Verify third-party software security",
			Family:      "Produce Well-Secured Software",
			Description: "Test acquired third-party software for security vulnerabilities.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-1357"},
			Tags:        []string{"supply-chain"},
			References:  ref("PW.6.2"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "PW.7.1",
			Title:       "Identify and handle disclosed vulnerabilities",
			Family:      "Produce Well-Secured Software",
			Description: "Establish a process to identify, triage, and address disclosed vulnerabilities.",
			Level:       "standard",
			RelatedCWEs: []string{},
			Tags:        []string{"vulnerability-management"},
			References:  ref("PW.7.1"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "PW.8.1",
			Title:       "Plan and document vulnerability responses",
			Family:      "Produce Well-Secured Software",
			Description: "Maintain a documented plan for responding to vulnerability reports.",
			Level:       "standard",
			RelatedCWEs: []string{},
			Tags:        []string{"vulnerability-management"},
			References:  ref("PW.8.1"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "RV.1.1",
			Title:       "Gather vulnerability reports",
			Family:      "Respond to Vulnerabilities",
			Description: "Establish mechanisms to receive vulnerability reports from internal and external sources.",
			Level:       "standard",
			RelatedCWEs: []string{},
			Tags:        []string{"vulnerability-management"},
			References:  ref("RV.1.1"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "RV.1.2",
			Title:       "Review vulnerability reports",
			Family:      "Respond to Vulnerabilities",
			Description: "Review and triage all received vulnerability reports in a timely manner.",
			Level:       "standard",
			RelatedCWEs: []string{},
			Tags:        []string{"vulnerability-management"},
			References:  ref("RV.1.2"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "RV.1.3",
			Title:       "Analyse vulnerabilities",
			Family:      "Respond to Vulnerabilities",
			Description: "Analyse vulnerabilities to determine scope, severity, and technical details.",
			Level:       "standard",
			RelatedCWEs: []string{},
			Tags:        []string{"vulnerability-management"},
			References:  ref("RV.1.3"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "RV.2.1",
			Title:       "Plan remediations",
			Family:      "Respond to Vulnerabilities",
			Description: "Plan, prioritise, and communicate remediations for identified vulnerabilities.",
			Level:       "standard",
			RelatedCWEs: []string{},
			Tags:        []string{"vulnerability-management"},
			References:  ref("RV.2.1"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "RV.2.2",
			Title:       "Implement remediations",
			Family:      "Respond to Vulnerabilities",
			Description: "Implement fixes for vulnerabilities, including memory safety, input validation, and injection flaws.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-119", "CWE-787", "CWE-20"},
			Tags:        []string{"memory", "input-validation"},
			References:  ref("RV.2.2"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "RV.3.1",
			Title:       "Analyse vulnerabilities to identify root causes",
			Family:      "Respond to Vulnerabilities",
			Description: "Analyse vulnerabilities to identify root causes and prevent recurrence in the SDLC.",
			Level:       "standard",
			RelatedCWEs: []string{},
			Tags:        []string{"sdlc"},
			References:  ref("RV.3.1"),
		},
	}
}
