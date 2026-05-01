package openssf_scorecard

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/vincents-ai/enrichment-engine/pkg/grc"
	"github.com/vincents-ai/enrichment-engine/pkg/storage"
)

const FrameworkID = "OPENSSF_SCORECARD_V5"

// Provider implements the OpenSSF Scorecard v5 security checks as GRC controls.
// Pattern C: staticControls() — no external file needed (ADR-015 compliant).
type Provider struct {
	store  storage.Backend
	logger *slog.Logger
}

// New creates a new OpenSSF Scorecard provider.
func New(store storage.Backend, logger *slog.Logger) *Provider {
	return &Provider{
		store:  store,
		logger: logger,
	}
}

// Name returns the provider identifier.
func (p *Provider) Name() string {
	return "openssf_scorecard"
}

// Run writes all OpenSSF Scorecard v5 controls to storage.
func (p *Provider) Run(ctx context.Context) (int, error) {
	p.logger.Info("loading OpenSSF Scorecard v5 controls")

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

	p.logger.Info("wrote OpenSSF Scorecard controls to storage", "count", count)
	return count, nil
}

func staticControls() []grc.Control {
	ref := func(checkName string) []grc.Reference {
		return []grc.Reference{{
			Source:  "OpenSSF Scorecard v5",
			URL:     "https://securityscorecards.dev/#" + checkName,
			Section: checkName,
		}}
	}

	return []grc.Control{
		{
			Framework:   FrameworkID,
			ControlID:   "SC-VULN",
			Title:       "Vulnerabilities",
			Family:      "Supply Chain Security",
			Description: "Checks whether the project has unfixed vulnerabilities in its dependencies using the OSV database. Projects with unpatched known vulnerabilities directly increase CVE exposure risk for downstream consumers. Timely remediation of dependency vulnerabilities is essential to reduce supply-chain attack surface.",
			Level:       "automated",
			RelatedCWEs: []string{"CWE-1035", "CWE-1104"},
			Tags:        []string{"vulnerability-management", "supply-chain"},
			References:  ref("Vulnerabilities"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "SC-MAINT",
			Title:       "Maintained",
			Family:      "Supply Chain Security",
			Description: "Checks whether the project is actively maintained by verifying recent commits, releases, or issue activity. Unmaintained projects accumulate unpatched vulnerabilities and are a significant source of supply-chain risk. Active maintenance signals that security issues will be addressed in a timely manner.",
			Level:       "automated",
			RelatedCWEs: []string{"CWE-1104"},
			Tags:        []string{"vulnerability-management", "governance"},
			References:  ref("Maintained"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "SC-CII",
			Title:       "CII-Best-Practices",
			Family:      "Supply Chain Security",
			Description: "Checks whether the project has earned an OpenSSF (CII) Best Practices Badge, demonstrating adherence to secure development practices. The badge programme covers a comprehensive set of SDLC security controls including vulnerability reporting, testing, and cryptography. Earning this badge indicates sustained commitment to security hygiene across the software development lifecycle.",
			Level:       "automated",
			RelatedCWEs: []string{},
			Tags:        []string{"governance", "sdlc"},
			References:  ref("CII-Best-Practices"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "SC-LICENSE",
			Title:       "License",
			Family:      "Supply Chain Security",
			Description: "Checks whether the project has a declared open-source license file. The absence of a license creates legal uncertainty for downstream consumers, which can impede security patching and vendor response. A clear license enables organisations to understand their obligations and facilitates transparent supply-chain governance.",
			Level:       "automated",
			RelatedCWEs: []string{},
			Tags:        []string{"governance"},
			References:  ref("License"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "SC-SIGNED",
			Title:       "Signed-Releases",
			Family:      "Supply Chain Security",
			Description: "Checks whether the project cryptographically signs its release artifacts, enabling consumers to verify authenticity and detect tampering. Unsigned releases are vulnerable to substitution attacks where a malicious actor replaces a legitimate artifact with a compromised one. Signing provides a verifiable chain of custody from build to deployment and directly mitigates CWE-494 Download of Code Without Integrity Check.",
			Level:       "automated",
			RelatedCWEs: []string{"CWE-494"},
			Tags:        []string{"provenance", "supply-chain", "integrity"},
			References:  ref("Signed-Releases"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "SC-BRANCH",
			Title:       "Branch-Protection",
			Family:      "Code Security",
			Description: "Checks whether the project enforces branch protection rules on its default branch, preventing unauthorized direct pushes and requiring status checks before merging. Without branch protection, a single compromised account can introduce malicious code into production. Enforcing branch protection is a fundamental access-control measure that limits the blast radius of credential compromise.",
			Level:       "automated",
			RelatedCWEs: []string{"CWE-284"},
			Tags:        []string{"access-control", "integrity"},
			References:  ref("Branch-Protection"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "SC-REVIEW",
			Title:       "Code-Review",
			Family:      "Code Security",
			Description: "Checks whether the project requires code review before changes are merged, reducing the risk of malicious or vulnerable code being introduced. Code review is a proven control for catching security defects early in the SDLC, and mandatory review requirements prevent single-actor compromise. This check helps ensure that no individual contributor can unilaterally introduce vulnerable or malicious dependencies.",
			Level:       "automated",
			RelatedCWEs: []string{"CWE-1357"},
			Tags:        []string{"sdlc", "supply-chain"},
			References:  ref("Code-Review"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "SC-PINNED",
			Title:       "Pinned-Dependencies",
			Family:      "Supply Chain Security",
			Description: "Checks whether the project pins its dependencies to specific cryptographic hashes rather than mutable version tags. Unpinned dependencies are vulnerable to dependency confusion and tag-poisoning attacks, where an attacker replaces a legitimate package version with a malicious one. Pinning dependencies to immutable hashes ensures reproducible builds and eliminates a critical class of supply-chain attack.",
			Level:       "automated",
			RelatedCWEs: []string{"CWE-829"},
			Tags:        []string{"supply-chain", "integrity"},
			References:  ref("Pinned-Dependencies"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "SC-TOKEN",
			Title:       "Token-Permissions",
			Family:      "Code Security",
			Description: "Checks whether the project's CI/CD workflows follow least-privilege principles by restricting the permissions of workflow tokens. Overly permissive tokens allow a compromised workflow to read secrets, push code, or modify releases beyond what is necessary. Restricting token permissions limits the impact of a CI/CD compromise and reduces privilege escalation risk.",
			Level:       "automated",
			RelatedCWEs: []string{"CWE-269", "CWE-284"},
			Tags:        []string{"access-control", "privilege"},
			References:  ref("Token-Permissions"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "SC-WORKFLOW",
			Title:       "Dangerous-Workflow",
			Family:      "Supply Chain Security",
			Description: "Checks whether the project's CI/CD workflows avoid dangerous patterns such as script injection from untrusted pull-request data. Dangerous workflows can be exploited by attackers who craft malicious pull requests to execute arbitrary code in the CI environment. Eliminating these patterns is essential to prevent supply-chain poisoning through the build pipeline.",
			Level:       "automated",
			RelatedCWEs: []string{"CWE-829", "CWE-284"},
			Tags:        []string{"supply-chain", "access-control"},
			References:  ref("Dangerous-Workflow"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "SC-POLICY",
			Title:       "Security-Policy",
			Family:      "Code Security",
			Description: "Checks whether the project publishes a security policy (SECURITY.md) that describes how to report vulnerabilities. A clear security policy enables responsible disclosure and ensures that vulnerability reporters know how to reach maintainers. Without a policy, critical vulnerabilities may go unaddressed or be disclosed publicly before a fix is available.",
			Level:       "automated",
			RelatedCWEs: []string{},
			Tags:        []string{"governance"},
			References:  ref("Security-Policy"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "SC-BINARY",
			Title:       "Binary-Artifacts",
			Family:      "Supply Chain Security",
			Description: "Checks whether the project's source repository contains binary artifacts, which are difficult to audit and may conceal malicious code. Binary blobs in source repositories bypass code review and create opaque dependencies whose provenance cannot be verified. Eliminating binary artifacts from source control is a foundational supply-chain integrity control.",
			Level:       "automated",
			RelatedCWEs: []string{"CWE-494"},
			Tags:        []string{"provenance", "integrity"},
			References:  ref("Binary-Artifacts"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "SC-SAST",
			Title:       "SAST",
			Family:      "Code Security",
			Description: "Checks whether the project uses static application security testing (SAST) tools to identify security defects in source code. Automated static analysis catches common vulnerability classes such as injection flaws, insecure API usage, and memory safety issues before code reaches production. Integrating SAST into the CI pipeline provides continuous security feedback and reduces the cost of remediation.",
			Level:       "automated",
			RelatedCWEs: []string{"CWE-1039"},
			Tags:        []string{"testing", "sdlc"},
			References:  ref("SAST"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "SC-FUZZ",
			Title:       "Fuzzing",
			Family:      "Code Security",
			Description: "Checks whether the project uses fuzzing to discover unexpected inputs that trigger crashes, memory corruption, or other security defects. Fuzzing is particularly effective at finding vulnerabilities that are difficult to detect through manual review or traditional unit testing. Continuous fuzzing via OSS-Fuzz or similar platforms provides ongoing coverage against newly introduced parsing and memory-safety bugs.",
			Level:       "automated",
			RelatedCWEs: []string{"CWE-1039"},
			Tags:        []string{"testing", "sdlc"},
			References:  ref("Fuzzing"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "SC-DEP-UPDATE",
			Title:       "Dependency-Update-Tool",
			Family:      "Supply Chain Security",
			Description: "Checks whether the project uses an automated dependency update tool such as Dependabot or Renovate to keep dependencies current. Stale dependencies are a primary source of known-vulnerability exposure, and automated update tools reduce the time-to-remediation for newly published CVEs. Regular dependency updates are a key control for managing software composition risk.",
			Level:       "automated",
			RelatedCWEs: []string{"CWE-1104"},
			Tags:        []string{"vulnerability-management"},
			References:  ref("Dependency-Update-Tool"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "SC-PACKAGING",
			Title:       "Packaging",
			Family:      "Supply Chain Security",
			Description: "Checks whether the project publishes its packages to a recognised package registry with proper provenance information. Publishing to official registries with verifiable metadata ensures that consumers can authenticate artifacts and trace them to their source repository. Proper packaging practices reduce the risk of package confusion attacks and improve supply-chain traceability.",
			Level:       "automated",
			RelatedCWEs: []string{"CWE-494"},
			Tags:        []string{"provenance", "supply-chain"},
			References:  ref("Packaging"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "SC-CONTRIBUTORS",
			Title:       "Contributors",
			Family:      "Code Security",
			Description: "Checks whether the project has a healthy contributor base with multiple active contributors from different organisations, reducing single-point-of-failure risk. Projects maintained by a single individual or organisation are more susceptible to account compromise and insider-threat scenarios. Diverse contributor populations improve resilience and reduce governance risk.",
			Level:       "automated",
			RelatedCWEs: []string{"CWE-284"},
			Tags:        []string{"access-control", "governance"},
			References:  ref("Contributors"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "SC-SBOM",
			Title:       "SBOM",
			Family:      "Supply Chain Security",
			Description: "Checks whether the project generates and publishes a Software Bill of Materials (SBOM) listing all components and their versions. An SBOM enables consumers to perform rapid vulnerability impact analysis when new CVEs are published against included components. Publishing a machine-readable SBOM is a foundational supply-chain transparency control required by many regulatory frameworks.",
			Level:       "automated",
			RelatedCWEs: []string{"CWE-1357"},
			Tags:        []string{"supply-chain", "provenance"},
			References:  ref("SBOM"),
		},
	}
}
