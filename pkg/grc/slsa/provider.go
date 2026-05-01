package slsa

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/vincents-ai/enrichment-engine/pkg/grc"
	"github.com/vincents-ai/enrichment-engine/pkg/storage"
)

const FrameworkID = "SLSA"

// Provider implements SLSA (Supply-chain Levels for Software Artifacts) v1.0.
type Provider struct {
	store  storage.Backend
	logger *slog.Logger
}

// New creates a new SLSA provider.
func New(store storage.Backend, logger *slog.Logger) *Provider {
	return &Provider{
		store:  store,
		logger: logger,
	}
}

// Name returns the provider identifier.
func (p *Provider) Name() string {
	return "slsa"
}

// Run writes all SLSA controls to storage.
func (p *Provider) Run(ctx context.Context) (int, error) {
	p.logger.Info("loading SLSA v1.0 controls")

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

	p.logger.Info("wrote SLSA controls to storage", "count", count)
	return count, nil
}

func staticControls() []grc.Control {
	ref := func(section string) []grc.Reference {
		return []grc.Reference{{Source: "SLSA v1.0", URL: "https://slsa.dev/spec/v1.0/", Section: section}}
	}

	return []grc.Control{
		{
			Framework:   FrameworkID,
			ControlID:   "L1.BUILD.1",
			Title:       "Provenance exists",
			Family:      "Build L1",
			Description: "The build system produces provenance for the artifact.",
			Level:       "l1",
			RelatedCWEs: []string{"CWE-494"},
			Tags:        []string{"provenance", "build-integrity", "supply-chain"},
			References:  ref("L1/build"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "L1.BUILD.2",
			Title:       "Provenance is authenticated",
			Family:      "Build L1",
			Description: "Provenance is signed or otherwise authenticated by the build platform.",
			Level:       "l1",
			RelatedCWEs: []string{"CWE-294", "CWE-287"},
			Tags:        []string{"provenance", "authentication"},
			References:  ref("L1/build"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "L2.BUILD.1",
			Title:       "Hosted build platform",
			Family:      "Build L2",
			Description: "The build runs on a hosted platform that generates and signs provenance.",
			Level:       "l2",
			RelatedCWEs: []string{"CWE-494", "CWE-829"},
			Tags:        []string{"build-integrity", "supply-chain"},
			References:  ref("L2/build"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "L2.BUILD.2",
			Title:       "Build environment is isolated",
			Family:      "Build L2",
			Description: "Each build runs in an isolated environment with least-privilege access.",
			Level:       "l2",
			RelatedCWEs: []string{"CWE-250"},
			Tags:        []string{"isolation", "privilege"},
			References:  ref("L2/build"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "L3.BUILD.1",
			Title:       "Provenance is non-falsifiable",
			Family:      "Build L3",
			Description: "Provenance is generated and signed in a way that cannot be forged by the build scripts.",
			Level:       "l3",
			RelatedCWEs: []string{"CWE-494", "CWE-345"},
			Tags:        []string{"provenance", "integrity"},
			References:  ref("L3/build"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "L3.BUILD.2",
			Title:       "Build steps are parameterless",
			Family:      "Build L3",
			Description: "Build steps do not accept parameters that could inject malicious commands.",
			Level:       "l3",
			RelatedCWEs: []string{"CWE-78", "CWE-77"},
			Tags:        []string{"injection", "build-integrity"},
			References:  ref("L3/build"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "L3.BUILD.3",
			Title:       "All dependencies are pinned",
			Family:      "Build L3",
			Description: "All external dependencies are pinned to specific cryptographic hashes.",
			Level:       "l3",
			RelatedCWEs: []string{"CWE-1357"},
			Tags:        []string{"supply-chain", "dependency"},
			References:  ref("L3/build"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "L4.BUILD.1",
			Title:       "Hermetic build",
			Family:      "Build L4",
			Description: "The build runs hermetically with no network access or external dependencies.",
			Level:       "l4",
			RelatedCWEs: []string{"CWE-829"},
			Tags:        []string{"build-integrity", "isolation"},
			References:  ref("L4/build"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "L4.BUILD.2",
			Title:       "Two-party review on build config",
			Family:      "Build L4",
			Description: "Changes to build configuration require review and approval by a second party.",
			Level:       "l4",
			RelatedCWEs: []string{"CWE-693"},
			Tags:        []string{"governance", "supply-chain"},
			References:  ref("L4/build"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "L1.SOURCE.1",
			Title:       "Version controlled",
			Family:      "Source L1",
			Description: "All source code is stored in a version control system.",
			Level:       "l1",
			RelatedCWEs: []string{"CWE-494"},
			Tags:        []string{"integrity", "provenance"},
			References:  ref("L1/source"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "L2.SOURCE.1",
			Title:       "Branch protection",
			Family:      "Source L2",
			Description: "Branch protection rules prevent direct pushes to protected branches.",
			Level:       "l2",
			RelatedCWEs: []string{"CWE-284"},
			Tags:        []string{"access-control"},
			References:  ref("L2/source"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "L3.SOURCE.1",
			Title:       "History is retained",
			Family:      "Source L3",
			Description: "Source history cannot be deleted or rewritten by any individual.",
			Level:       "l3",
			RelatedCWEs: []string{"CWE-345"},
			Tags:        []string{"integrity"},
			References:  ref("L3/source"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "L3.SOURCE.2",
			Title:       "Verified history",
			Family:      "Source L3",
			Description: "The VCS cryptographically authenticates and makes the commit history tamper-evident.",
			Level:       "l3",
			RelatedCWEs: []string{"CWE-345"},
			Tags:        []string{"integrity", "provenance"},
			References:  ref("L3/source"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "L4.SOURCE.1",
			Title:       "Two-party review on source changes",
			Family:      "Source L4",
			Description: "All source changes are reviewed and approved by a second party before merging.",
			Level:       "l4",
			RelatedCWEs: []string{},
			Tags:        []string{"governance"},
			References:  ref("L4/source"),
		},
	}
}
