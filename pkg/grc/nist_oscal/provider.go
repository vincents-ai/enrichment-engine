// Deprecated: this provider is a duplicate of nist_sp800_53. Both parse the same
// NIST SP 800-53 Rev 5 OSCAL catalog, but nist_sp800_53 is superior (embedded
// data, hardcoded CWE mappings, family tags, control enhancement recursion) and
// follows ADR-015 (no runtime fetch). Unregistered from builtin registry.
package nist_oscal

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

const FrameworkID = "NIST_800_53_r5"

var NISTCatalogURL = "https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json"

// Provider fetches and parses NIST SP 800-53 rev5 controls from OSCAL format.
type Provider struct {
	store  storage.Backend
	logger *slog.Logger
}

// New creates a new NIST OSCAL provider.
func New(store storage.Backend, logger *slog.Logger) *Provider {
	return &Provider{
		store:  store,
		logger: logger,
	}
}

// Name returns the provider identifier.
func (p *Provider) Name() string {
	return "nist_oscal"
}

// Run fetches the NIST catalog, parses controls, and writes them to storage.
func (p *Provider) Run(ctx context.Context) (int, error) {
	p.logger.Info("fetching NIST SP 800-53 rev5 catalog", "url", NISTCatalogURL)

	f, err := os.CreateTemp("", "nist_catalog_*.json")
	if err != nil {
		return 0, fmt.Errorf("create temp file: %w", err)
	}
	destPath := f.Name()
	f.Close()
	defer os.Remove(destPath)
	if err := p.download(ctx, NISTCatalogURL, destPath); err != nil {
		return 0, fmt.Errorf("download catalog: %w", err)
	}

	controls, err := p.parse(destPath)
	if err != nil {
		return 0, fmt.Errorf("parse catalog: %w", err)
	}

	p.logger.Info("parsed NIST controls", "count", len(controls))

	count := 0
	for _, ctrl := range controls {
		id := fmt.Sprintf("%s/%s", FrameworkID, ctrl.ControlID)
		if err := p.store.WriteControl(ctx, id, ctrl); err != nil {
			p.logger.Warn("failed to write control", "id", id, "error", err)
			continue
		}
		count++
	}

	p.logger.Info("wrote NIST controls to storage", "count", count)
	return count, nil
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

// oscalCatalog is the top-level OSCAL catalog structure.
type oscalCatalog struct {
	Catalog struct {
		UUID     string `json:"uuid"`
		Metadata struct {
			Title        string `json:"title"`
			LastModified string `json:"last-modified"`
		} `json:"metadata"`
		Groups []oscalGroup `json:"groups"`
	} `json:"catalog"`
}

type oscalGroup struct {
	ID       string         `json:"id"`
	Class    string         `json:"class"`
	Title    string         `json:"title"`
	Controls []oscalControl `json:"controls"`
	Groups   []oscalGroup   `json:"groups,omitempty"`
}

type oscalControl struct {
	ID     string `json:"id"`
	Class  string `json:"class,omitempty"`
	Title  string `json:"title"`
	Params []struct {
		ID    string `json:"id"`
		Label string `json:"label"`
	} `json:"params,omitempty"`
	Props []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	} `json:"props,omitempty"`
	Parts []oscalPart `json:"parts,omitempty"`
}

type oscalPart struct {
	Name  string      `json:"name"`
	Title string      `json:"title,omitempty"`
	Prose string      `json:"prose,omitempty"`
	Parts []oscalPart `json:"parts,omitempty"`
}

func (p *Provider) parse(path string) ([]grc.Control, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var catalog oscalCatalog
	if err := json.NewDecoder(f).Decode(&catalog); err != nil {
		return nil, fmt.Errorf("decode OSCAL catalog: %w", err)
	}

	var controls []grc.Control
	for _, group := range catalog.Catalog.Groups {
		controls = append(controls, p.extractControls(group)...)
	}

	return controls, nil
}

func (p *Provider) extractControls(group oscalGroup) []grc.Control {
	var controls []grc.Control

	for _, ctrl := range group.Controls {
		description := p.extractProse(ctrl.Parts)

		control := grc.Control{
			Framework:              FrameworkID,
			ControlID:              ctrl.ID,
			Title:                  ctrl.Title,
			Family:                 group.Title,
			Description:            description,
			ImplementationGuidance: p.extractGuidance(ctrl.Parts),
			AssessmentMethods:      p.extractAssessmentMethods(ctrl.Parts),
		}

		// Extract related CWEs from props
		for _, prop := range ctrl.Props {
			if prop.Name == "cwe" {
				control.RelatedCWEs = append(control.RelatedCWEs, prop.Value)
			}
		}

		// Determine level from class
		switch strings.ToLower(ctrl.Class) {
		case "critical":
			control.Level = "critical"
		case "high":
			control.Level = "high"
		case "moderate":
			control.Level = "standard"
		default:
			control.Level = "standard"
		}

		controls = append(controls, control)
	}

	// Recurse into nested groups
	for _, subGroup := range group.Groups {
		controls = append(controls, p.extractControls(subGroup)...)
	}

	return controls
}

func (p *Provider) extractProse(parts []oscalPart) string {
	for _, part := range parts {
		if part.Name == "statement" && part.Prose != "" {
			return part.Prose
		}
	}
	return ""
}

func (p *Provider) extractGuidance(parts []oscalPart) string {
	for _, part := range parts {
		if part.Name == "guidance" && part.Prose != "" {
			return part.Prose
		}
	}
	return ""
}

func (p *Provider) extractAssessmentMethods(parts []oscalPart) []string {
	var methods []string
	for _, part := range parts {
		if part.Name == "assessment-objective" && part.Prose != "" {
			methods = append(methods, part.Prose)
		}
	}
	return methods
}
