package nist_sp800_53

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/vincents-ai/enrichment-engine/pkg/grc"
	"github.com/vincents-ai/enrichment-engine/pkg/storage"
)

const FrameworkID = "NIST_SP800_53_R5"

//go:embed nist_sp800_53_r5_catalog.json
var embeddedCatalog []byte

// Provider parses and provides NIST SP 800-53 Rev.5 controls from a build-time
// embedded OSCAL catalog (ADR-015: no runtime fetch).
type Provider struct {
	store  storage.Backend
	logger *slog.Logger
}

// New creates a new NIST SP 800-53 Rev.5 provider.
func New(store storage.Backend, logger *slog.Logger) *Provider {
	return &Provider{
		store:  store,
		logger: logger,
	}
}

// Name returns the provider identifier.
func (p *Provider) Name() string {
	return "nist_sp800_53"
}

// Run parses the embedded NIST SP 800-53 Rev.5 OSCAL catalog and writes all
// controls (including control enhancements) to storage.
func (p *Provider) Run(ctx context.Context) (int, error) {
	p.logger.Info("loading NIST SP 800-53 Rev.5 controls from embedded catalog")

	controls, err := p.parse(embeddedCatalog)
	if err != nil {
		return 0, fmt.Errorf("parse embedded catalog: %w", err)
	}

	p.logger.Info("parsed NIST SP 800-53 controls", "count", len(controls))

	count := 0
	for _, ctrl := range controls {
		id := fmt.Sprintf("%s/%s", FrameworkID, ctrl.ControlID)
		if err := p.store.WriteControl(ctx, id, ctrl); err != nil {
			p.logger.Warn("failed to write control", "id", id, "error", err)
			continue
		}
		count++
	}

	p.logger.Info("wrote NIST SP 800-53 controls to storage", "count", count)
	return count, nil
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
	ID       string         `json:"id"`
	Class    string         `json:"class,omitempty"`
	Title    string         `json:"title"`
	Params   []oscalParam   `json:"params,omitempty"`
	Props    []oscalProp    `json:"props,omitempty"`
	Parts    []oscalPart    `json:"parts,omitempty"`
	Controls []oscalControl `json:"controls,omitempty"` // control enhancements
}

type oscalParam struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

type oscalProp struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type oscalPart struct {
	Name  string      `json:"name"`
	Title string      `json:"title,omitempty"`
	Prose string      `json:"prose,omitempty"`
	Parts []oscalPart `json:"parts,omitempty"`
}

func (p *Provider) parse(data []byte) ([]grc.Control, error) {
	var catalog oscalCatalog
	if err := json.Unmarshal(data, &catalog); err != nil {
		return nil, fmt.Errorf("decode OSCAL catalog: %w", err)
	}

	var controls []grc.Control
	for _, group := range catalog.Catalog.Groups {
		controls = append(controls, p.extractGroup(group)...)
	}
	return controls, nil
}

func (p *Provider) extractGroup(group oscalGroup) []grc.Control {
	var controls []grc.Control

	for _, ctrl := range group.Controls {
		controls = append(controls, p.extractControl(group, ctrl)...)
	}

	// Recurse into nested groups (OSCAL spec allows this)
	for _, subGroup := range group.Groups {
		controls = append(controls, p.extractGroup(subGroup)...)
	}

	return controls
}

func (p *Provider) extractControl(group oscalGroup, ctrl oscalControl) []grc.Control {
	var controls []grc.Control

	description := extractProse(ctrl.Parts, "statement")
	guidance := extractProse(ctrl.Parts, "guidance")
	assessment := extractProseAll(ctrl.Parts, "assessment-objective")

	// Build CWE list: start with any CWEs in OSCAL props, then apply our map.
	cwes := make([]string, 0)
	for _, prop := range ctrl.Props {
		if prop.Name == "cwe" {
			cwes = append(cwes, prop.Value)
		}
	}
	if mapped := cweMap[strings.ToLower(ctrl.ID)]; len(mapped) > 0 {
		cwes = mergeUnique(cwes, mapped)
	}

	control := grc.Control{
		Framework:              FrameworkID,
		ControlID:              ctrl.ID,
		Title:                  ctrl.Title,
		Family:                 group.Title,
		Description:            description,
		ImplementationGuidance: guidance,
		AssessmentMethods:      assessment,
		RelatedCWEs:            cwes,
		Tags:                   familyTags(group.ID),
		Level:                  "standard",
	}

	controls = append(controls, control)

	// Recurse into control enhancements (sub-controls)
	for _, enhancement := range ctrl.Controls {
		controls = append(controls, p.extractControl(group, enhancement)...)
	}

	return controls
}

// cweMap maps control IDs (lowercase) to CWE identifiers.
// Focused on families where OSCAL props are empty: AC, IA, SC, SI, SR, SA, CM, AU, RA.
var cweMap = map[string][]string{
	// Access Control
	"ac-2":  {"CWE-284", "CWE-269"},
	"ac-3":  {"CWE-284"},
	"ac-6":  {"CWE-269"},
	"ac-17": {"CWE-284"},
	// Identification and Authentication
	"ia-2": {"CWE-287", "CWE-308"},
	"ia-5": {"CWE-255", "CWE-521"},
	"ia-8": {"CWE-287"},
	// System and Communications Protection
	"sc-8":  {"CWE-319"},
	"sc-13": {"CWE-326", "CWE-327"},
	"sc-28": {"CWE-311"},
	// System and Information Integrity
	"si-2":  {"CWE-1104", "CWE-1329"},
	"si-3":  {"CWE-506"},
	"si-10": {"CWE-20"},
	// Supply Chain Risk Management (SR family — key differentiator)
	"sr-3":  {"CWE-1357"},
	"sr-4":  {"CWE-1357", "CWE-494"},
	"sr-10": {"CWE-1329"},
	"sr-11": {"CWE-494", "CWE-829"},
	// Software and Systems Acquisition
	"sa-8":  {"CWE-1357"},
	"sa-15": {"CWE-1357"},
	"sa-17": {"CWE-1357"},
	// Configuration Management
	"cm-2": {"CWE-16"},
	"cm-6": {"CWE-16"},
	"cm-7": {"CWE-284"},
	// Audit and Accountability
	"au-2": {"CWE-778"},
	"au-9": {"CWE-284"},
	// Risk Assessment
	"ra-5": {"CWE-1104"},
}

// familyTags returns tags for a given control family ID.
var familyTagMap = map[string][]string{
	"ac": {"access-control", "authentication"},
	"at": {"training"},
	"au": {"logging"},
	"ca": {"assessment"},
	"cm": {"configuration"},
	"cp": {"continuity"},
	"ia": {"access-control", "authentication"},
	"ir": {"incident-response"},
	"ma": {"maintenance"},
	"mp": {"media-protection"},
	"pe": {"physical"},
	"pl": {"planning"},
	"pm": {"program-management"},
	"ps": {"personnel"},
	"pt": {"privacy"},
	"ra": {"vulnerability-management"},
	"sa": {"supply-chain", "integrity"},
	"sc": {"cryptography", "network"},
	"si": {"vulnerability-management", "integrity"},
	"sr": {"supply-chain", "integrity"},
}

func familyTags(groupID string) []string {
	if tags, ok := familyTagMap[strings.ToLower(groupID)]; ok {
		return tags
	}
	return nil
}

func extractProse(parts []oscalPart, name string) string {
	for _, part := range parts {
		if part.Name == name && part.Prose != "" {
			return part.Prose
		}
	}
	return ""
}

func extractProseAll(parts []oscalPart, name string) []string {
	var results []string
	for _, part := range parts {
		if part.Name == name && part.Prose != "" {
			results = append(results, part.Prose)
		}
	}
	return results
}

func mergeUnique(existing, additional []string) []string {
	seen := make(map[string]struct{}, len(existing))
	for _, v := range existing {
		seen[v] = struct{}{}
	}
	result := make([]string, len(existing))
	copy(result, existing)
	for _, v := range additional {
		if _, ok := seen[v]; !ok {
			result = append(result, v)
			seen[v] = struct{}{}
		}
	}
	return result
}
