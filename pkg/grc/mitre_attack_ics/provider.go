package mitre_attack_ics

// MITRE ATT&CK for ICS data is licensed under Apache 2.0.
// Copyright (c) The MITRE Corporation.
// See: https://github.com/mitre/cti/blob/master/LICENSE

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/shift/enrichment-engine/pkg/grc"
	"github.com/shift/enrichment-engine/pkg/storage"
)

const FrameworkID = "MITRE_ATTACK_ICS_V16"

//go:embed ics_attack.json
var embeddedCatalog []byte

// STIX2 bundle structures.
type stixBundle struct {
	Objects []stixObject `json:"objects"`
}

type stixObject struct {
	Type               string       `json:"type"`
	ID                 string       `json:"id"`
	Name               string       `json:"name"`
	Description        string       `json:"description"`
	ExternalReferences []stixExtRef `json:"external_references"`
	XMitreDomains      []string     `json:"x_mitre_domains"`
	Revoked            bool         `json:"revoked"`
	Labels             []string     `json:"labels"`
}

type stixExtRef struct {
	SourceName string `json:"source_name"`
	ExternalID string `json:"external_id"`
	URL        string `json:"url"`
}

// Provider parses and serves MITRE ATT&CK for ICS mitigations from a build-time
// embedded STIX2 bundle (ADR-015: build-time embed, no runtime fetch).
type Provider struct {
	store  storage.Backend
	logger *slog.Logger
}

// New creates a new MITRE ATT&CK ICS provider.
func New(store storage.Backend, logger *slog.Logger) *Provider {
	return &Provider{store: store, logger: logger}
}

// Name returns the provider identifier.
func (p *Provider) Name() string { return "mitre_attack_ics" }

// Run parses the embedded ICS ATT&CK catalog and writes controls to storage.
func (p *Provider) Run(ctx context.Context) (int, error) {
	p.logger.Info("parsing embedded MITRE ATT&CK for ICS catalog")

	controls, err := p.parse(embeddedCatalog)
	if err != nil {
		return 0, fmt.Errorf("parse ICS ATT&CK catalog: %w", err)
	}

	p.logger.Info("parsed MITRE ATT&CK ICS controls", "count", len(controls))

	count := 0
	for _, ctrl := range controls {
		id := fmt.Sprintf("%s/%s", FrameworkID, ctrl.ControlID)
		if err := p.store.WriteControl(ctx, id, ctrl); err != nil {
			p.logger.Warn("failed to write control", "id", id, "error", err)
			continue
		}
		count++
	}

	p.logger.Info("wrote MITRE ATT&CK ICS controls to storage", "count", count)
	return count, nil
}

// parse unmarshals the STIX2 bundle and extracts course-of-action objects as
// GRC controls. Only non-revoked objects in the "ics-attack" domain are included.
func (p *Provider) parse(data []byte) ([]grc.Control, error) {
	var bundle stixBundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		return nil, fmt.Errorf("unmarshal STIX bundle: %w", err)
	}

	var controls []grc.Control
	for _, obj := range bundle.Objects {
		if obj.Type != "course-of-action" {
			continue
		}
		if obj.Revoked {
			continue
		}
		if !containsDomain(obj.XMitreDomains, "ics-attack") {
			continue
		}

		extID, extURL := extractRef(obj.ExternalReferences, "mitre-attack")
		if extID == "" {
			// Fall back: some objects use "mitre-ics-attack" as source name.
			extID, extURL = extractRef(obj.ExternalReferences, "mitre-ics-attack")
		}
		if extID == "" {
			p.logger.Warn("course-of-action missing mitre-attack external_id", "stix_id", obj.ID, "name", obj.Name)
			continue
		}

		// Collect additional references (standards citations stored in labels).
		refs := []grc.Reference{{
			Source:  "MITRE ATT&CK for ICS",
			URL:     extURL,
			Section: extID,
		}}
		for _, label := range obj.Labels {
			refs = append(refs, grc.Reference{Source: label})
		}

		ctrl := grc.Control{
			Framework:   FrameworkID,
			ControlID:   extID,
			Title:       obj.Name,
			Family:      mitigationFamily(extID),
			Description: obj.Description,
			Level:       "standard",
			RelatedCWEs: icsCWEs(extID),
			Tags:        icsTags(extID),
			References:  refs,
		}
		controls = append(controls, ctrl)
	}

	return controls, nil
}

// containsDomain checks whether a domain slice contains the target domain.
func containsDomain(domains []string, target string) bool {
	for _, d := range domains {
		if strings.EqualFold(d, target) {
			return true
		}
	}
	return false
}

// extractRef returns the external_id and URL for the first reference whose
// source_name matches the given name.
func extractRef(refs []stixExtRef, sourceName string) (string, string) {
	for _, r := range refs {
		if r.SourceName == sourceName && r.ExternalID != "" {
			return r.ExternalID, r.URL
		}
	}
	return "", ""
}

// mitigationFamily returns a human-readable family label for an ICS mitigation ID.
func mitigationFamily(id string) string {
	families := map[string]string{
		// ICS-specific mitigations (M08xx range)
		"M0800": "Access Control",
		"M0801": "Access Control",
		"M0802": "Authentication",
		"M0803": "Data Protection",
		"M0804": "Authentication",
		"M0805": "Physical Security",
		"M0806": "Network Security",
		"M0807": "Network Security",
		"M0808": "Encryption",
		"M0809": "Data Protection",
		"M0810": "Network Security",
		"M0811": "Availability",
		"M0812": "Safety Systems",
		"M0813": "Authentication",
		"M0814": "Network Security",
		"M0815": "Availability",
		"M0816": "General",
		"M0817": "Supply Chain",
		"M0818": "Input Validation",
		// Enterprise mitigations also present in ICS (M09xx range)
		"M0913": "Application Security",
		"M0915": "Identity Management",
		"M0916": "Vulnerability Management",
		"M0917": "Security Awareness",
		"M0918": "Identity Management",
		"M0919": "Threat Intelligence",
		"M0920": "Network Security",
		"M0921": "Network Security",
		"M0922": "Access Control",
		"M0924": "Access Control",
		"M0926": "Identity Management",
		"M0927": "Identity Management",
		"M0928": "Configuration Management",
		"M0930": "Network Segmentation",
		"M0931": "Network Security",
		"M0932": "Authentication",
		"M0934": "Physical Security",
		"M0935": "Network Security",
		"M0936": "Identity Management",
		"M0937": "Network Security",
		"M0938": "Application Security",
		"M0941": "Encryption",
		"M0942": "Configuration Management",
		"M0944": "Application Security",
		"M0945": "Application Security",
		"M0946": "Integrity",
		"M0947": "Audit and Accountability",
		"M0948": "Application Security",
		"M0949": "Endpoint Protection",
		"M0950": "Endpoint Protection",
		"M0951": "Patch Management",
		"M0953": "Data Protection",
		"M0954": "Configuration Management",
	}
	if f, ok := families[id]; ok {
		return f
	}
	return "General"
}

// icsCWEMap maps ICS mitigation IDs to related CWE identifiers.
var icsCWEMap = map[string][]string{
	"M0800": {"CWE-284"},
	"M0801": {"CWE-284", "CWE-269"},
	"M0802": {"CWE-287", "CWE-295"},
	"M0803": {},
	"M0804": {"CWE-287", "CWE-308"},
	"M0805": {},
	"M0806": {},
	"M0807": {"CWE-284"},
	"M0808": {"CWE-311", "CWE-319"},
	"M0809": {"CWE-200"},
	"M0810": {"CWE-319"},
	"M0811": {},
	"M0812": {"CWE-284"},
	"M0813": {"CWE-287"},
	"M0814": {"CWE-284"},
	"M0815": {},
	"M0816": {},
	"M0817": {},
	"M0818": {"CWE-20"},
	"M0913": {},
	"M0915": {"CWE-287", "CWE-269"},
	"M0916": {},
	"M0917": {},
	"M0918": {"CWE-284", "CWE-269"},
	"M0919": {},
	"M0920": {"CWE-295", "CWE-326"},
	"M0921": {"CWE-284"},
	"M0922": {"CWE-284", "CWE-732"},
	"M0924": {"CWE-284"},
	"M0926": {"CWE-250", "CWE-269"},
	"M0927": {"CWE-521"},
	"M0928": {"CWE-16"},
	"M0930": {"CWE-284", "CWE-668"},
	"M0931": {"CWE-284"},
	"M0932": {"CWE-287", "CWE-308"},
	"M0934": {"CWE-284"},
	"M0935": {"CWE-284", "CWE-668"},
	"M0936": {"CWE-284"},
	"M0937": {"CWE-284"},
	"M0938": {"CWE-284"},
	"M0941": {"CWE-311", "CWE-312"},
	"M0942": {"CWE-284"},
	"M0944": {"CWE-829"},
	"M0945": {"CWE-494"},
	"M0946": {"CWE-494"},
	"M0947": {"CWE-778"},
	"M0948": {"CWE-284"},
	"M0949": {"CWE-494"},
	"M0950": {"CWE-787", "CWE-20"},
	"M0951": {},
	"M0953": {},
	"M0954": {"CWE-16"},
}

// icsCWEs returns the CWE list for an ICS mitigation ID.
func icsCWEs(id string) []string {
	cwes, ok := icsCWEMap[id]
	if !ok {
		return nil
	}
	if len(cwes) == 0 {
		return nil
	}
	return cwes
}

// icsTagsMap maps family names to additional secondary tags.
var familyTagMap = map[string]string{
	"Access Control":           "access-control",
	"Authentication":           "authentication",
	"Network Security":         "network-security",
	"Network Segmentation":     "network-segmentation",
	"Encryption":               "encryption",
	"Data Protection":          "data-protection",
	"Physical Security":        "physical-security",
	"Availability":             "availability",
	"Safety Systems":           "safety-systems",
	"Supply Chain":             "supply-chain",
	"Input Validation":         "input-validation",
	"Application Security":     "application-security",
	"Identity Management":      "identity-management",
	"Vulnerability Management": "vulnerability-management",
	"Security Awareness":       "security-awareness",
	"Threat Intelligence":      "threat-intelligence",
	"Configuration Management": "configuration-management",
	"Integrity":                "integrity",
	"Audit and Accountability": "audit",
	"Endpoint Protection":      "endpoint-protection",
	"Patch Management":         "patch-management",
}

// icsTags returns the tag set for a given ICS mitigation ID. All ICS controls
// receive the "ot-security" tag; secondary tags are derived from the family.
func icsTags(id string) []string {
	tags := []string{"ot-security"}
	family := mitigationFamily(id)
	if secondary, ok := familyTagMap[family]; ok {
		tags = append(tags, secondary)
	}
	return tags
}
