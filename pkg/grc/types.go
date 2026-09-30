package grc

import "time"

// Control represents a GRC compliance control from any framework.
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
	Tags                   []string    `json:"Tags,omitempty"`

	// Provenance records HOW this control's content was obtained, which is not
	// the same question as which standard it cites.
	//
	// It exists because a provider that fails to download an official catalog
	// previously fell back to locally written mappings while still citing the
	// authority as the source. A stored control then said "ENISA" and linked to
	// ENISA for content nobody fetched from ENISA, which is a false regulatory
	// claim in a compliance product — the sort of thing that would be relied on
	// in an audit and could not be substantiated.
	//
	// The distinction is exactly the one the remediation brief draws between an
	// official catalog, a local interpretation, and a provisional entry. A
	// consumer that must not treat a mapping as compliance evidence can filter on
	// this; a consumer displaying source freshness can show it.
	Provenance ControlProvenance `json:"Provenance,omitempty"`

	// SourceRetrievedAt is when the upstream document was actually fetched. It is
	// zero for locally written controls, because no document was fetched. A
	// retrieval timestamp for content that was never retrieved is the same class
	// of defect as R02 in the regulatory registry, where SourceHash was computed
	// from a label rather than from the source bytes.
	SourceRetrievedAt time.Time `json:"SourceRetrievedAt,omitempty"`

	// ProvenanceNote explains the provenance in human terms for an operator
	// reading the stored control.
	ProvenanceNote string `json:"ProvenanceNote,omitempty"`
}

// ControlProvenance distinguishes an officially retrieved catalog from a locally
// written interpretation.
type ControlProvenance string

const (
	// ProvenanceOfficial means the content was parsed from a document fetched
	// from the cited authority.
	ProvenanceOfficial ControlProvenance = "official"

	// ProvenanceLocalInterpretation means the content was written locally and
	// the cited authority did NOT supply it. It may be accurate, and it may be
	// reviewed, but it is not authoritative and must not be presented as though
	// it were fetched.
	ProvenanceLocalInterpretation ControlProvenance = "local_interpretation"
)

// Reference is an external citation or documentation link for a control.
type Reference struct {
	Source  string `json:"source,omitempty"`
	URL     string `json:"url,omitempty"`
	Section string `json:"section,omitempty"`
}

// Mapping represents a link between a vulnerability and a GRC control.
type Mapping struct {
	VulnerabilityID string  `json:"vulnerability_id"`
	ControlID       string  `json:"control_id"`
	Framework       string  `json:"framework"`
	MappingType     string  `json:"mapping_type"`
	Confidence      float64 `json:"confidence"`
	Evidence        string  `json:"evidence,omitempty"`
}

// MappingType defines how a vulnerability maps to a control.
type MappingType string

const (
	MappingTypeCWE    MappingType = "cwe"
	MappingTypeCPE    MappingType = "cpe"
	MappingTypeTag    MappingType = "tag"
	MappingTypeManual MappingType = "manual"
)

// SBOMComponent represents a component from a Software Bill of Materials.
type SBOMComponent struct {
	Name    string   `json:"name"`
	Version string   `json:"version"`
	Type    string   `json:"type"`
	CPEs    []string `json:"cpes,omitempty"`
}

// EnrichedComponent is an SBOM component with GRC metadata attached.
type EnrichedComponent struct {
	SBOMComponent
	Vulnerabilities []string `json:"vulnerabilities,omitempty"`
	Controls        []string `json:"controls,omitempty"`
	Frameworks      []string `json:"frameworks,omitempty"`
	ComplianceRisk  string   `json:"compliance_risk,omitempty"`
}
