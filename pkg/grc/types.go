package grc

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
}

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
