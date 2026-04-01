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

// Framework defines metadata for a GRC framework.
type Framework struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Version      string    `json:"version"`
	Description  string    `json:"description"`
	SourceURL    string    `json:"source_url"`
	LastUpdated  time.Time `json:"last_updated"`
	ControlCount int       `json:"control_count"`
}

// Asset represents an IT asset in the infrastructure topology.
type Asset struct {
	ID       string            `json:"id"`
	Name     string            `json:"name"`
	Type     string            `json:"type"`
	Provider string            `json:"provider,omitempty"`
	Region   string            `json:"region,omitempty"`
	Tags     map[string]string `json:"tags,omitempty"`
	CPEs     []string          `json:"cpes,omitempty"`
	LastSeen time.Time         `json:"last_seen"`
}

// Threat represents an operational threat intelligence entry.
type Threat struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Type        string    `json:"type"`
	Source      string    `json:"source"`
	Description string    `json:"description,omitempty"`
	Tactics     []string  `json:"tactics,omitempty"`
	Techniques  []string  `json:"techniques,omitempty"`
	IoCs        []string  `json:"iocs,omitempty"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
}

// Risk represents a quantified risk assessment.
type Risk struct {
	ID              string    `json:"id"`
	AssetID         string    `json:"asset_id"`
	VulnerabilityID string    `json:"vulnerability_id"`
	ControlID       string    `json:"control_id,omitempty"`
	Framework       string    `json:"framework,omitempty"`
	Likelihood      float64   `json:"likelihood"`
	Impact          float64   `json:"impact"`
	RiskScore       float64   `json:"risk_score"`
	Mitigated       bool      `json:"mitigated"`
	LastAssessed    time.Time `json:"last_assessed"`
}

// SBOMComponent represents a component from a Software Bill of Materials.
type SBOMComponent struct {
	Name    string   `json:"name"`
	Version string   `json:"version"`
	Type    string   `json:"type"`
	CPEs    []string `json:"cpes,omitempty"`
	PURL    string   `json:"purl,omitempty"`
}

// EnrichedComponent is an SBOM component with GRC metadata attached.
type EnrichedComponent struct {
	SBOMComponent
	Vulnerabilities []string `json:"vulnerabilities,omitempty"`
	Controls        []string `json:"controls,omitempty"`
	Frameworks      []string `json:"frameworks,omitempty"`
	ComplianceRisk  string   `json:"compliance_risk,omitempty"`
}
