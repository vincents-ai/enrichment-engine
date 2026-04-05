package cyclonedx

type Bom struct {
	BOMFormat       string          `json:"bomFormat"`
	SpecVersion     string          `json:"specVersion"`
	SerialNumber    string          `json:"serialNumber"`
	Version         int             `json:"version"`
	Metadata        *Metadata       `json:"metadata,omitempty"`
	Components      []Component     `json:"components,omitempty"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities,omitempty"`
}

type Metadata struct {
	Timestamp string     `json:"timestamp"`
	Tools     []Tool     `json:"tools,omitempty"`
	Component *Component `json:"component,omitempty"`
}

type Tool struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

type Component struct {
	Type       string     `json:"type"`
	Name       string     `json:"name"`
	Version    string     `json:"version,omitempty"`
	CPE        string     `json:"cpe,omitempty"`
	Properties []Property `json:"properties,omitempty"`
}

type Vulnerability struct {
	ID         string     `json:"id"`
	Source     *Source    `json:"source,omitempty"`
	Ratings    []Rating   `json:"ratings,omitempty"`
	Affects    []Affects  `json:"affects,omitempty"`
	Properties []Property `json:"properties,omitempty"`
}

type Source struct {
	Name string `json:"name"`
	URL  string `json:"url,omitempty"`
}

type Rating struct {
	Source        *Source `json:"source,omitempty"`
	Score         float64 `json:"score"`
	Severity      string  `json:"severity,omitempty"`
	Method        string  `json:"method,omitempty"`
	Justification string  `json:"justification,omitempty"`
}

type Affects struct {
	Ref string `json:"ref"`
}

type Property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
