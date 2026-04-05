package cyclonedx

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/shift/enrichment-engine/pkg/storage"
)

type Serializer struct {
	store    storage.Backend
	toolName string
	toolVer  string
}

type SerializerOption func(*Serializer)

func WithToolName(n string) SerializerOption    { return func(s *Serializer) { s.toolName = n } }
func WithToolVersion(v string) SerializerOption { return func(s *Serializer) { s.toolVer = v } }

func NewSerializer(store storage.Backend, opts ...SerializerOption) *Serializer {
	s := &Serializer{
		store:    store,
		toolName: "enrichment-engine",
		toolVer:  "dev",
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

func (s *Serializer) Serialize(ctx context.Context) (*Bom, error) {
	vulns, err := s.store.ListAllVulnerabilities(ctx)
	if err != nil {
		return nil, fmt.Errorf("list vulnerabilities: %w", err)
	}
	controls, err := s.store.ListAllControls(ctx)
	if err != nil {
		return nil, fmt.Errorf("list controls: %w", err)
	}

	controlMap := make(map[string]*storage.ControlRow, len(controls))
	for i := range controls {
		controlMap[controls[i].ID] = &controls[i]
	}

	frameworkSet := make(map[string]bool)
	for _, ctrl := range controls {
		frameworkSet[ctrl.Framework] = true
	}
	frameworkList := make([]string, 0, len(frameworkSet))
	for f := range frameworkSet {
		frameworkList = append(frameworkList, f)
	}

	bom := &Bom{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.5",
		SerialNumber: fmt.Sprintf("urn:uuid:%s", generateUUID()),
		Version:      1,
		Metadata: &Metadata{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Tools: []Tool{
				{Name: s.toolName, Version: s.toolVer},
			},
		},
		Components: []Component{
			{
				Type: "application",
				Name: "GRC Enrichment Report",
				Properties: []Property{
					{Name: "frameworks", Value: marshalStringList(frameworkList)},
					{Name: "total_controls", Value: fmt.Sprintf("%d", len(controls))},
					{Name: "total_vulnerabilities", Value: fmt.Sprintf("%d", len(vulns))},
				},
			},
		},
	}

	for _, vuln := range vulns {
		mappings, err := s.store.ListMappings(ctx, vuln.ID)
		if err != nil {
			return nil, fmt.Errorf("list mappings for %s: %w", vuln.ID, err)
		}
		if len(mappings) == 0 {
			continue
		}

		var affects []Affects
		var props []Property
		seenControls := make(map[string]bool)
		for _, m := range mappings {
			affects = append(affects, Affects{Ref: m.ControlID})
			props = append(props, Property{
				Name:  fmt.Sprintf("mapping:%s:%s", m.ControlID, m.MappingType),
				Value: fmt.Sprintf("framework=%s,confidence=%.2f", m.Framework, m.Confidence),
			})
			if ctrl, ok := controlMap[m.ControlID]; ok && !seenControls[m.ControlID] {
				seenControls[m.ControlID] = true
				props = append(props, Property{
					Name:  fmt.Sprintf("control:%s:title", m.ControlID),
					Value: ctrl.Title,
				})
			}
		}

		bom.Vulnerabilities = append(bom.Vulnerabilities, Vulnerability{
			ID:         vuln.ID,
			Source:     &Source{Name: "NVD", URL: "https://nvd.nist.gov/vuln/detail/" + vuln.ID},
			Affects:    affects,
			Properties: props,
		})
	}

	return bom, nil
}

func (s *Serializer) SerializeJSON(ctx context.Context) ([]byte, error) {
	bom, err := s.Serialize(ctx)
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(bom, "", "  ")
}
