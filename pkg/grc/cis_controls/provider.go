package cis_controls

import (
	"context"
	_ "embed"
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

const (
	FrameworkID = "CIS_Controls_v8"
	CatalogURL  = "https://bitbucket.org/cis-it-workspace/cis-controls-v8.1_oscal/raw/75ec5f4f79f103a74420e2b93553ce429160a92c/src/catalogs/json/cis-controls-v8.1_catalog.json"
)

//go:embed cis_controls_v8.json
var embeddedCatalog []byte

// Provider fetches and parses CIS Controls v8.1.
type Provider struct {
	store  storage.Backend
	logger *slog.Logger
}

// New creates a new CIS Controls provider.
func New(store storage.Backend, logger *slog.Logger) *Provider {
	return &Provider{
		store:  store,
		logger: logger,
	}
}

// Name returns the provider identifier.
func (p *Provider) Name() string {
	return "cis_controls"
}

// Run fetches the CIS Controls catalog, parses controls, and writes them to storage.
func (p *Provider) Run(ctx context.Context) (int, error) {
	p.logger.Info("fetching CIS Controls v8.1 catalog", "url", CatalogURL)

	f, err := os.CreateTemp("", "cis_controls_v8_*.json")
	if err != nil {
		return 0, fmt.Errorf("create temp file: %w", err)
	}
	destPath := f.Name()
	f.Close()
	defer os.Remove(destPath)

	var data []byte

	if err = p.download(ctx, CatalogURL, destPath); err != nil {
		p.logger.Warn("failed to download catalog, using embedded fallback", "error", err)
		data = embeddedCatalog
	} else {
		data, err = os.ReadFile(destPath)
		if err != nil {
			return 0, fmt.Errorf("read catalog: %w", err)
		}
	}

	controls, err := p.parse(data)
	if err != nil {
		return 0, fmt.Errorf("parse catalog: %w", err)
	}

	if len(controls) == 0 {
		p.logger.Warn("parsed 0 controls from downloaded catalog, falling back to embedded", "url", CatalogURL)
		controls, err = p.parse(embeddedCatalog)
		if err != nil {
			return 0, fmt.Errorf("parse embedded catalog: %w", err)
		}
	}

	p.logger.Info("parsed CIS Controls", "count", len(controls))

	count := 0
	for _, ctrl := range controls {
		id := fmt.Sprintf("%s/%s", FrameworkID, ctrl.ControlID)
		if err := p.store.WriteControl(ctx, id, ctrl); err != nil {
			p.logger.Warn("failed to write control", "id", id, "error", err)
			continue
		}
		count++
	}

	p.logger.Info("wrote CIS Controls to storage", "count", count)
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

// cisCatalog is the top-level CIS Controls structure.
type cisCatalog struct {
	ImplementationGroups []cisIG `json:"implementationGroups"`
}

type cisIG struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Controls    []cisSubControl `json:"controls"`
}

type cisSubControl struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
}

func (p *Provider) parse(data []byte) ([]grc.Control, error) {
	var catalog cisCatalog
	if err := json.Unmarshal(data, &catalog); err != nil {
		return nil, fmt.Errorf("decode CIS Controls catalog: %w", err)
	}

	var controls []grc.Control
	for _, ig := range catalog.ImplementationGroups {
		controls = append(controls, p.extractControls(ig)...)
	}

	return controls, nil
}

func (p *Provider) extractControls(ig cisIG) []grc.Control {
	var controls []grc.Control

	for _, ctrl := range ig.Controls {
		level := p.mapLevel(ctrl.ID)

		control := grc.Control{
			Framework:   FrameworkID,
			ControlID:   ctrl.ID,
			Title:       ctrl.Title,
			Family:      ig.Name,
			Description: ctrl.Description,
			Level:       level,
			RelatedCWEs: cisCWEs(ctrl.ID),
		}

		controls = append(controls, control)
	}

	return controls
}

var cisCWEMap = map[string][]string{
	"1.1":   {"CWE-1069", "CWE-1342"},
	"1.2":   {"CWE-1104", "CWE-16"},
	"1.3":   {"CWE-1104", "CWE-937"},
	"2.1":   {"CWE-1104", "CWE-1024"},
	"2.2":   {"CWE-1104"},
	"2.3":   {"CWE-1104", "CWE-488"},
	"2.4":   {"CWE-1104", "CWE-1024"},
	"2.5":   {"CWE-94", "CWE-1104"},
	"2.6":   {"CWE-1357", "CWE-1104"},
	"2.7":   {"CWE-94", "CWE-95", "CWE-22"},
	"3.3":   {"CWE-284", "CWE-285", "CWE-862"},
	"3.5":   {"CWE-226", "CWE-228"},
	"3.6":   {"CWE-311", "CWE-312"},
	"3.9":   {"CWE-311", "CWE-312"},
	"3.10":  {"CWE-319", "CWE-326"},
	"3.11":  {"CWE-311", "CWE-312", "CWE-316"},
	"3.12":  {"CWE-16", "CWE-668"},
	"3.13":  {"CWE-200", "CWE-212", "CWE-497"},
	"4.1":   {"CWE-16", "CWE-1188"},
	"4.2":   {"CWE-16", "CWE-1188"},
	"4.3":   {"CWE-613", "CWE-287"},
	"4.4":   {"CWE-284", "CWE-668"},
	"4.5":   {"CWE-284", "CWE-668"},
	"4.6":   {"CWE-1104", "CWE-16"},
	"4.7":   {"CWE-798", "CWE-254"},
	"5.1":   {"CWE-287", "CWE-798"},
	"5.2":   {"CWE-521", "CWE-265"},
	"5.3":   {"CWE-798", "CWE-287"},
	"5.4":   {"CWE-250", "CWE-269"},
	"5.5":   {"CWE-287", "CWE-798"},
	"5.6":   {"CWE-287", "CWE-308"},
	"5.7":   {"CWE-521", "CWE-265"},
	"6.1":   {"CWE-285", "CWE-862"},
	"6.2":   {"CWE-285", "CWE-863"},
	"6.3":   {"CWE-287", "CWE-308"},
	"6.4":   {"CWE-287", "CWE-308"},
	"6.5":   {"CWE-250", "CWE-269", "CWE-287"},
	"6.7":   {"CWE-285", "CWE-862"},
	"6.8":   {"CWE-285", "CWE-862"},
	"7.1":   {"CWE-1104", "CWE-937"},
	"7.2":   {"CWE-1104", "CWE-937"},
	"7.3":   {"CWE-1104"},
	"7.4":   {"CWE-1104"},
	"7.5":   {"CWE-1104", "CWE-937"},
	"7.6":   {"CWE-1104", "CWE-937"},
	"7.7":   {"CWE-1104"},
	"8.1":   {"CWE-778", "CWE-223"},
	"8.2":   {"CWE-778"},
	"8.3":   {"CWE-778"},
	"8.5":   {"CWE-778"},
	"8.9":   {"CWE-778"},
	"8.10":  {"CWE-778"},
	"8.11":  {"CWE-778", "CWE-693"},
	"9.1":   {"CWE-1104", "CWE-1021"},
	"9.2":   {"CWE-1021"},
	"9.3":   {"CWE-1021"},
	"9.7":   {"CWE-1021", "CWE-919"},
	"9.8":   {"CWE-919", "CWE-1021"},
	"10.1":  {"CWE-778"},
	"10.2":  {"CWE-778"},
	"10.3":  {"CWE-778", "CWE-693"},
	"10.4":  {"CWE-778", "CWE-693"},
	"11.1":  {"CWE-778", "CWE-693"},
	"11.2":  {"CWE-778", "CWE-693"},
	"11.3":  {"CWE-778", "CWE-693"},
	"16.1":  {"CWE-1104", "CWE-1024"},
	"16.3":  {"CWE-1104", "CWE-937"},
	"16.5":  {"CWE-1104", "CWE-1357"},
	"16.10": {"CWE-1059", "CWE-693"},
	"16.12": {"CWE-94", "CWE-95", "CWE-119", "CWE-1336", "CWE-502", "CWE-22"},
	"16.13": {"CWE-1104", "CWE-937"},
	"17.3":  {"CWE-16", "CWE-778"},
	"17.4":  {"CWE-778", "CWE-693"},
	"18.1":  {"CWE-1104", "CWE-937"},
	"18.2":  {"CWE-1104", "CWE-937"},
	"18.4":  {"CWE-1104", "CWE-937"},
}

func cisCWEs(controlID string) []string {
	return cisCWEMap[controlID]
}

func (p *Provider) mapLevel(controlID string) string {
	parts := strings.Split(controlID, ".")
	if len(parts) == 0 {
		return "standard"
	}

	igNum := parts[0]
	subNum := parts[len(parts)-1]

	ig := 0
	fmt.Sscanf(igNum, "%d", &ig)

	sub := 0
	fmt.Sscanf(subNum, "%d", &sub)

	switch {
	case ig <= 6 && sub <= 3:
		return "basic"
	case ig <= 12 && sub <= 5:
		return "standard"
	default:
		return "high"
	}
}
