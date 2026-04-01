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
	"path/filepath"
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

	destPath := filepath.Join(os.TempDir(), "cis_controls_v8.json")

	var data []byte
	var err error

	if err = p.download(ctx, CatalogURL, destPath); err != nil {
		p.logger.Warn("failed to download catalog, using embedded fallback", "error", err)
		data = embeddedCatalog
	} else {
		defer os.Remove(destPath)
		data, err = os.ReadFile(destPath)
		if err != nil {
			return 0, fmt.Errorf("read catalog: %w", err)
		}
	}

	controls, err := p.parse(data)
	if err != nil {
		return 0, fmt.Errorf("parse catalog: %w", err)
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
		return err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = io.Copy(f, resp.Body)
	return err
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
		}

		controls = append(controls, control)
	}

	return controls
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
