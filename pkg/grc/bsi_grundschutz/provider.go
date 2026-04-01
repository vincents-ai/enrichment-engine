package bsi_grundschutz

import (
	"context"
	"encoding/xml"
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
	FrameworkID = "BSI_IT_Grundschutz_2023"
	CatalogURL  = "https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-GS-Kompendium/XML_Kompendium_2023.xml?__blob=publicationFile&v=4"
)

// Provider fetches and parses BSI IT-Grundschutz controls from XML.
type Provider struct {
	store  storage.Backend
	logger *slog.Logger
}

// New creates a new BSI Grundschutz provider.
func New(store storage.Backend, logger *slog.Logger) *Provider {
	return &Provider{
		store:  store,
		logger: logger,
	}
}

// Name returns the provider identifier.
func (p *Provider) Name() string {
	return "bsi_grundschutz"
}

// Run fetches the BSI catalog, parses controls, and writes them to storage.
func (p *Provider) Run(ctx context.Context) (int, error) {
	p.logger.Info("fetching BSI IT-Grundschutz catalog (XML)", "url", CatalogURL)

	destPath := filepath.Join(os.TempDir(), "bsi_grundschutz_catalog.xml")
	if err := p.download(ctx, CatalogURL, destPath); err != nil {
		return 0, fmt.Errorf("download catalog: %w", err)
	}
	defer os.Remove(destPath)

	controls, err := p.parse(destPath)
	if err != nil {
		return 0, fmt.Errorf("parse catalog: %w", err)
	}

	p.logger.Info("parsed BSI Grundschutz controls", "count", len(controls))

	count := 0
	for _, ctrl := range controls {
		id := fmt.Sprintf("%s/%s", FrameworkID, ctrl.ControlID)
		if err := p.store.WriteControl(ctx, id, ctrl); err != nil {
			p.logger.Warn("failed to write control", "id", id, "error", err)
			continue
		}
		count++
	}

	p.logger.Info("wrote BSI Grundschutz controls to storage", "count", count)
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

// bsiCatalog is the top-level BSI IT-Grundschutz XML structure.
type bsiCatalog struct {
	XMLName xml.Name    `xml:"it-grundschutz"`
	Groups  []bsiGroup  `xml:"gruppe"`
	Modules []bsiModule `xml:"baustein"`
}

type bsiGroup struct {
	XMLName     xml.Name     `xml:"gruppe"`
	ID          string       `xml:"id,attr"`
	Name        string       `xml:name`
	Title       string       `xml:title`
	Description string       `xml:beschreibung`
	Controls    []bsiControl `xml:"massnahme"`
	SubGroups   []bsiGroup   `xml:"gruppe"`
}

type bsiModule struct {
	XMLName     xml.Name     `xml:"baustein"`
	ID          string       `xml:"id,attr"`
	Name        string       `xml:name`
	Title       string       `xml:title`
	Description string       `xml:beschreibung`
	Controls    []bsiControl `xml:"massnahme"`
}

type bsiControl struct {
	XMLName     xml.Name `xml:"massnahme"`
	ID          string   `xml:"id,attr"`
	Name        string   `xml:name`
	Title       string   `xml:title`
	Description string   `xml:beschreibung`
	Level       string   `xml:"stufe"`
	Class       string   `xml:"klasse"`
	Typ         string   `xml:"typ"`
	Content     string   `xml:"inhalt"`
}

func (p *Provider) parse(path string) ([]grc.Control, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("read catalog: %w", err)
	}

	var catalog bsiCatalog
	if err := xml.Unmarshal(data, &catalog); err != nil {
		return nil, fmt.Errorf("decode BSI XML catalog: %w", err)
	}

	var controls []grc.Control

	for _, group := range catalog.Groups {
		controls = append(controls, p.extractControls(group)...)
	}
	for _, module := range catalog.Modules {
		controls = append(controls, p.extractModuleControls(module)...)
	}

	return controls, nil
}

func (p *Provider) extractControls(group bsiGroup) []grc.Control {
	var controls []grc.Control

	for _, ctrl := range group.Controls {
		control := p.buildControl(ctrl, group.ID, group.Title)
		controls = append(controls, control)
	}

	for _, subGroup := range group.SubGroups {
		controls = append(controls, p.extractControls(subGroup)...)
	}

	return controls
}

func (p *Provider) extractModuleControls(module bsiModule) []grc.Control {
	var controls []grc.Control

	for _, ctrl := range module.Controls {
		control := p.buildControl(ctrl, module.ID, module.Title)
		controls = append(controls, control)
	}

	return controls
}

func (p *Provider) buildControl(ctrl bsiControl, moduleID, moduleTitle string) grc.Control {
	controlID := ctrl.ID
	if controlID == "" {
		controlID = ctrl.Name
	}

	title := ctrl.Title
	if title == "" {
		title = ctrl.Name
	}

	description := ctrl.Description
	if description == "" {
		description = ctrl.Content
	}

	level := p.mapLevel(ctrl.Level, ctrl.Class, ctrl.Typ)

	return grc.Control{
		Framework:   FrameworkID,
		ControlID:   fmt.Sprintf("%s.%s", moduleID, controlID),
		Title:       title,
		Family:      moduleTitle,
		Description: description,
		Level:       level,
	}
}

func (p *Provider) mapLevel(level, class, typ string) string {
	lower := strings.ToLower
	switch lower(level) {
	case "high", "hoch", "kritisch":
		return "high"
	case "standard", "standardniveau":
		return "standard"
	case "basic", "basis":
		return "basic"
	}

	switch lower(class) {
	case "high", "hoch":
		return "high"
	case "standard":
		return "standard"
	case "basic", "basis":
		return "basic"
	}

	switch lower(typ) {
	case "high", "hoch":
		return "high"
	case "standard":
		return "standard"
	case "basic", "basis":
		return "basic"
	}

	return "standard"
}
