package bsi_grundschutz

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/shift/enrichment-engine/pkg/grc"
	"github.com/shift/enrichment-engine/pkg/storage"
)

const (
	FrameworkID = "BSI_IT_Grundschutz_2023"
)

var CatalogURL = "https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-GS-Kompendium/XML_Kompendium_2023.xml?__blob=publicationFile&v=4"

// DocBook XML namespace
const docbookNS = "http://docbook.org/ns/docbook"

// Provider fetches and parses BSI IT-Grundschutz controls from DocBook XML.
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
	p.logger.Info("fetching BSI IT-Grundschutz catalog (DocBook XML)", "url", CatalogURL)

	f, err := os.CreateTemp("", "bsi_grundschutz_catalog_*.xml")
	if err != nil {
		return 0, fmt.Errorf("create temp file: %w", err)
	}
	destPath := f.Name()
	f.Close()
	defer os.Remove(destPath)
	if err := p.download(ctx, CatalogURL, destPath); err != nil {
		return 0, fmt.Errorf("download catalog: %w", err)
	}

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

// Control title pattern: "CON.1 Kryptokonzept" or "CON.1.A1 Description (B) [Role]"
var (
	modulePattern  = regexp.MustCompile(`^([A-Z]+\.\d+(?:\.\d+)?)\s+(.+)$`)
	controlPattern = regexp.MustCompile(`^([A-Z]+\.\d+(?:\.\d+)?(?:\.[A-Z]\d+)?)\s+(.+?)\s*\(([BSH])\)\s*(?:\[(.+?)\])?$`)
)

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

	var book docbookBook
	if err := xml.Unmarshal(data, &book); err != nil {
		return nil, fmt.Errorf("decode BSI DocBook XML: %w", err)
	}

	var controls []grc.Control
	var currentModule string
	var currentModuleTitle string

	for _, chapter := range book.Chapters {
		for _, section := range chapter.Sections {
			for _, subSection := range section.Sections {
				for _, title := range subSection.Titles {
					if match := modulePattern.FindStringSubmatch(title); match != nil {
						currentModule = match[1]
						currentModuleTitle = match[2]
					} else if match := controlPattern.FindStringSubmatch(title); match != nil {
						controlID := match[1]
						description := match[2]
						level := p.mapLevel(match[3])

						ctrl := grc.Control{
							Framework:   FrameworkID,
							ControlID:   controlID,
							Title:       description,
							Family:      currentModuleTitle,
							Description: fmt.Sprintf("%s: %s", currentModule, description),
							Level:       level,
						}
						controls = append(controls, ctrl)
					}
				}
			}
		}
	}

	return controls, nil
}

func (p *Provider) mapLevel(level string) string {
	switch strings.ToUpper(level) {
	case "H":
		return "high"
	case "S":
		return "standard"
	case "B":
		return "basic"
	default:
		return "standard"
	}
}

// DocBook XML structures
type docbookBook struct {
	XMLName  xml.Name         `xml:"http://docbook.org/ns/docbook book"`
	Chapters []docbookChapter `xml:"http://docbook.org/ns/docbook chapter"`
}

type docbookChapter struct {
	XMLName  xml.Name         `xml:"http://docbook.org/ns/docbook chapter"`
	Sections []docbookSection `xml:"http://docbook.org/ns/docbook section"`
}

type docbookSection struct {
	XMLName  xml.Name         `xml:"http://docbook.org/ns/docbook section"`
	Sections []docbookSection `xml:"http://docbook.org/ns/docbook section"`
	Titles   []string         `xml:"http://docbook.org/ns/docbook title"`
}
