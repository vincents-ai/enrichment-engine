package owasp_asvs

// OWASP ASVS v4.0.3 data is embedded verbatim under Creative Commons Attribution-ShareAlike 4.0 International (CC BY-SA 4.0).
// CC BY-SA 4.0 is copyleft-compatible with AGPL. This embedding constitutes a derivative work and is itself licensed CC BY-SA 4.0.
// Original source: https://owasp.org/www-project-application-security-verification-standard/
// License: https://creativecommons.org/licenses/by-sa/4.0/

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/csv"
	"fmt"
	"log/slog"
	"strings"

	"github.com/vincents-ai/enrichment-engine/pkg/grc"
	"github.com/vincents-ai/enrichment-engine/pkg/storage"
)

const FrameworkID = "OWASP_ASVS_4"

//go:embed owasp_asvs_v4.csv
var embeddedCatalog []byte

// Provider loads and parses the OWASP Application Security Verification Standard v4.0.3.
type Provider struct {
	store  storage.Backend
	logger *slog.Logger
}

// New creates a new OWASP ASVS provider.
func New(store storage.Backend, logger *slog.Logger) *Provider {
	return &Provider{store: store, logger: logger}
}

// Name returns the provider identifier.
func (p *Provider) Name() string { return "owasp_asvs" }

// Run parses the embedded ASVS catalog and writes all controls to storage.
func (p *Provider) Run(ctx context.Context) (int, error) {
	p.logger.Info("loading OWASP ASVS v4.0.3 controls")
	controls, err := p.parse(embeddedCatalog)
	if err != nil {
		return 0, fmt.Errorf("parse OWASP ASVS catalog: %w", err)
	}
	count := 0
	for _, ctrl := range controls {
		id := fmt.Sprintf("%s/%s", FrameworkID, ctrl.ControlID)
		if err := p.store.WriteControl(ctx, id, ctrl); err != nil {
			p.logger.Warn("failed to write control", "id", id, "error", err)
			continue
		}
		count++
	}
	p.logger.Info("wrote OWASP ASVS controls", "count", count)
	return count, nil
}

func (p *Provider) parse(data []byte) ([]grc.Control, error) {
	r := csv.NewReader(bytes.NewReader(data))
	r.LazyQuotes = true
	records, err := r.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("read csv: %w", err)
	}
	if len(records) < 2 {
		return nil, fmt.Errorf("empty catalog")
	}

	// Find column indices dynamically from header row.
	// Expected: chapter_id, chapter_name, section_id, section_name,
	//           req_id, req_description, level1, level2, level3, cwe, nist
	header := records[0]
	idx := func(name string) int {
		for i, h := range header {
			if strings.EqualFold(strings.TrimSpace(h), name) {
				return i
			}
		}
		return -1
	}

	idxReqID := idx("req_id")
	if idxReqID < 0 {
		idxReqID = idx("item")
	}
	if idxReqID < 0 {
		idxReqID = idx("#")
	}
	idxDesc := idx("req_description")
	if idxDesc < 0 {
		idxDesc = idx("description")
	}
	idxChapterName := idx("chapter_name")
	idxSectionName := idx("section_name")
	idxLevel1 := idx("level1")
	if idxLevel1 < 0 {
		idxLevel1 = idx("l1")
	}
	idxCWE := idx("cwe")

	if idxReqID < 0 {
		return nil, fmt.Errorf("could not find req_id column in CSV header: %v", header)
	}

	var controls []grc.Control
	for _, row := range records[1:] {
		if len(row) <= idxReqID {
			continue
		}
		controlID := strings.TrimSpace(row[idxReqID])
		if controlID == "" || strings.HasPrefix(controlID, "#") {
			continue
		}

		// Determine family: prefer chapter_name, fall back to section_name.
		family := ""
		if idxChapterName >= 0 && idxChapterName < len(row) {
			family = strings.TrimSpace(row[idxChapterName])
		}
		if family == "" && idxSectionName >= 0 && idxSectionName < len(row) {
			family = strings.TrimSpace(row[idxSectionName])
		}

		// Title: use section_name if available, otherwise controlID.
		title := controlID
		if idxSectionName >= 0 && idxSectionName < len(row) && strings.TrimSpace(row[idxSectionName]) != "" {
			title = strings.TrimSpace(row[idxSectionName])
		}

		desc := ""
		if idxDesc >= 0 && idxDesc < len(row) {
			desc = strings.TrimSpace(row[idxDesc])
		}

		// Determine level: L1 if level1 column contains "✓", otherwise L2.
		level := "L2"
		if idxLevel1 >= 0 && idxLevel1 < len(row) && strings.TrimSpace(row[idxLevel1]) == "✓" {
			level = "L1"
		}

		// Parse CWE — numeric in CSV, add "CWE-" prefix; skip 0.
		var cwes []string
		if idxCWE >= 0 && idxCWE < len(row) {
			for _, c := range strings.Split(row[idxCWE], ",") {
				c = strings.TrimSpace(c)
				if c == "" || c == "0" {
					continue
				}
				if !strings.HasPrefix(c, "CWE-") {
					c = "CWE-" + c
				}
				cwes = append(cwes, c)
			}
		}

		tags := tagsForFamily(family)
		controls = append(controls, grc.Control{
			Framework:   FrameworkID,
			ControlID:   controlID,
			Title:       title,
			Family:      family,
			Description: desc,
			Level:       level,
			RelatedCWEs: cwes,
			Tags:        tags,
			References: []grc.Reference{
				{
					Source:  "OWASP ASVS v4.0.3",
					URL:     "https://owasp.org/www-project-application-security-verification-standard/",
					Section: controlID,
				},
			},
		})
	}
	return controls, nil
}

func tagsForFamily(family string) []string {
	f := strings.ToLower(family)
	switch {
	case strings.Contains(f, "authn") || strings.Contains(f, "authentication"):
		return []string{"authentication", "access-control"}
	case strings.Contains(f, "session"):
		return []string{"authentication", "access-control"}
	case strings.Contains(f, "access control") || strings.Contains(f, "authz"):
		return []string{"access-control"}
	case strings.Contains(f, "input") || strings.Contains(f, "validation") || strings.Contains(f, "injection"):
		return []string{"input-validation", "injection"}
	case strings.Contains(f, "crypto"):
		return []string{"cryptography"}
	case strings.Contains(f, "error") || strings.Contains(f, "log"):
		return []string{"logging"}
	case strings.Contains(f, "data protection") || strings.Contains(f, "sensitive"):
		return []string{"cryptography", "privacy"}
	case strings.Contains(f, "config"):
		return []string{"configuration"}
	case strings.Contains(f, "api") || strings.Contains(f, "web service"):
		return []string{"input-validation", "authentication"}
	case strings.Contains(f, "file") || strings.Contains(f, "upload"):
		return []string{"input-validation"}
	case strings.Contains(f, "malicious"):
		return []string{"input-validation", "supply-chain"}
	case strings.Contains(f, "business logic"):
		return []string{"design"}
	case strings.Contains(f, "commun") || strings.Contains(f, "tls"):
		return []string{"cryptography", "network"}
	default:
		return []string{"input-validation"}
	}
}
