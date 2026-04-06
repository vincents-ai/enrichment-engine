package pdfparser

import (
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/ledongthuc/pdf"
)

type Control struct {
	SectionID   string
	Title       string
	Description string
	Family      string
	Level       string
}

type Parser struct {
	SkipFrontMatter bool
	SkipBackMatter  bool
	MinSectionDepth int
}

func New() *Parser {
	return &Parser{
		SkipFrontMatter: true,
		SkipBackMatter:  true,
		MinSectionDepth: 1,
	}
}

var sectionHeaderRe = regexp.MustCompile(`^([A-Z]\.\d+(?:\.\d+)*|\d+(?:\.\d+)+|[1-9])\s+(.+)$`)

var sectionHeaderInlineRe = regexp.MustCompile(`([A-Z]\.\d+(?:\.\d+)*|\d+(?:\.\d+)+|[1-9])\s+([A-Z][A-Za-z])`)

func sectionIDPattern() *regexp.Regexp {
	return regexp.MustCompile(`^(?:[A-Z]\.\d+(?:\.\d+)*|\d+(?:\.\d+)+|[1-9])$`)
}

func (p *Parser) ParseFile(path string) ([]Control, error) {
	f, r, err := pdf.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open pdf: %w", err)
	}
	defer f.Close()

	textReader, err := r.GetPlainText()
	if err != nil {
		return nil, fmt.Errorf("extract text: %w", err)
	}

	data, err := io.ReadAll(textReader)
	if err != nil {
		return nil, fmt.Errorf("read text: %w", err)
	}

	return p.parseText(string(data)), nil
}

func (p *Parser) parseText(text string) []Control {
	text = normalizeText(text)
	lines := strings.Split(text, "\n")
	controls := make([]Control, 0)
	var current *Control
	inFrontMatter := p.SkipFrontMatter
	inBackMatter := false
	frontMatterSeen := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		if inBackMatter {
			continue
		}

		if p.SkipBackMatter && isBackMatter(trimmed) {
			if current != nil {
				controls = append(controls, *current)
				current = nil
			}
			inBackMatter = true
			continue
		}

		if m := sectionHeaderRe.FindStringSubmatch(trimmed); m != nil {
			id := m[1]
			title := m[2]

			if p.SkipFrontMatter && !frontMatterSeen {
				first := id[0]
				if (first >= '2' && first <= '9') || (first >= 'A' && first <= 'Z') {
					frontMatterSeen = true
					inFrontMatter = false
				} else {
					continue
				}
			}

			if current != nil {
				controls = append(controls, *current)
			}

			current = &Control{
				SectionID: id,
				Title:     title,
				Family:    inferFamily(id),
			}
			continue
		}

		if inFrontMatter {
			continue
		}

		if current != nil {
			if current.Description != "" {
				current.Description += " "
			}
			current.Description += trimmed
		}
	}

	if current != nil {
		controls = append(controls, *current)
	}

	return controls
}

func normalizeText(text string) string {
	normalized := sectionHeaderInlineRe.ReplaceAllString(text, "\n$1 $2")
	return normalized
}

func isBackMatter(s string) bool {
	return strings.EqualFold(s, "Bibliography") ||
		strings.EqualFold(s, "Index") ||
		strings.HasPrefix(strings.ToUpper(s), "ANNEX ")
}

func inferFamily(sectionID string) string {
	parts := strings.Split(sectionID, ".")
	if len(parts) < 2 {
		return ""
	}
	prefix := parts[0]
	if (prefix == "A" || prefix == "B") && len(parts) >= 3 {
		return fmt.Sprintf("Annex %s.%s", parts[0], parts[1])
	}
	return fmt.Sprintf("Section %s", prefix)
}

func ValidateSectionID(id string) bool {
	return sectionIDPattern().MatchString(id)
}

func OpenAndValidatePDF(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open file: %w", err)
	}
	defer f.Close()

	buf := make([]byte, 5)
	if _, err := f.Read(buf); err != nil {
		return fmt.Errorf("read header: %w", err)
	}
	if string(buf) != "%PDF-" {
		return fmt.Errorf("not a valid PDF file")
	}
	return nil
}
