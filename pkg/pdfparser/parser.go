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

type ControlIssue struct {
	SectionID string
	Field     string
	Severity  string
	Message   string
}

type Parser struct {
	SkipFrontMatter      bool
	SkipBackMatter       bool
	MinSectionDepth      int
	MaxDescriptionLength int
}

func New() *Parser {
	return &Parser{
		SkipFrontMatter:      true,
		SkipBackMatter:       true,
		MinSectionDepth:      1,
		MaxDescriptionLength: 2000,
	}
}

var sectionHeaderRe = regexp.MustCompile(`^([A-Z]\.\d+(?:\.\d+)*|\d+(?:\.\d+)+|[1-9])\s+(.+)$`)

var sectionHeaderInlineRe = regexp.MustCompile(`([A-Z]\.\d+(?:\.\d+)*|\d+(?:\.\d+)+|[1-9])\s+([A-Z][A-Za-z])`)

var sectionIDOnlyRe = regexp.MustCompile(`^([A-Z]\.\d+(?:\.\d+)*|\d+(?:\.\d+)+|[1-9])$`)

var boldMarkerRe = regexp.MustCompile(`\*\*([A-Z]\.\d+(?:\.\d+)*|\d+(?:\.\d+)+)\*\*\s*$`)

func sectionIDPattern() *regexp.Regexp {
	return regexp.MustCompile(`^(?:[A-Z]\.\d+(?:\.\d+)*|\d+(?:\.\d+)+|[1-9])$`)
}

var isoFamilyMap = map[string]string{
	"4":  "Organizational Context",
	"5":  "Leadership",
	"6":  "Planning",
	"7":  "Support",
	"8":  "Operation",
	"9":  "Performance Evaluation",
	"10": "Improvement",
	"A":  "Controls",
	"B":  "Reference Controls",
}

var isoAnnexFamilyMap = map[string]string{
	"A.5":  "Information Security Policies",
	"A.6":  "Organization of Information Security",
	"A.7":  "Human Resource Security",
	"A.8":  "Asset Management",
	"A.9":  "Access Control",
	"A.10": "Cryptography",
	"A.11": "Physical and Environmental Security",
	"A.12": "Operations Security",
	"A.13": "Communications Security",
	"A.14": "System Acquisition Development and Maintenance",
	"A.15": "Supplier Relationships",
	"A.16": "Information Security Incident Management",
	"A.17": "Business Continuity",
	"A.18": "Compliance",
}

func InferFamilyFromSection(sectionID string) string {
	parts := strings.Split(sectionID, ".")
	if len(parts) == 0 {
		return ""
	}

	if len(parts) == 1 {
		if family, ok := isoFamilyMap[parts[0]]; ok {
			return family
		}
		return ""
	}

	prefix := parts[0]

	if (prefix == "A" || prefix == "B") && len(parts) >= 3 {
		annexPrefix := prefix + "." + parts[1]
		if family, ok := isoAnnexFamilyMap[annexPrefix]; ok {
			return family
		}
		if family, ok := isoFamilyMap[prefix]; ok {
			return family
		}
		return fmt.Sprintf("Annex %s.%s", parts[0], parts[1])
	}

	if (prefix == "A" || prefix == "B") && len(parts) == 2 {
		annexPrefix := prefix + "." + parts[1]
		if family, ok := isoAnnexFamilyMap[annexPrefix]; ok {
			return family
		}
		if family, ok := isoFamilyMap[prefix]; ok {
			return family
		}
		return fmt.Sprintf("Annex %s.%s", parts[0], parts[1])
	}

	if family, ok := isoFamilyMap[prefix]; ok {
		return family
	}

	return fmt.Sprintf("Section %s", prefix)
}

func (p *Parser) ValidateControls(controls []Control) []ControlIssue {
	var issues []ControlIssue
	maxLen := p.MaxDescriptionLength
	if maxLen <= 0 {
		maxLen = 2000
	}

	for _, c := range controls {
		if c.SectionID == "" {
			issues = append(issues, ControlIssue{
				SectionID: c.SectionID,
				Field:     "SectionID",
				Severity:  "error",
				Message:   "section ID must not be empty",
			})
		}
		if len(c.Description) > maxLen {
			issues = append(issues, ControlIssue{
				SectionID: c.SectionID,
				Field:     "Description",
				Severity:  "warning",
				Message:   fmt.Sprintf("description length %d exceeds maximum %d", len(c.Description), maxLen),
			})
		}
		if c.Title == "" {
			issues = append(issues, ControlIssue{
				SectionID: c.SectionID,
				Field:     "Title",
				Severity:  "error",
				Message:   "title must not be empty",
			})
		}
	}

	return issues
}

func (p *Parser) ParseReader(r io.Reader) ([]Control, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read input: %w", err)
	}
	return p.parseText(string(data)), nil
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

	return p.ParseReader(textReader)
}

func (p *Parser) parseText(text string) []Control {
	text = normalizeText(text)
	text = joinSplitHeaders(text)
	lines := strings.Split(text, "\n")
	controls := make([]Control, 0)
	var current *Control
	inFrontMatter := p.SkipFrontMatter
	inBackMatter := false
	frontMatterSeen := false

	for i := 0; i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i])
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
				Family:    InferFamilyFromSection(id),
			}
			continue
		}

		if sectionIDOnlyRe.MatchString(trimmed) && i+1 < len(lines) {
			nextLine := strings.TrimSpace(lines[i+1])
			if nextLine != "" && !sectionIDOnlyRe.MatchString(nextLine) && !isBackMatter(nextLine) {
				id := trimmed
				title := nextLine

				if p.SkipFrontMatter && !frontMatterSeen {
					first := id[0]
					if (first >= '2' && first <= '9') || (first >= 'A' && first <= 'Z') {
						frontMatterSeen = true
						inFrontMatter = false
					} else {
						i++
						continue
					}
				}

				if current != nil {
					controls = append(controls, *current)
				}

				current = &Control{
					SectionID: id,
					Title:     title,
					Family:    InferFamilyFromSection(id),
				}
				i++
				continue
			}
		}

		if bm := boldMarkerRe.FindStringSubmatch(trimmed); bm != nil {
			id := bm[1]
			if i+1 < len(lines) {
				nextLine := strings.TrimSpace(lines[i+1])
				if nextLine != "" && !isBackMatter(nextLine) {
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
						Title:     nextLine,
						Family:    InferFamilyFromSection(id),
					}
					i++
					continue
				}
			}
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

func joinSplitHeaders(text string) string {
	lines := strings.Split(text, "\n")
	var result []string
	i := 0
	for i < len(lines) {
		trimmed := strings.TrimSpace(lines[i])
		if sectionIDOnlyRe.MatchString(trimmed) && i+1 < len(lines) {
			next := strings.TrimSpace(lines[i+1])
			if next != "" && !sectionIDOnlyRe.MatchString(next) && !isBackMatter(next) {
				result = append(result, trimmed+" "+next)
				i += 2
				continue
			}
		}
		result = append(result, lines[i])
		i++
	}
	return strings.Join(result, "\n")
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
