package pdfparser

import (
	"testing"
)

func TestParserNew(t *testing.T) {
	p := New()
	if p == nil {
		t.Fatal("New() returned nil")
	}
	if !p.SkipFrontMatter {
		t.Error("expected SkipFrontMatter to be true by default")
	}
	if !p.SkipBackMatter {
		t.Error("expected SkipBackMatter to be true by default")
	}
}

func TestParserParseFile_NotFound(t *testing.T) {
	p := New()
	_, err := p.ParseFile("/nonexistent/path/to/file.pdf")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestParserParseFile_InvalidPDF(t *testing.T) {
	p := New()
	_, err := p.ParseFile("parser_test.go")
	if err == nil {
		t.Fatal("expected error for non-PDF file")
	}
}

func TestSectionIDPattern(t *testing.T) {
	re := sectionIDPattern()

	valid := []string{
		"2", "3", "4", "5",
		"2.1", "3.1", "4.2.1", "A.5.1",
		"A.6.1", "A.6.2", "B.1", "4.2",
		"10.1.2", "A.12.4.1",
	}

	for _, id := range valid {
		if !re.MatchString(id) {
			t.Errorf("expected %q to match section ID pattern", id)
		}
	}

	invalid := []string{
		"", "abc", " Foreword", "Table of",
		"3.1 ", " 3.1", ".1", "3.", "3.1.2.",
		"ISO", "27000", "foreword",
	}

	for _, id := range invalid {
		if re.MatchString(id) {
			t.Errorf("expected %q to NOT match section ID pattern", id)
		}
	}
}

func TestValidateSectionID(t *testing.T) {
	tests := []struct {
		id   string
		want bool
	}{
		{"3.1", true},
		{"A.5.1", true},
		{"", false},
		{"abc", false},
		{"Foreword", false},
		{"4.2.1", true},
	}

	for _, tt := range tests {
		got := ValidateSectionID(tt.id)
		if got != tt.want {
			t.Errorf("ValidateSectionID(%q) = %v, want %v", tt.id, got, tt.want)
		}
	}
}

func TestOpenAndValidatePDF_Invalid(t *testing.T) {
	err := OpenAndValidatePDF("parser_test.go")
	if err == nil {
		t.Fatal("expected error for non-PDF file")
	}
}

func TestOpenAndValidatePDF_NotFound(t *testing.T) {
	err := OpenAndValidatePDF("/nonexistent/file.pdf")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestInferFamily(t *testing.T) {
	tests := []struct {
		id   string
		want string
	}{
		{"3.1", "Section 3"},
		{"4.2.1", "Section 4"},
		{"A.5.1", "Annex A.5"},
		{"A.6.2", "Annex A.6"},
		{"B.1.1", "Annex B.1"},
		{"2", ""},
	}

	for _, tt := range tests {
		got := inferFamily(tt.id)
		if got != tt.want {
			t.Errorf("inferFamily(%q) = %q, want %q", tt.id, got, tt.want)
		}
	}
}

func TestParseText(t *testing.T) {
	p := New()
	p.SkipFrontMatter = false

	text := `3 Terms and definitions
3.1 asset
anything that has value to an organization
3.2 control
measure that maintains or modifies risk
4 Overview
4.1 The ISMS family of standards
Standards supporting ISMS implementation
Bibliography
This is back matter and should be skipped.`

	controls := p.parseText(text)

	if len(controls) < 5 {
		t.Fatalf("expected at least 5 controls, got %d", len(controls))
	}

	for _, c := range controls {
		if c.SectionID == "" {
			t.Error("found control with empty SectionID")
		}
		if c.Title == "" {
			t.Errorf("control %q has empty Title", c.SectionID)
		}
	}

	found := make(map[string]bool)
	for _, c := range controls {
		found[c.SectionID] = true
	}

	for _, id := range []string{"3.1", "3.2", "4.1"} {
		if !found[id] {
			t.Errorf("expected to find section %q", id)
		}
	}

	if found["Bibliography"] {
		t.Error("back matter should not appear as a control")
	}
}

func TestParseText_SkipsFrontMatter(t *testing.T) {
	p := New()

	text := `Foreword
This document was prepared by ISO/IEC JTC 1.
Introduction
This is the introduction section.
3 Terms and definitions
3.1 asset
anything that has value to an organization`

	controls := p.parseText(text)

	for _, c := range controls {
		if c.SectionID == "Foreword" || c.SectionID == "Introduction" {
			t.Errorf("front matter %q should be skipped", c.SectionID)
		}
	}

	found := false
	for _, c := range controls {
		if c.SectionID == "3.1" {
			found = true
		}
	}
	if !found {
		t.Error("expected to find section 3.1")
	}
}

func TestSectionHeaderRegex(t *testing.T) {
	tests := []struct {
		line  string
		id    string
		title string
	}{
		{"3.1 Terms and definitions", "3.1", "Terms and definitions"},
		{"4.2.1 Plan Do Check Act cycle", "4.2.1", "Plan Do Check Act cycle"},
		{"A.5.1 Information security policies", "A.5.1", "Information security policies"},
		{"A.6.1 Internal organization", "A.6.1", "Internal organization"},
	}

	for _, tt := range tests {
		m := sectionHeaderRe.FindStringSubmatch(tt.line)
		if m == nil {
			t.Errorf("no match for %q", tt.line)
			continue
		}
		if m[1] != tt.id {
			t.Errorf("id: got %q, want %q", m[1], tt.id)
		}
		if m[2] != tt.title {
			t.Errorf("title: got %q, want %q", m[2], tt.title)
		}
	}
}

func TestControlStruct(t *testing.T) {
	c := Control{
		SectionID:   "A.5.1",
		Title:       "Information security policies",
		Description: "Management direction and support.",
		Family:      "Annex A.5",
		Level:       "standard",
	}

	if c.SectionID != "A.5.1" {
		t.Errorf("SectionID mismatch")
	}
	if c.Family != "Annex A.5" {
		t.Errorf("Family mismatch")
	}
}

func TestParseText_EmptyInput(t *testing.T) {
	p := New()
	controls := p.parseText("")
	if len(controls) != 0 {
		t.Errorf("expected 0 controls for empty input, got %d", len(controls))
	}
}

func TestParseText_NoSections(t *testing.T) {
	p := New()
	p.SkipFrontMatter = false
	controls := p.parseText("This is just some plain text\nwith no section headers\nat all.")
	if len(controls) != 0 {
		t.Errorf("expected 0 controls, got %d", len(controls))
	}
}

func TestParseText_DescriptionAccumulation(t *testing.T) {
	p := New()
	p.SkipFrontMatter = false

	text := `3.1 asset
anything that has value
to an organization
3.2 control
measure that maintains risk`

	controls := p.parseText(text)
	if len(controls) != 2 {
		t.Fatalf("expected 2 controls, got %d", len(controls))
	}

	if controls[0].SectionID != "3.1" {
		t.Errorf("expected section 3.1 first, got %s", controls[0].SectionID)
	}

	expected := "anything that has value to an organization"
	if controls[0].Description != expected {
		t.Errorf("description: got %q, want %q", controls[0].Description, expected)
	}
}

func TestParseText_MultipleDescriptions(t *testing.T) {
	re := sectionHeaderRe

	lines := []string{
		"2 Normative references",
		"ISO/IEC 27001:2013, Information technology",
		"3 Terms and definitions",
		"For the purposes of this document",
		"3.1 asset",
		"anything that has value",
	}

	count := 0
	for _, line := range lines {
		if re.MatchString(line) {
			count++
		}
	}

	if count != 3 {
		t.Errorf("expected 3 section headers, got %d", count)
	}
}
