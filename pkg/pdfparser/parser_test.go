package pdfparser

import (
	"strings"
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

func TestInferFamilyFromSection(t *testing.T) {
	tests := []struct {
		id   string
		want string
	}{
		{"4.1", "Organizational Context"},
		{"4.2", "Organizational Context"},
		{"4.2.1", "Organizational Context"},
		{"5", "Leadership"},
		{"5.1", "Leadership"},
		{"6.1.2", "Planning"},
		{"7", "Support"},
		{"8.1", "Operation"},
		{"9", "Performance Evaluation"},
		{"9.1.2", "Performance Evaluation"},
		{"10", "Improvement"},
		{"10.1", "Improvement"},
		{"A.5.1", "Information Security Policies"},
		{"A.5.2", "Information Security Policies"},
		{"A.6.1", "Organization of Information Security"},
		{"A.7.1", "Human Resource Security"},
		{"A.8.1", "Asset Management"},
		{"A.9.1", "Access Control"},
		{"A.10.1", "Cryptography"},
		{"A.11.1", "Physical and Environmental Security"},
		{"A.12.1", "Operations Security"},
		{"A.13.1", "Communications Security"},
		{"A.14.1", "System Acquisition Development and Maintenance"},
		{"A.15.1", "Supplier Relationships"},
		{"A.16.1", "Information Security Incident Management"},
		{"A.17.1", "Business Continuity"},
		{"A.18.1", "Compliance"},
		{"A", "Controls"},
		{"A.5", "Information Security Policies"},
		{"A.99.1", "Controls"},
		{"B.1.1", "Reference Controls"},
		{"3.1", "Section 3"},
		{"2", ""},
		{"", ""},
	}

	for _, tt := range tests {
		got := InferFamilyFromSection(tt.id)
		if got != tt.want {
			t.Errorf("InferFamilyFromSection(%q) = %q, want %q", tt.id, got, tt.want)
		}
	}
}

func TestValidateControls(t *testing.T) {
	p := New()

	t.Run("too long description", func(t *testing.T) {
		controls := []Control{
			{SectionID: "A.5.1", Title: "Test", Description: strings.Repeat("a", 2001)},
		}
		issues := p.ValidateControls(controls)
		found := false
		for _, iss := range issues {
			if iss.Field == "Description" && iss.Severity == "warning" {
				found = true
			}
		}
		if !found {
			t.Error("expected warning for description exceeding max length")
		}
	})

	t.Run("description at limit", func(t *testing.T) {
		controls := []Control{
			{SectionID: "A.5.1", Title: "Test", Description: strings.Repeat("a", 2000)},
		}
		issues := p.ValidateControls(controls)
		for _, iss := range issues {
			if iss.Field == "Description" {
				t.Errorf("unexpected description issue: %v", iss)
			}
		}
	})

	t.Run("empty section ID", func(t *testing.T) {
		controls := []Control{
			{SectionID: "", Title: "Test", Description: "desc"},
		}
		issues := p.ValidateControls(controls)
		found := false
		for _, iss := range issues {
			if iss.Field == "SectionID" && iss.Severity == "error" {
				found = true
			}
		}
		if !found {
			t.Error("expected error for empty SectionID")
		}
	})

	t.Run("empty title", func(t *testing.T) {
		controls := []Control{
			{SectionID: "A.5.1", Title: "", Description: "desc"},
		}
		issues := p.ValidateControls(controls)
		found := false
		for _, iss := range issues {
			if iss.Field == "Title" && iss.Severity == "error" {
				found = true
			}
		}
		if !found {
			t.Error("expected error for empty Title")
		}
	})

	t.Run("no issues", func(t *testing.T) {
		controls := []Control{
			{SectionID: "A.5.1", Title: "Test", Description: "short desc"},
		}
		issues := p.ValidateControls(controls)
		if len(issues) != 0 {
			t.Errorf("expected no issues, got %d: %+v", len(issues), issues)
		}
	})

	t.Run("multiple issues", func(t *testing.T) {
		controls := []Control{
			{SectionID: "", Title: "", Description: strings.Repeat("x", 3000)},
		}
		issues := p.ValidateControls(controls)
		if len(issues) != 3 {
			t.Errorf("expected 3 issues, got %d: %+v", len(issues), issues)
		}
	})

	t.Run("custom max length", func(t *testing.T) {
		p := New()
		p.MaxDescriptionLength = 100
		controls := []Control{
			{SectionID: "A.5.1", Title: "Test", Description: strings.Repeat("a", 101)},
		}
		issues := p.ValidateControls(controls)
		found := false
		for _, iss := range issues {
			if iss.Field == "Description" {
				found = true
			}
		}
		if !found {
			t.Error("expected warning with custom max length")
		}
	})
}

func TestParseReader(t *testing.T) {
	p := New()
	p.SkipFrontMatter = false

	text := `3.1 asset
anything that has value
to an organization
3.2 control
measure that maintains risk`

	controls, err := p.ParseReader(strings.NewReader(text))
	if err != nil {
		t.Fatalf("ParseReader returned error: %v", err)
	}

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

func TestSectionHeaderSpansLines(t *testing.T) {
	p := New()
	p.SkipFrontMatter = false

	tests := []struct {
		name      string
		text      string
		wantID    string
		wantTitle string
	}{
		{
			name:      "section ID on one line, title on next",
			text:      "4.2.1\nInformation security policies\nDescription follows here.",
			wantID:    "4.2.1",
			wantTitle: "Information security policies",
		},
		{
			name:      "annex header split across lines",
			text:      "A.5.1\nInformation security policies\nManagement direction and support for infosec.",
			wantID:    "A.5.1",
			wantTitle: "Information security policies",
		},
		{
			name:      "single-digit clause split",
			text:      "4\nOrganizational context\nSome description text.",
			wantID:    "4",
			wantTitle: "Organizational context",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			controls := p.parseText(tt.text)
			if len(controls) != 1 {
				t.Fatalf("expected 1 control, got %d: %+v", len(controls), controls)
			}
			if controls[0].SectionID != tt.wantID {
				t.Errorf("SectionID: got %q, want %q", controls[0].SectionID, tt.wantID)
			}
			if controls[0].Title != tt.wantTitle {
				t.Errorf("Title: got %q, want %q", controls[0].Title, tt.wantTitle)
			}
		})
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
