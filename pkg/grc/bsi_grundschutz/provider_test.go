package bsi_grundschutz

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"testing"
)

func TestProviderParse(t *testing.T) {
	// Create a minimal DocBook XML fixture
	fixture := `<?xml version="1.0" encoding="UTF-8"?>
<book xmlns="http://docbook.org/ns/docbook" version="5.0">
<chapter>
<section>
<section>
<title>CON.1 Kryptokonzept</title>
<title>CON.1.A1 Auswahl geeigneter kryptografischer Verfahren (B) [Fachverantwortliche]</title>
<title>CON.1.A2 Datensicherung beim Einsatz kryptografischer Verfahren (B) [IT-Betrieb]</title>
<title>CON.1.A3 Test (S)</title>
<title>CON.1.A4 Hoch sicher (H) [Admin]</title>
</section>
</section>
</chapter>
</book>`

	dir := t.TempDir()
	path := filepath.Join(dir, "test.xml")
	if err := os.WriteFile(path, []byte(fixture), 0644); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}

	p := &Provider{}
	controls, err := p.parse(path)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	if len(controls) != 4 {
		t.Fatalf("expected 4 controls, got %d", len(controls))
	}

	// Check first control
	if controls[0].ControlID != "CON.1.A1" {
		t.Errorf("expected ControlID CON.1.A1, got %s", controls[0].ControlID)
	}
	if controls[0].Title != "Auswahl geeigneter kryptografischer Verfahren" {
		t.Errorf("unexpected title: %s", controls[0].Title)
	}
	if controls[0].Family != "Kryptokonzept" {
		t.Errorf("expected Family Kryptokonzept, got %s", controls[0].Family)
	}
	if controls[0].Level != "basic" {
		t.Errorf("expected Level basic, got %s", controls[0].Level)
	}

	// Check standard level
	if controls[2].Level != "standard" {
		t.Errorf("expected Level standard, got %s", controls[2].Level)
	}

	// Check high level
	if controls[3].Level != "high" {
		t.Errorf("expected Level high, got %s", controls[3].Level)
	}
}

func TestProviderMapLevel(t *testing.T) {
	p := &Provider{}

	tests := []struct {
		input    string
		expected string
	}{
		{"B", "basic"},
		{"S", "standard"},
		{"H", "high"},
		{"b", "basic"},
		{"s", "standard"},
		{"h", "high"},
		{"X", "standard"},
		{"", "standard"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := p.mapLevel(tt.input)
			if got != tt.expected {
				t.Errorf("mapLevel(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestProviderName(t *testing.T) {
	p := &Provider{}
	if got := p.Name(); got != "bsi_grundschutz" {
		t.Errorf("Name() = %q, want %q", got, "bsi_grundschutz")
	}
}

func TestDocBookXMLUnmarshal(t *testing.T) {
	// Verify the XML structure matches what we expect
	fixture := `<?xml version="1.0" encoding="UTF-8"?>
<book xmlns="http://docbook.org/ns/docbook" version="5.0">
<chapter>
<section>
<section>
<title>CON.1 Kryptokonzept</title>
<title>CON.1.A1 Test (B)</title>
</section>
</section>
</chapter>
</book>`

	var book docbookBook
	if err := xml.Unmarshal([]byte(fixture), &book); err != nil {
		t.Fatalf("failed to unmarshal DocBook XML: %v", err)
	}

	if len(book.Chapters) != 1 {
		t.Fatalf("expected 1 chapter, got %d", len(book.Chapters))
	}

	if len(book.Chapters[0].Sections) != 1 {
		t.Fatalf("expected 1 section in chapter, got %d", len(book.Chapters[0].Sections))
	}

	if len(book.Chapters[0].Sections[0].Sections) != 1 {
		t.Fatalf("expected 1 subsection, got %d", len(book.Chapters[0].Sections[0].Sections))
	}

	if len(book.Chapters[0].Sections[0].Sections[0].Titles) != 2 {
		t.Fatalf("expected 2 titles, got %d", len(book.Chapters[0].Sections[0].Sections[0].Titles))
	}

	if book.Chapters[0].Sections[0].Sections[0].Titles[0] != "CON.1 Kryptokonzept" {
		t.Errorf("unexpected title: %s", book.Chapters[0].Sections[0].Sections[0].Titles[0])
	}
}
