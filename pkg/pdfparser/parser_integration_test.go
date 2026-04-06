//go:build pdf_integration

package pdfparser_test

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shift/enrichment-engine/pkg/pdfparser"
)

func TestMain(m *testing.M) {
	if err := generateMockPDF(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to generate mock PDF: %v\n", err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}

func generateMockPDF() error {
	dir := "testdata"
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	path := filepath.Join(dir, "mock_iso_standard.pdf")

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	var buf bytes.Buffer
	w := &offsetWriter{w: &buf}

	write := func(s string) {
		fmt.Fprint(w, s)
	}

	objOffsets := make([]int, 10)

	write("%PDF-1.4\n")

	objOffsets[1] = w.offset
	write("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")

	objOffsets[2] = w.offset
	write("2 0 obj\n<< /Type /Pages /Kids [3 0 R 6 0 R 8 0 R] /Count 3 >>\nendobj\n")

	objOffsets[3] = w.offset
	write("3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>\nendobj\n")

	page1Text := "BT /F1 24 Tf 72 720 Td (ISO/IEC 27000:2018) Tj /F1 14 Tf 0 -30 Td (Foreword) Tj 0 -20 Td (This is front matter and should be skipped.) Tj ET"
	objOffsets[4] = w.offset
	write("4 0 obj\n")
	write(fmt.Sprintf("<< /Length %d >>\n", len(page1Text)))
	write("stream\n")
	write(page1Text)
	write("\nendstream\nendobj\n")

	objOffsets[5] = w.offset
	write("5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n")

	objOffsets[6] = w.offset
	write("6 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 7 0 R /Resources << /Font << /F1 5 0 R >> >> >>\nendobj\n")

	page2Text := "BT /F1 18 Tf 72 720 Td (2 Normative references) Tj /F1 16 Tf 0 -30 Td (3 Terms and definitions) Tj /F1 14 Tf 0 -25 Td (3.1 asset) Tj 0 -18 Td (anything that has value to an organization) Tj 0 -25 Td (3.2 control) Tj 0 -18 Td (measure that maintains or modifies risk) Tj 0 -25 Td (3.3 information security) Tj 0 -18 Td (preservation of confidentiality integrity and availability) Tj 0 -25 Td (4 Overview) Tj 0 -20 Td (This section provides an overview of ISMS.) Tj 0 -25 Td (4.1 The ISMS family of standards) Tj 0 -18 Td (Standards supporting ISMS implementation) Tj 0 -25 Td (4.2 Overview of the ISMS) Tj 0 -18 Td (An ISMS provides a systematic approach) Tj 0 -25 Td (4.2.1 Plan Do Check Act cycle) Tj 0 -18 Td (The PDCA cycle is a fundamental concept.) Tj 0 -25 Td (5 Vocabulary structure) Tj 0 -18 Td (Terms are organized by concept.) Tj 0 -25 Td (A.5 Information security policies) Tj 0 -18 Td (Policies provide direction.) Tj 0 -25 Td (A.5.1 Information security policies) Tj 0 -18 Td (Management direction and support.) Tj ET"
	objOffsets[7] = w.offset
	write("7 0 obj\n")
	write(fmt.Sprintf("<< /Length %d >>\n", len(page2Text)))
	write("stream\n")
	write(page2Text)
	write("\nendstream\nendobj\n")

	objOffsets[8] = w.offset
	write("8 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 9 0 R /Resources << /Font << /F1 5 0 R >> >> >>\nendobj\n")

	page3Text := "BT /F1 14 Tf 72 720 Td (A.6 Organization of information security) Tj 0 -25 Td (A.6.1 Internal organization) Tj 0 -18 Td (Management commitment to security.) Tj 0 -25 Td (A.6.2 Mobile devices and teleworking) Tj 0 -18 Td (Security of mobile devices and remote work.) Tj 0 -25 Td (Bibliography) Tj 0 -18 Td (This is back matter and should be skipped.) Tj ET"
	objOffsets[9] = w.offset
	write("9 0 obj\n")
	write(fmt.Sprintf("<< /Length %d >>\n", len(page3Text)))
	write("stream\n")
	write(page3Text)
	write("\nendstream\nendobj\n")

	xrefOffset := w.offset
	write("xref\n")
	write("0 10\n")
	write("0000000000 65535 f \n")
	for i := 1; i <= 9; i++ {
		write(fmt.Sprintf("%010d 00000 n \n", objOffsets[i]))
	}

	write("trailer\n<< /Size 10 /Root 1 0 R >>\n")
	write("startxref\n")
	write(fmt.Sprintf("%d\n", xrefOffset))
	write("%%EOF\n")

	_, err = f.Write(buf.Bytes())
	return err
}

type offsetWriter struct {
	w      interface{ Write([]byte) (int, error) }
	offset int
}

func (o *offsetWriter) Write(p []byte) (int, error) {
	n, err := o.w.Write(p)
	o.offset += n
	return n, err
}

func TestParserParseFile_MockPDF(t *testing.T) {
	p := pdfparser.New()

	_, err := p.ParseFile("testdata/mock_iso_standard.pdf")
	if err != nil {
		t.Fatalf("failed to parse mock PDF: %v", err)
	}
}

func TestParserExtractsSections_MockPDF(t *testing.T) {
	p := pdfparser.New()

	controls, err := p.ParseFile("testdata/mock_iso_standard.pdf")
	if err != nil {
		t.Fatalf("failed to parse mock PDF: %v", err)
	}

	if len(controls) < 5 {
		t.Fatalf("expected at least 5 controls from mock PDF, got %d: %+v", len(controls), controls)
	}

	for _, c := range controls {
		if c.SectionID == "" {
			t.Error("found control with empty SectionID")
		}
		if c.Title == "" {
			t.Errorf("control %q has empty Title", c.SectionID)
		}
		if !pdfparser.ValidateSectionID(c.SectionID) {
			t.Errorf("control has invalid SectionID: %q", c.SectionID)
		}
	}

	sectionIDRe := strings.NewReplacer(".", "")
	for _, c := range controls {
		if !strings.ContainsAny(sectionIDRe.Replace(c.SectionID), "0123456789") {
			t.Errorf("section ID %q doesn't contain numbers", c.SectionID)
		}
	}
}

func TestOpenAndValidatePDF_MockPDF(t *testing.T) {
	err := pdfparser.OpenAndValidatePDF("testdata/mock_iso_standard.pdf")
	if err != nil {
		t.Fatalf("mock PDF should be valid: %v", err)
	}
}

func TestParserExtractsSections_RealISO27000(t *testing.T) {
	path := "testdata/ISO_IEC_27000_2018.pdf"
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Skip("ISO/IEC 27000:2018 PDF not available, download from https://standards.iso.org/ittf/PubliclyAvailableStandards/ and place at " + path)
	}

	p := pdfparser.New()
	controls, err := p.ParseFile(path)
	if err != nil {
		t.Fatalf("failed to parse ISO 27000 PDF: %v", err)
	}

	if len(controls) < 50 {
		t.Fatalf("expected at least 50 sections from ISO 27000, got %d", len(controls))
	}

	for _, c := range controls {
		if c.SectionID == "" {
			t.Error("found control with empty SectionID")
		}
		if c.Title == "" {
			t.Errorf("control %q has empty Title", c.SectionID)
		}
		if !pdfparser.ValidateSectionID(c.SectionID) {
			t.Errorf("invalid section ID pattern: %q", c.SectionID)
		}
	}
}
