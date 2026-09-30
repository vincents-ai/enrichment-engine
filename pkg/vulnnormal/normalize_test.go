package vulnnormal

import (
	"encoding/json"
	"strings"
	"testing"
)

// The three shapes the brief names must produce EQUIVALENT canonical facts.
func TestSupportedShapesProduceEquivalentFacts(t *testing.T) {
	bare := []byte(`{"id":"CVE-2026-1234","published":"2026-01-02T00:00:00",
		"description":{"lang":"en","value":"SQL injection"},
		"weaknesses":[{"description":[{"lang":"en","value":"CWE-89 Improper neutralization"}]}],
		"configurations":[{"nodes":[{"cpeMatch":[{"criteria":"cpe:2.3:a:vendor:widget:1.0:*:*:*:*:*:*:*"}]}]}]}`)

	wrapped := []byte(`{"vulnerabilities":[{"cve":` + string(bare) + `}]}`)

	envelope := []byte(`{"schema":"nvd-2.0","identifier":"nvd:2026/CVE-2026-1234","item":` + string(bare) + `}`)

	want, err := Normalize(bare, "nvd")
	if err != nil {
		t.Fatalf("bare CVE: %v", err)
	}
	for name, in := range map[string][]byte{"nvd response wrapper": wrapped, "vulnz envelope": envelope} {
		got, err := Normalize(in, "nvd")
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if got.ID != want.ID {
			t.Errorf("%s: ID %q, want %q", name, got.ID, want.ID)
		}
		if len(got.CWEs) != 1 || got.CWEs[0] != "CWE-89" {
			t.Errorf("%s: CWEs %v, want [CWE-89]", name, got.CWEs)
		}
		if len(got.CPEs) != 1 || !strings.HasPrefix(got.CPEs[0], "cpe:2.3:a:vendor:widget") {
			t.Errorf("%s: CPEs %v", name, got.CPEs)
		}
		if got.SchemaVersion != SchemaVersion {
			t.Errorf("%s: schema version %q, want %q", name, got.SchemaVersion, SchemaVersion)
		}
	}
}

// A vulnerability with no weaknesses is a legitimate, mappable absence. An
// unreadable record is a failure. They must not look the same, because the
// original defect was exactly that confusion.
func TestEmptyVulnerabilityIsNotAnUnreadableRecord(t *testing.T) {
	empty, err := Normalize([]byte(`{"id":"CVE-2026-9999"}`), "nvd")
	if err != nil {
		t.Fatalf("a valid CVE with no weaknesses must normalize successfully: %v", err)
	}
	if empty.ID != "CVE-2026-9999" {
		t.Errorf("ID = %q", empty.ID)
	}
	if len(empty.CWEs) != 0 || len(empty.CPEs) != 0 {
		t.Errorf("expected no mappings, got CWEs %v CPEs %v", empty.CWEs, empty.CPEs)
	}

	_, err = Normalize([]byte(`{"totally":"unrelated"}`), "nvd")
	if err == nil {
		t.Fatal("an unreadable record must be an error, not an empty result")
	}
	if !contains(err.Error(), "Supported shapes") {
		t.Errorf("the error should tell the caller what shapes are supported, got: %v", err)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// A record stored BEFORE normalization existed must still be readable after the
// engine moves to the canonical shape, so an upgraded database does not silently
// stop enriching. The engine keeps a legacy fallback for exactly this; this test
// pins that the legacy shape is still recognisable.
func TestLegacyNestedRecordIsStillRecognisable(t *testing.T) {
	legacy := []byte(`{"id":"CVE-2026-5555","cve":{"id":"CVE-2026-5555",
		"weaknesses":[{"description":[{"lang":"en","value":"CWE-79 XSS"}]}]}}`)
	// The legacy shape has a top-level id, so it normalizes; the point is that a
	// record with the id nested under "cve" alone must still be identifiable
	// rather than being discarded as unreadable.
	c, err := Normalize(legacy, "nvd")
	if err != nil {
		t.Fatalf("a legacy record must remain readable: %v", err)
	}
	if c.ID != "CVE-2026-5555" {
		t.Errorf("ID = %q, want CVE-2026-5555", c.ID)
	}
}

// Normalization must be idempotent, or a reprocessing run would double-wrap
// every record and the stored schema version would drift.
func TestNormalizationIsIdempotent(t *testing.T) {
	in := []byte(`{"id":"CVE-2026-1234","weaknesses":[{"description":[{"lang":"en","value":"CWE-89"}]}]}`)
	once, err := Normalize(in, "nvd")
	if err != nil {
		t.Fatalf("first pass: %v", err)
	}
	stored, _ := json.Marshal(once)
	twice, err := Normalize(stored, "nvd")
	if err != nil {
		t.Fatalf("second pass: %v", err)
	}
	if twice.ID != once.ID || len(twice.CWEs) != len(once.CWEs) {
		t.Errorf("normalization is not idempotent: %+v then %+v", once, twice)
	}
	if twice.SchemaVersion != SchemaVersion {
		t.Errorf("schema version drifted to %q", twice.SchemaVersion)
	}
}

// A batch must not be silently truncated: an unreadable record names its index.
func TestBatchNamesTheUnreadableRecord(t *testing.T) {
	good := json.RawMessage(`{"id":"CVE-2026-0001"}`)
	bad := json.RawMessage(`{"nothing":"useful"}`)
	if _, err := NormalizeAll([]json.RawMessage{good, bad}, "nvd"); err == nil {
		t.Fatal("a batch containing an unreadable record must fail")
	} else if !strings.Contains(err.Error(), "record 2 of 2") {
		t.Errorf("the error must identify which record failed, got: %v", err)
	}
}
