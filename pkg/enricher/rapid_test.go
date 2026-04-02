package enricher

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/shift/enrichment-engine/pkg/grc"
	"github.com/shift/enrichment-engine/pkg/storage"
	pgregory "pgregory.net/rapid"
)

func rapidRandomString(t *pgregory.T, min, max int) string {
	return pgregory.StringN(min, max, 127).Draw(t, "str")
}

func TestProperty_ExtractCWEs_NoWeaknesses(t *testing.T) {
	t.Parallel()
	pgregory.Check(t, func(t *pgregory.T) {
		id := rapidRandomString(t, 5, 20)
		record := map[string]interface{}{
			"id": id,
			"cve": map[string]interface{}{
				"id":         id,
				"weaknesses": []map[string]interface{}{},
			},
		}
		data, _ := json.Marshal(record)

		cwes := extractCWEs(data)
		if len(cwes) != 0 {
			t.Fatalf("expected 0 CWEs, got %d: %v", len(cwes), cwes)
		}
	})
}

func TestProperty_ExtractCWEs_Deduplicates(t *testing.T) {
	t.Parallel()
	pgregory.Check(t, func(t *pgregory.T) {
		cweNum := pgregory.IntRange(1, 9999).Draw(t, "cweNum")
		cweStr := fmt.Sprintf("CWE-%d", cweNum)
		dupCount := pgregory.IntRange(2, 10).Draw(t, "dupCount")

		weaknesses := make([]map[string]interface{}, dupCount)
		for i := 0; i < dupCount; i++ {
			weaknesses[i] = map[string]interface{}{
				"description": []map[string]string{{"lang": "en", "value": cweStr}},
			}
		}

		record := map[string]interface{}{
			"id": "CVE-DEDUP",
			"cve": map[string]interface{}{
				"id":         "CVE-DEDUP",
				"weaknesses": weaknesses,
			},
		}
		data, _ := json.Marshal(record)

		cwes := extractCWEs(data)
		if len(cwes) != 1 {
			t.Fatalf("expected 1 unique CWE for %d duplicates, got %d: %v", dupCount, len(cwes), cwes)
		}
		if cwes[0] != cweStr {
			t.Errorf("expected %q, got %q", cweStr, cwes[0])
		}
	})
}

func TestProperty_ExtractCWEs_EnglishOnly(t *testing.T) {
	t.Parallel()
	pgregory.Check(t, func(t *pgregory.T) {
		cweNum := pgregory.IntRange(1, 9999).Draw(t, "cweNum")
		cweStr := fmt.Sprintf("CWE-%d", cweNum)
		langs := []string{"en", "de", "fr", "es", "it", "nl"}
		weaknesses := make([]map[string]interface{}, 0, len(langs))
		for _, lang := range langs {
			weaknesses = append(weaknesses, map[string]interface{}{
				"description": []map[string]string{{"lang": lang, "value": cweStr}},
			})
		}

		record := map[string]interface{}{
			"id": "CVE-LANG",
			"cve": map[string]interface{}{
				"id":         "CVE-LANG",
				"weaknesses": weaknesses,
			},
		}
		data, _ := json.Marshal(record)

		cwes := extractCWEs(data)
		if len(cwes) != 1 {
			t.Fatalf("expected 1 CWE (English only) for %d languages, got %d: %v", len(langs), len(cwes), cwes)
		}
	})
}

func TestProperty_ExtractCWEs_IgnoresNonCWE(t *testing.T) {
	t.Parallel()
	pgregory.Check(t, func(t *pgregory.T) {
		nonCwe := rapidRandomString(t, 1, 20)
		weaknesses := []map[string]interface{}{
			{"description": []map[string]string{{"lang": "en", "value": nonCwe}}},
		}
		record := map[string]interface{}{
			"id": "CVE-NOPE",
			"cve": map[string]interface{}{
				"id":         "CVE-NOPE",
				"weaknesses": weaknesses,
			},
		}
		data, _ := json.Marshal(record)

		cwes := extractCWEs(data)
		if len(cwes) != 0 {
			t.Fatalf("expected 0 CWEs for non-CWE value %q, got %d", nonCwe, len(cwes))
		}
	})
}

func TestProperty_ExtractCWEs_MalformedInput(t *testing.T) {
	t.Parallel()
	pgregory.Check(t, func(t *pgregory.T) {
		badInput := pgregory.SliceOfN(pgregory.Byte(), 0, 100).Draw(t, "badJSON")
		cwes := extractCWEs(json.RawMessage(badInput))
		if cwes != nil {
			t.Errorf("expected nil for malformed JSON, got %v", cwes)
		}
	})
}

func TestProperty_ExtractedCWEsValidFormat(t *testing.T) {
	t.Parallel()
	pgregory.Check(t, func(t *pgregory.T) {
		cweNum := pgregory.IntRange(1, 9999).Draw(t, "cweNum")
		weaknesses := []map[string]interface{}{
			{"description": []map[string]string{{"lang": "en", "value": fmt.Sprintf("CWE-%d", cweNum)}}},
		}
		record := map[string]interface{}{
			"id": "CVE-FMT",
			"cve": map[string]interface{}{
				"id":         "CVE-FMT",
				"weaknesses": weaknesses,
			},
		}
		data, _ := json.Marshal(record)

		cwes := extractCWEs(data)
		for _, cwe := range cwes {
			if !strings.HasPrefix(cwe, "CWE-") {
				t.Errorf("CWE %q missing CWE- prefix", cwe)
				continue
			}
			num := strings.TrimPrefix(cwe, "CWE-")
			if num == "" {
				t.Errorf("CWE %q has empty number part", cwe)
				continue
			}
			for _, r := range num {
				if r < '0' || r > '9' {
					t.Errorf("CWE %q has non-digit: %q", cwe, r)
					break
				}
			}
		}
	})
}

func TestProperty_MapByCWE_OnlyMatches(t *testing.T) {
	t.Parallel()
	pgregory.Check(t, func(t *pgregory.T) {
		mock := &mockBackend{}

		vulnCWE := fmt.Sprintf("CWE-%d", pgregory.IntRange(1, 9999).Draw(t, "vulnCWE"))
		ctrlCWE := fmt.Sprintf("CWE-%d", pgregory.IntRange(1, 9999).Draw(t, "ctrlCWE"))

		vulnRecord := map[string]interface{}{
			"id": "CVE-PROP",
			"cve": map[string]interface{}{
				"id": "CVE-PROP",
				"weaknesses": []map[string]interface{}{
					{"description": []map[string]string{{"lang": "en", "value": vulnCWE}}},
				},
			},
		}
		vulnData, _ := json.Marshal(vulnRecord)
		mock.vulns = []storage.VulnerabilityRow{{ID: "CVE-PROP", Record: vulnData}}

		if vulnCWE == ctrlCWE {
			mock.controls = []storage.ControlRow{{
				ID: "FW/C-1", Framework: "FW", ControlID: "C-1", Title: "Match",
				RelatedCWEs: []string{ctrlCWE},
			}}
		} else {
			mock.controls = []storage.ControlRow{{
				ID: "FW/C-2", Framework: "FW", ControlID: "C-2", Title: "NoMatch",
				RelatedCWEs: []string{ctrlCWE},
			}}
		}

		e := New(Config{Store: mock, Logger: testLogger()})
		count, err := e.mapByCWE(context.Background())
		if err != nil {
			t.Fatalf("mapByCWE: %v", err)
		}

		if vulnCWE == ctrlCWE {
			if count != 1 {
				t.Fatalf("expected 1 mapping for matching CWE %s, got %d", vulnCWE, count)
			}
		} else {
			if count != 0 {
				t.Fatalf("expected 0 mappings for different CWEs (%s vs %s), got %d", vulnCWE, ctrlCWE, count)
			}
		}
	})
}

func TestProperty_EnrichSBOM_NeverPanics(t *testing.T) {
	t.Parallel()
	pgregory.Check(t, func(t *pgregory.T) {
		mock := &mockBackend{
			controls: []storage.ControlRow{{
				ID: "FW/C-1", Framework: "FW", ControlID: "C-1", Title: "Test",
			}},
		}

		e := New(Config{Store: mock, Logger: testLogger()})
		n := pgregory.IntRange(0, 20).Draw(t, "components")

		components := make([]grc.SBOMComponent, n)
		for i := 0; i < n; i++ {
			components[i] = grc.SBOMComponent{
				Name:    rapidRandomString(t, 1, 50),
				Version: "1.0.0",
				Type:    "library",
				CPEs:    []string{},
			}
		}

		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("EnrichSBOM panicked with %d components: %v", n, r)
			}
		}()

		result, err := e.EnrichSBOM(context.Background(), components)
		if err != nil {
			t.Fatalf("EnrichSBOM error: %v", err)
		}
		if len(result) != n {
			t.Fatalf("expected %d enriched components, got %d", n, len(result))
		}
	})
}

func TestProperty_EngineDefaultParallel(t *testing.T) {
	t.Parallel()
	pgregory.Check(t, func(t *pgregory.T) {
		negatives := []int{-10, -5, -1, 0}
		idx := pgregory.IntRange(0, len(negatives)-1).Draw(t, "neg")
		n := negatives[idx]

		e := New(Config{Store: &mockBackend{}, Logger: testLogger(), MaxParallel: n})
		if e.maxParallel != 1 {
			t.Errorf("expected maxParallel=1 for input %d, got %d", n, e.maxParallel)
		}
	})
}
