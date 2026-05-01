package storage_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/vincents-ai/enrichment-engine/pkg/storage"
	pgregory "pgregory.net/rapid"
)

func makeRapidString(min, max int) *pgregory.Generator[string] {
	return pgregory.StringN(min, max, 127)
}

func randomString(t *pgregory.T, min, max int) string {
	return makeRapidString(min, max).Draw(t, "str")
}

func randomControl(t *pgregory.T) (string, map[string]interface{}) {
	fw := randomString(t, 3, 15)
	id := randomString(t, 1, 10)
	title := randomString(t, 3, 30)
	family := randomString(t, 3, 20)
	desc := randomString(t, 5, 50)
	level := pgregory.OneOf(
		pgregory.Just("basic"),
		pgregory.Just("standard"),
		pgregory.Just("high"),
		pgregory.Just("critical"),
	).Draw(t, "level")

	n := pgregory.IntRange(0, 5).Draw(t, "cwes")
	cwes := make([]string, n)
	for i := 0; i < n; i++ {
		cwes[i] = fmt.Sprintf("CWE-%d", pgregory.IntRange(1, 9999).Draw(t, fmt.Sprintf("cwe-%d", i)))
	}

	ctrl := map[string]interface{}{
		"Framework":   fw,
		"ControlID":   id,
		"Title":       title,
		"Family":      family,
		"Description": desc,
		"Level":       level,
	}
	if len(cwes) > 0 {
		ctrl["RelatedCWEs"] = cwes
	}
	return "ctrl-" + id, ctrl
}

func randomVulnerability(t *pgregory.T) (string, map[string]interface{}) {
	id := randomString(t, 8, 20)
	n := pgregory.IntRange(0, 5).Draw(t, "cwes")
	weaknesses := make([]map[string]interface{}, n)
	for i := 0; i < n; i++ {
		cwe := fmt.Sprintf("CWE-%d", pgregory.IntRange(1, 9999).Draw(t, fmt.Sprintf("cwe-%d", i)))
		weaknesses[i] = map[string]interface{}{
			"description": []map[string]string{{"lang": "en", "value": cwe}},
		}
	}
	vuln := map[string]interface{}{
		"id": id,
		"cve": map[string]interface{}{
			"id":         id,
			"weaknesses": weaknesses,
		},
	}
	return id, vuln
}

func setupRapidDB(t *testing.T) *storage.SQLiteBackend {
	t.Helper()
	path := t.TempDir() + "/rapid.db"
	backend, err := storage.NewSQLiteBackend(path)
	if err != nil {
		t.Fatalf("NewSQLiteBackend: %v", err)
	}
	t.Cleanup(func() { backend.Close(context.Background()) })
	return backend
}

func setupRapidDBDirect(rt *pgregory.T) *storage.SQLiteBackend {
	dir, err := os.MkdirTemp("", "rapid-sqlite-*")
	if err != nil {
		rt.Fatalf("MkdirTemp: %v", err)
	}
	path := dir + "/rapid.db"
	backend, err := storage.NewSQLiteBackend(path)
	if err != nil {
		os.RemoveAll(dir)
		rt.Fatalf("NewSQLiteBackend: %v", err)
	}
	return backend
}

func TestProperty_WriteControlNeverErrors(t *testing.T) {
	t.Parallel()
	pgregory.Check(t, func(t *pgregory.T) {
		backend := setupRapidDBDirect(t)
		id, ctrl := randomControl(t)
		err := backend.WriteControl(context.Background(), id, ctrl)
		if err != nil {
			t.Fatalf("WriteControl failed: %v", err)
		}
	})
}

func TestProperty_WriteReadControlRoundtrip(t *testing.T) {
	t.Parallel()
	pgregory.Check(t, func(t *pgregory.T) {
		backend := setupRapidDBDirect(t)
		id, control := randomControl(t)

		if err := backend.WriteControl(context.Background(), id, control); err != nil {
			t.Fatalf("WriteControl: %v", err)
		}

		data, err := backend.ReadControl(context.Background(), id)
		if err != nil {
			t.Fatalf("ReadControl: %v", err)
		}

		var got map[string]interface{}
		if err := json.Unmarshal(data, &got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}

		if got["Framework"] != control["Framework"] {
			t.Errorf("Framework mismatch: got %v, want %v", got["Framework"], control["Framework"])
		}
		if got["ControlID"] != control["ControlID"] {
			t.Errorf("ControlID mismatch: got %v, want %v", got["ControlID"], control["ControlID"])
		}
		if got["Title"] != control["Title"] {
			t.Errorf("Title mismatch: got %v, want %v", got["Title"], control["Title"])
		}
	})
}

func TestProperty_ListAllControlsCountMatches(t *testing.T) {
	t.Parallel()
	pgregory.Check(t, func(t *pgregory.T) {
		backend := setupRapidDBDirect(t)
		ctx := context.Background()
		n := pgregory.IntRange(0, 30).Draw(t, "count")

		for i := 0; i < n; i++ {
			id := fmt.Sprintf("count-ctrl-%d", i)
			_, ctrl := randomControl(t)
			if err := backend.WriteControl(ctx, id, ctrl); err != nil {
				t.Fatalf("WriteControl[%d]: %v", i, err)
			}
		}

		rows, err := backend.ListAllControls(ctx)
		if err != nil {
			t.Fatalf("ListAllControls: %v", err)
		}
		if len(rows) != n {
			t.Errorf("expected %d controls, got %d", n, len(rows))
		}
	})
}

func TestProperty_VulnerabilityRoundtrip(t *testing.T) {
	t.Parallel()
	pgregory.Check(t, func(t *pgregory.T) {
		backend := setupRapidDBDirect(t)
		id, vuln := randomVulnerability(t)

		if err := backend.WriteVulnerability(context.Background(), id, vuln); err != nil {
			t.Fatalf("WriteVulnerability: %v", err)
		}

		data, err := backend.ReadVulnerability(context.Background(), id)
		if err != nil {
			t.Fatalf("ReadVulnerability: %v", err)
		}

		var got map[string]interface{}
		if err := json.Unmarshal(data, &got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if got["id"] != id {
			t.Errorf("id mismatch: got %v, want %v", got["id"], id)
		}
	})
}

func TestProperty_MappingUpsert(t *testing.T) {
	t.Parallel()
	pgregory.Check(t, func(t *pgregory.T) {
		backend := setupRapidDBDirect(t)
		ctx := context.Background()

		mapType := randomString(t, 3, 10)
		conf := pgregory.Float64Range(0.0, 1.0).Draw(t, "conf")
		ev := randomString(t, 0, 50)

		backend.WriteMapping(ctx, "upsert-v", "upsert-c", "FW", mapType, conf, ev)

		mapType2 := randomString(t, 3, 10)
		backend.WriteMapping(ctx, "upsert-v", "upsert-c", "FW", mapType2, pgregory.Float64Range(0.0, 1.0).Draw(t, "conf2"), randomString(t, 0, 50))

		rows, err := backend.ListMappings(ctx, "upsert-v")
		if err != nil {
			t.Fatalf("ListMappings: %v", err)
		}
		if mapType != mapType2 {
			if len(rows) != 2 {
				t.Fatalf("expected 2 mappings (different mapping_types), got %d", len(rows))
			}
		} else {
			if len(rows) != 1 {
				t.Fatalf("expected 1 mapping after upsert (same mapping_type), got %d", len(rows))
			}
		}
	})
}

func TestProperty_ListByFrameworkFilter(t *testing.T) {
	t.Parallel()
	pgregory.Check(t, func(t *pgregory.T) {
		backend := setupRapidDBDirect(t)
		ctx := context.Background()
		nA := pgregory.IntRange(0, 5).Draw(t, "nA")
		nB := pgregory.IntRange(0, 5).Draw(t, "nB")

		for i := 0; i < nA; i++ {
			backend.WriteControl(ctx, fmt.Sprintf("fa-%d", i), map[string]interface{}{"Framework": "FW-A", "ControlID": fmt.Sprintf("A-%d", i), "Title": "A"})
		}
		for i := 0; i < nB; i++ {
			backend.WriteControl(ctx, fmt.Sprintf("fb-%d", i), map[string]interface{}{"Framework": "FW-B", "ControlID": fmt.Sprintf("B-%d", i), "Title": "B"})
		}

		rowsA, _ := backend.ListControlsByFramework(ctx, "FW-A")
		rowsB, _ := backend.ListControlsByFramework(ctx, "FW-B")
		if len(rowsA) != nA {
			t.Errorf("expected %d A controls, got %d", nA, len(rowsA))
		}
		if len(rowsB) != nB {
			t.Errorf("expected %d B controls, got %d", nB, len(rowsB))
		}
	})
}

func TestProperty_ConcurrentWriteSafety(t *testing.T) {
	t.Parallel()
	pgregory.Check(t, func(t *pgregory.T) {
		backend := setupRapidDBDirect(t)
		ctx := context.Background()
		n := pgregory.IntRange(1, 50).Draw(t, "goroutines")

		errCh := make(chan error, n)
		for i := 0; i < n; i++ {
			go func(idx int) {
				ctrl := map[string]interface{}{"Framework": "CONC-FW", "ControlID": fmt.Sprintf("CONC-%d", idx), "Title": "Concurrent"}
				errCh <- backend.WriteControl(ctx, fmt.Sprintf("conc-ctrl-%d", idx), ctrl)
			}(i)
		}

		for i := 0; i < n; i++ {
			if err := <-errCh; err != nil {
				t.Fatalf("concurrent write error at goroutine %d: %v", i, err)
			}
		}

		rows, err := backend.ListAllControls(ctx)
		if err != nil {
			t.Fatalf("ListAllControls: %v", err)
		}
		if len(rows) != n {
			t.Errorf("expected %d controls, got %d", n, len(rows))
		}
	})
}

func TestProperty_ControlStringsValidUTF8(t *testing.T) {
	t.Parallel()
	pgregory.Check(t, func(t *pgregory.T) {
		backend := setupRapidDBDirect(t)
		id, ctrl := randomControl(t)
		if err := backend.WriteControl(context.Background(), id, ctrl); err != nil {
			t.Fatalf("WriteControl failed: %v", err)
		}
		data, err := backend.ReadControl(context.Background(), id)
		if err != nil {
			t.Fatalf("ReadControl failed: %v", err)
		}
		if len(data) == 0 {
			t.Fatal("empty data returned")
		}
		if !json.Valid(data) {
			t.Fatalf("invalid JSON returned: %s", string(data))
		}
	})
}

func TestProperty_ControlIDNonEmpty(t *testing.T) {
	t.Parallel()
	pgregory.Check(t, func(t *pgregory.T) {
		_, ctrl := randomControl(t)
		id, ok := ctrl["ControlID"].(string)
		if !ok {
			t.Fatal("ControlID missing or not string")
		}
		if len(id) == 0 {
			t.Error("ControlID is empty")
		}
	})
}
