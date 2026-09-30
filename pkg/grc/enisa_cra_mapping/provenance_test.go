package enisa_cra_mapping

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vincents-ai/enrichment-engine/pkg/grc"
	"github.com/vincents-ai/enrichment-engine/pkg/storage"
)

// memoryStore records what a provider writes so a test can inspect provenance.
type memoryStore struct {
	storage.Backend
	controls map[string]grc.Control
}

func newMemoryStore() *memoryStore {
	return &memoryStore{controls: map[string]grc.Control{}}
}

// WriteControl satisfies storage.Backend, whose control parameter is
// interface{}. Anything other than a grc.Control is a programming error rather
// than something to tolerate silently, so it is recorded as a zero value and
// the type assertion is explicit.
func (m *memoryStore) WriteControl(_ context.Context, id string, control interface{}) error {
	c, ok := control.(grc.Control)
	if !ok {
		return nil
	}
	m.controls[id] = c
	return nil
}

// setCatalogURL redirects the provider at a test server for the duration of a
// test. CatalogURL is a package variable precisely so the fetch target can be
// exercised without network access.
func setCatalogURL(t *testing.T, url string) {
	t.Helper()
	prev := CatalogURL
	CatalogURL = url
	t.Cleanup(func() { CatalogURL = prev })
}

// The provider previously fell back to locally written mappings after a failed
// download, but the controls it wrote still cited ENISA with an ENISA URL. The
// count and the references were identical to a successful fetch, so nothing
// downstream could tell the difference and the only trace was a log line.
//
// In a compliance product that is a false regulatory claim: the mapping looks
// authoritative, is likely to be relied on, and cannot be substantiated.
func TestFallbackMappingsDoNotClaimEnisaProvenance(t *testing.T) {
	// A server that is up but serves something unusable, which is what a
	// captive portal or an error page looks like from here.
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<!doctype html><html><body>Sign in</body></html>"))
	}))
	defer bad.Close()
	setCatalogURL(t, bad.URL+"/catalog.json")

	store := newMemoryStore()
	p := New(store, slog.Default())
	if _, err := p.Run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(store.controls) == 0 {
		t.Fatal("expected the local fallback to produce controls")
	}

	for id, c := range store.controls {
		if c.Provenance != grc.ProvenanceLocalInterpretation {
			t.Errorf("%s: provenance = %q, want %q; content that was not fetched "+
				"from ENISA must not be stored as though it were", id, c.Provenance,
				grc.ProvenanceLocalInterpretation)
		}
		if !c.SourceRetrievedAt.IsZero() {
			t.Errorf("%s: SourceRetrievedAt is %s but no document was retrieved; a "+
				"retrieval timestamp for content that was never retrieved is a false "+
				"claim of the same kind", id, c.SourceRetrievedAt)
		}
		if c.ProvenanceNote == "" {
			t.Errorf("%s: ProvenanceNote must explain the degraded status to an operator", id)
		}
		for _, ref := range c.References {
			if ref.Source == "ENISA" {
				t.Errorf("%s: a locally written control still cites ENISA as source %q; "+
					"the reference is what a reader would follow to verify it", id, ref.Source)
			}
		}
	}
}

// A successful fetch is genuinely official, and must be distinguishable from the
// fallback. If both look the same, the provenance field carries no information.
func TestFetchedMappingsAreMarkedOfficial(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"mappings":[{"id":"MAP-900","cra_requirement":"Annex I-1",` +
			`"harmonised_standard":"EN 18031-1","standard_section":"5.1","title":"Fetched",` +
			`"description":"d","confidence":"high","level":"critical","annex":"I"}]}`))
	}))
	defer srv.Close()
	setCatalogURL(t, srv.URL+"/catalog.json")

	store := newMemoryStore()
	p := New(store, slog.Default())
	if _, err := p.Run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	c, ok := store.controls[FrameworkID+"/MAP-900"]
	if !ok {
		t.Fatalf("fetched control not stored; have %v", keys(store.controls))
	}
	if c.Provenance != grc.ProvenanceOfficial {
		t.Errorf("a successfully fetched control must be official, got %q", c.Provenance)
	}
	if c.SourceRetrievedAt.IsZero() {
		t.Error("a fetched control must record when the document was retrieved")
	}
	foundENISA := false
	for _, ref := range c.References {
		if ref.Source == "ENISA" {
			foundENISA = true
		}
	}
	if !foundENISA {
		t.Error("a genuinely fetched control should still cite ENISA")
	}
}

// MAP-005 cited ETSI EN 303 645 Section 5.2 for password and credential
// requirements. Those are in Section 5.1; Section 5.2 is Vulnerability
// disclosure. A wrong clause in a mapping presented as authoritative survives
// review because nothing checks the clause against the source.
func TestPasswordRequirementsCiteTheCorrectETSIClause(t *testing.T) {
	controls := markLocal(New(nil, slog.Default()).generateEmbeddedMappings())
	var map005 *grc.Control
	for i := range controls {
		if controls[i].ControlID == "MAP-005" {
			map005 = &controls[i]
		}
	}
	if map005 == nil {
		t.Fatal("MAP-005 is missing from the embedded mappings")
	}

	var etsi *grc.Reference
	for i := range map005.References {
		if map005.References[i].Source == "ETSI EN 303 645" {
			etsi = &map005.References[i]
		}
	}
	if etsi == nil {
		t.Fatal("MAP-005 does not reference ETSI EN 303 645")
	}
	if etsi.Section == "5.2" {
		t.Errorf("MAP-005 cites ETSI EN 303 645 Section 5.2, which is Vulnerability " +
			"disclosure; password and credential requirements are Section 5.1")
	}
	if etsi.Section != "5.1" {
		t.Errorf("MAP-005 should cite ETSI EN 303 645 Section 5.1, got %q", etsi.Section)
	}
	if !strings.Contains(strings.ToLower(map005.Description), "password") {
		t.Errorf("MAP-005 describes password requirements, so its description should "+
			"say so; got %q", map005.Description)
	}
}

// The fallback must not erase a previously good catalog without saying so.
func TestFallbackIsReportedAsDegraded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	setCatalogURL(t, srv.URL+"/catalog.json")

	store := newMemoryStore()
	p := New(store, slog.Default())
	n, err := p.Run(context.Background())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if n == 0 {
		t.Error("expected the fallback to produce controls")
	}
	// Every control is local, so a consumer can refuse to treat them as evidence.
	local := 0
	for _, c := range store.controls {
		if c.Provenance == grc.ProvenanceLocalInterpretation {
			local++
		}
	}
	if local != len(store.controls) {
		t.Errorf("%d of %d controls are local; a failed fetch must not produce a "+
			"mix of official and local with no way to tell", local, len(store.controls))
	}
}

func keys(m map[string]grc.Control) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
