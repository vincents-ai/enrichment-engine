package resilience_test

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/shift/enrichment-engine/pkg/grc"
	"github.com/shift/enrichment-engine/pkg/grc/anssi_ebios"
	"github.com/shift/enrichment-engine/pkg/grc/cen_cenelec_cra"
	"github.com/shift/enrichment-engine/pkg/grc/nis2"
	"github.com/shift/enrichment-engine/pkg/storage"
)

func resilienceLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

type nopStore struct {
	mu     sync.Mutex
	writes int
}

func (n *nopStore) WriteVulnerability(_ context.Context, _ string, _ interface{}) error { return nil }
func (n *nopStore) WriteControl(_ context.Context, _ string, _ interface{}) error {
	n.mu.Lock()
	n.writes++
	n.mu.Unlock()
	return nil
}
func (n *nopStore) WriteMapping(_ context.Context, _, _, _, _ string, _ float64, _ string) error {
	return nil
}
func (n *nopStore) ReadVulnerability(_ context.Context, _ string) ([]byte, error) { return nil, nil }
func (n *nopStore) ReadControl(_ context.Context, _ string) ([]byte, error)       { return nil, nil }
func (n *nopStore) ListMappings(_ context.Context, _ string) ([]storage.MappingRow, error) {
	return nil, nil
}
func (n *nopStore) Close(_ context.Context) error { return nil }
func (n *nopStore) ListAllVulnerabilities(_ context.Context) ([]storage.VulnerabilityRow, error) {
	return nil, nil
}
func (n *nopStore) ListAllControls(_ context.Context) ([]storage.ControlRow, error) { return nil, nil }
func (n *nopStore) ListControlsByCWE(_ context.Context, _ string) ([]storage.ControlRow, error) {
	return nil, nil
}
func (n *nopStore) ListControlsByCPE(_ context.Context, _ string) ([]storage.ControlRow, error) {
	return nil, nil
}
func (n *nopStore) ListControlsByFramework(_ context.Context, _ string) ([]storage.ControlRow, error) {
	return nil, nil
}
func (n *nopStore) ListControlsByTag(_ context.Context, _ string) ([]storage.ControlRow, error) {
	return nil, nil
}

var _ storage.Backend = (*nopStore)(nil)

func TestHTTPClientTimeout(t *testing.T) {
	if grc.HTTPClient.Timeout == 0 {
		t.Fatal("HTTPClient has no timeout configured (is infinite)")
	}
	if grc.HTTPClient.Timeout > 60*time.Second {
		t.Errorf("HTTPClient timeout is %v, expected <= 60s", grc.HTTPClient.Timeout)
	}
}

func TestHTTPClientTransportTimeouts(t *testing.T) {
	transport, ok := grc.HTTPClient.Transport.(*http.Transport)
	if !ok {
		t.Fatal("HTTPClient.Transport is not *http.Transport")
	}
	if transport.TLSHandshakeTimeout == 0 {
		t.Error("TLSHandshakeTimeout is 0")
	}
	if transport.ResponseHeaderTimeout == 0 {
		t.Error("ResponseHeaderTimeout is 0")
	}
	if transport.IdleConnTimeout == 0 {
		t.Error("IdleConnTimeout is 0")
	}
	if transport.ExpectContinueTimeout == 0 {
		t.Error("ExpectContinueTimeout is 0")
	}
}

func TestHTTPClientUserAgent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ua := r.Header.Get("User-Agent")
		if ua == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	resp, err := grc.HTTPClient.Get(srv.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusBadRequest {
		t.Error("no User-Agent header sent by default HTTPClient (consider setting one)")
	}
}

func TestLiveFetchProvider_NilStore(t *testing.T) {
	logger := resilienceLogger()

	t.Run("anssi_ebios", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("anssi_ebios panicked with nil store: %v", r)
			}
		}()
		p := anssi_ebios.New(nil, logger)
		if p == nil {
			t.Fatal("New returned nil")
		}
		if p.Name() != "anssi_ebios" {
			t.Errorf("expected name 'anssi_ebios', got %q", p.Name())
		}
	})

	t.Run("cen_cenelec_cra", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("cen_cenelec_cra panicked with nil store: %v", r)
			}
		}()
		p := cen_cenelec_cra.New(nil, logger)
		if p == nil {
			t.Fatal("New returned nil")
		}
		if p.Name() != "cen_cenelec_cra" {
			t.Errorf("expected name 'cen_cenelec_cra', got %q", p.Name())
		}
	})

	t.Run("nis2", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("nis2 panicked with nil store: %v", r)
			}
		}()
		p := nis2.New(nil, logger)
		if p == nil {
			t.Fatal("New returned nil")
		}
		if p.Name() != "nis2" {
			t.Errorf("expected name 'nis2', got %q", p.Name())
		}
	})
}

func TestLiveFetchProvider_CancelledContext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"controls": []}`))
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	store := &nopStore{}
	logger := resilienceLogger()

	t.Run("anssi_ebios", func(t *testing.T) {
		orig := anssi_ebios.CatalogURL
		anssi_ebios.CatalogURL = srv.URL
		defer func() { anssi_ebios.CatalogURL = orig }()

		p := anssi_ebios.New(store, logger)
		count, err := p.Run(ctx)
		if err != nil {
			t.Errorf("provider with embedded fallback should not error on cancelled context, got: %v", err)
		}
		if count <= 0 {
			t.Errorf("expected embedded fallback controls to be written, got count %d", count)
		}
	})

	t.Run("cen_cenelec_cra", func(t *testing.T) {
		orig := cen_cenelec_cra.CatalogURL
		cen_cenelec_cra.CatalogURL = srv.URL
		defer func() { cen_cenelec_cra.CatalogURL = orig }()

		p := cen_cenelec_cra.New(store, logger)
		count, err := p.Run(ctx)
		if err != nil {
			t.Errorf("provider with embedded fallback should not error on cancelled context, got: %v", err)
		}
		if count <= 0 {
			t.Errorf("expected embedded fallback controls to be written, got count %d", count)
		}
	})

	t.Run("nis2", func(t *testing.T) {
		orig := nis2.CatalogURL
		nis2.CatalogURL = srv.URL
		defer func() { nis2.CatalogURL = orig }()

		p := nis2.New(store, logger)
		count, err := p.Run(ctx)
		if err != nil {
			t.Errorf("provider with embedded fallback should not error on cancelled context, got: %v", err)
		}
		if count <= 0 {
			t.Errorf("expected embedded fallback controls to be written, got count %d", count)
		}
	})
}

func TestLiveFetchProvider_EmptyResponse(t *testing.T) {
	emptySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
	}))
	defer emptySrv.Close()

	errorSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal server error"))
	}))
	defer errorSrv.Close()

	store := &nopStore{}
	logger := resilienceLogger()

	t.Run("anssi_ebios_empty_200", func(t *testing.T) {
		orig := anssi_ebios.CatalogURL
		anssi_ebios.CatalogURL = emptySrv.URL
		defer func() { anssi_ebios.CatalogURL = orig }()

		p := anssi_ebios.New(store, logger)
		count, err := p.Run(context.Background())
		if err != nil {
			t.Errorf("expected graceful handling of empty response, got error: %v", err)
		}
		if count < 0 {
			t.Errorf("expected non-negative count, got %d", count)
		}
	})

	t.Run("anssi_ebios_500", func(t *testing.T) {
		orig := anssi_ebios.CatalogURL
		anssi_ebios.CatalogURL = errorSrv.URL
		defer func() { anssi_ebios.CatalogURL = orig }()

		p := anssi_ebios.New(store, logger)
		count, err := p.Run(context.Background())
		if err != nil {
			t.Errorf("expected fallback to embedded controls on 500, got error: %v", err)
		}
		if count <= 0 {
			t.Errorf("expected embedded controls to be written on 500, got count %d", count)
		}
	})

	t.Run("cen_cenelec_cra_empty_200", func(t *testing.T) {
		orig := cen_cenelec_cra.CatalogURL
		cen_cenelec_cra.CatalogURL = emptySrv.URL
		defer func() { cen_cenelec_cra.CatalogURL = orig }()

		p := cen_cenelec_cra.New(store, logger)
		count, err := p.Run(context.Background())
		if err != nil {
			t.Errorf("expected graceful handling of empty response, got error: %v", err)
		}
		if count < 0 {
			t.Errorf("expected non-negative count, got %d", count)
		}
	})

	t.Run("cen_cenelec_cra_500", func(t *testing.T) {
		orig := cen_cenelec_cra.CatalogURL
		cen_cenelec_cra.CatalogURL = errorSrv.URL
		defer func() { cen_cenelec_cra.CatalogURL = orig }()

		p := cen_cenelec_cra.New(store, logger)
		count, err := p.Run(context.Background())
		if err != nil {
			t.Errorf("expected fallback to embedded controls on 500, got error: %v", err)
		}
		if count <= 0 {
			t.Errorf("expected embedded controls to be written on 500, got count %d", count)
		}
	})

	t.Run("nis2_empty_200", func(t *testing.T) {
		orig := nis2.CatalogURL
		nis2.CatalogURL = emptySrv.URL
		defer func() { nis2.CatalogURL = orig }()

		p := nis2.New(store, logger)
		count, err := p.Run(context.Background())
		if err != nil {
			t.Errorf("expected graceful handling of empty response, got error: %v", err)
		}
		if count < 0 {
			t.Errorf("expected non-negative count, got %d", count)
		}
	})

	t.Run("nis2_500", func(t *testing.T) {
		orig := nis2.CatalogURL
		nis2.CatalogURL = errorSrv.URL
		defer func() { nis2.CatalogURL = orig }()

		p := nis2.New(store, logger)
		count, err := p.Run(context.Background())
		if err != nil {
			t.Errorf("expected fallback to embedded controls on 500, got error: %v", err)
		}
		if count <= 0 {
			t.Errorf("expected embedded controls to be written on 500, got count %d", count)
		}
	})
}
