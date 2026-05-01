package grc

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/vincents-ai/enrichment-engine/pkg/storage"
)

type mockGRCProvider struct {
	name    string
	runFunc func(ctx context.Context) (int, error)
}

func (m *mockGRCProvider) Name() string { return m.name }
func (m *mockGRCProvider) Run(ctx context.Context) (int, error) {
	return m.runFunc(ctx)
}

type mockStore struct {
	storage.Backend
}

func (m *mockStore) WriteControl(ctx context.Context, id string, control interface{}) error {
	return nil
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestSortedList(t *testing.T) {
	reg := NewRegistry()
	reg.Register("charlie", nil)
	reg.Register("alpha", nil)
	reg.Register("bravo", nil)

	sorted := reg.SortedList()
	if !sort.StringsAreSorted(sorted) {
		t.Errorf("SortedList not sorted: %v", sorted)
	}
	if len(sorted) != 3 {
		t.Errorf("expected 3, got %d", len(sorted))
	}
	if sorted[0] != "alpha" || sorted[1] != "bravo" || sorted[2] != "charlie" {
		t.Errorf("expected [alpha bravo charlie], got %v", sorted)
	}
}

func TestSortedListEmpty(t *testing.T) {
	reg := NewRegistry()
	sorted := reg.SortedList()
	if len(sorted) != 0 {
		t.Errorf("expected empty list, got %v", sorted)
	}
}

func TestDefaultRegistry(t *testing.T) {
	reg := DefaultRegistry()
	if reg == nil {
		t.Fatal("DefaultRegistry returned nil")
	}
	reg2 := DefaultRegistry()
	if reg != reg2 {
		t.Error("DefaultRegistry should return singleton")
	}
}

func TestGetFound(t *testing.T) {
	reg := NewRegistry()
	called := false
	reg.Register("test", func(s storage.Backend, l *slog.Logger) GRCProvider {
		called = true
		return &mockGRCProvider{name: "test"}
	})

	p, err := reg.Get("test", nil, nil)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if !called {
		t.Error("factory function was not called")
	}
	if p == nil {
		t.Fatal("expected non-nil provider")
	}
	if p.Name() != "test" {
		t.Errorf("expected name 'test', got %q", p.Name())
	}
}

func TestGetNotFound(t *testing.T) {
	reg := NewRegistry()
	_, err := reg.Get("nonexistent", nil, nil)
	if err == nil {
		t.Fatal("expected error for unknown provider")
	}
}

func TestRunSelectedWithNames(t *testing.T) {
	reg := NewRegistry()
	var called atomic.Int32
	reg.Register("p1", func(s storage.Backend, l *slog.Logger) GRCProvider {
		return &mockGRCProvider{name: "p1", runFunc: func(ctx context.Context) (int, error) { called.Add(1); return 1, nil }}
	})
	reg.Register("p2", func(s storage.Backend, l *slog.Logger) GRCProvider {
		return &mockGRCProvider{name: "p2", runFunc: func(ctx context.Context) (int, error) { called.Add(1); return 2, nil }}
	})

	total, err := reg.RunSelected(context.Background(), []string{"p1", "p2"}, nil, nil, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if total != 3 {
		t.Errorf("expected 3, got %d", total)
	}
	if called.Load() != 2 {
		t.Errorf("expected 2 providers called, got %d", called.Load())
	}
}

func TestRunSelectedEmptyNames(t *testing.T) {
	reg := NewRegistry()
	var called atomic.Int32
	reg.Register("p1", func(s storage.Backend, l *slog.Logger) GRCProvider {
		return &mockGRCProvider{name: "p1", runFunc: func(ctx context.Context) (int, error) { called.Add(1); return 5, nil }}
	})
	reg.Register("p2", func(s storage.Backend, l *slog.Logger) GRCProvider {
		return &mockGRCProvider{name: "p2", runFunc: func(ctx context.Context) (int, error) { called.Add(1); return 3, nil }}
	})

	total, err := reg.RunSelected(context.Background(), nil, nil, nil, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if total != 8 {
		t.Errorf("expected 8, got %d", total)
	}
	if called.Load() != 2 {
		t.Errorf("expected 2 providers called, got %d", called.Load())
	}
}

func TestRunSelectedWithInvalidName(t *testing.T) {
	reg := NewRegistry()
	reg.Register("p1", func(s storage.Backend, l *slog.Logger) GRCProvider {
		return &mockGRCProvider{name: "p1", runFunc: func(ctx context.Context) (int, error) { return 1, nil }}
	})

	total, err := reg.RunSelected(context.Background(), []string{"p1", "nonexistent"}, nil, nil, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if total != 1 {
		t.Errorf("expected 1, got %d", total)
	}
}

func TestRunSelectedParallel(t *testing.T) {
	reg := NewRegistry()
	var mu sync.Mutex
	var called []string
	reg.Register("p1", func(s storage.Backend, l *slog.Logger) GRCProvider {
		return &mockGRCProvider{name: "p1", runFunc: func(ctx context.Context) (int, error) {
			mu.Lock()
			called = append(called, "p1")
			mu.Unlock()
			return 1, nil
		}}
	})
	reg.Register("p2", func(s storage.Backend, l *slog.Logger) GRCProvider {
		return &mockGRCProvider{name: "p2", runFunc: func(ctx context.Context) (int, error) {
			mu.Lock()
			called = append(called, "p2")
			mu.Unlock()
			return 2, nil
		}}
	})

	total, err := reg.RunSelected(context.Background(), []string{"p1", "p2"}, nil, nil, 4)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if total != 3 {
		t.Errorf("expected 3, got %d", total)
	}
	if len(called) != 2 {
		t.Errorf("expected 2 providers called, got %d", len(called))
	}
}

func TestRunSelectedSequentialError(t *testing.T) {
	reg := NewRegistry()
	reg.Register("p1", func(s storage.Backend, l *slog.Logger) GRCProvider {
		return &mockGRCProvider{name: "p1", runFunc: func(ctx context.Context) (int, error) {
			return 0, errors.New("fail")
		}}
	})

	total, err := reg.RunSelected(context.Background(), []string{"p1"}, nil, testLogger(), 1)
	if err != nil {
		t.Fatalf("sequential RunSelected should not return error, got: %v", err)
	}
	if total != 0 {
		t.Errorf("expected 0, got %d", total)
	}
}

func TestRunSelectedParallelError(t *testing.T) {
	reg := NewRegistry()
	reg.Register("p1", func(s storage.Backend, l *slog.Logger) GRCProvider {
		return &mockGRCProvider{name: "p1", runFunc: func(ctx context.Context) (int, error) {
			return 0, errors.New("fail")
		}}
	})

	total, err := reg.RunSelected(context.Background(), []string{"p1"}, nil, testLogger(), 2)
	if err == nil {
		t.Fatal("expected error from parallel RunSelected")
	}
	if total != 0 {
		t.Errorf("expected 0, got %d", total)
	}
}

func TestRunSelectedZeroMaxParallel(t *testing.T) {
	reg := NewRegistry()
	var called atomic.Int32
	reg.Register("p1", func(s storage.Backend, l *slog.Logger) GRCProvider {
		return &mockGRCProvider{name: "p1", runFunc: func(ctx context.Context) (int, error) { called.Add(1); return 1, nil }}
	})

	total, err := reg.RunSelected(context.Background(), []string{"p1"}, nil, nil, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if total != 1 {
		t.Errorf("expected 1, got %d", total)
	}
	if called.Load() != 1 {
		t.Errorf("expected 1 provider called, got %d", called.Load())
	}
}

func TestRunSelectedNegativeMaxParallel(t *testing.T) {
	reg := NewRegistry()
	reg.Register("p1", func(s storage.Backend, l *slog.Logger) GRCProvider {
		return &mockGRCProvider{name: "p1", runFunc: func(ctx context.Context) (int, error) { return 1, nil }}
	})

	total, err := reg.RunSelected(context.Background(), []string{"p1"}, nil, nil, -5)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if total != 1 {
		t.Errorf("expected 1, got %d", total)
	}
}

func TestRunAllEmpty(t *testing.T) {
	reg := NewRegistry()
	total, err := reg.RunAll(context.Background(), nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if total != 0 {
		t.Errorf("expected 0, got %d", total)
	}
}

func TestRunAllWithProviders(t *testing.T) {
	reg := NewRegistry()
	reg.Register("p1", func(s storage.Backend, l *slog.Logger) GRCProvider {
		return &mockGRCProvider{name: "p1", runFunc: func(ctx context.Context) (int, error) { return 3, nil }}
	})

	total, err := reg.RunAll(context.Background(), nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if total != 3 {
		t.Errorf("expected 3, got %d", total)
	}
}

func TestRunSelectedMixedSuccessAndError(t *testing.T) {
	reg := NewRegistry()
	reg.Register("p1", func(s storage.Backend, l *slog.Logger) GRCProvider {
		return &mockGRCProvider{name: "p1", runFunc: func(ctx context.Context) (int, error) { return 2, nil }}
	})
	reg.Register("p2", func(s storage.Backend, l *slog.Logger) GRCProvider {
		return &mockGRCProvider{name: "p2", runFunc: func(ctx context.Context) (int, error) { return 0, errors.New("fail") }}
	})

	total, err := reg.RunSelected(context.Background(), []string{"p1", "p2"}, nil, testLogger(), 1)
	if err != nil {
		t.Fatalf("sequential RunSelected should not return error, got: %v", err)
	}
	if total != 2 {
		t.Errorf("expected 2, got %d", total)
	}
}

func TestRunSelectedParallelMixedSuccessAndError(t *testing.T) {
	reg := NewRegistry()
	reg.Register("p1", func(s storage.Backend, l *slog.Logger) GRCProvider {
		return &mockGRCProvider{name: "p1", runFunc: func(ctx context.Context) (int, error) { return 2, nil }}
	})
	reg.Register("p2", func(s storage.Backend, l *slog.Logger) GRCProvider {
		return &mockGRCProvider{name: "p2", runFunc: func(ctx context.Context) (int, error) { return 0, errors.New("fail") }}
	})

	total, err := reg.RunSelected(context.Background(), []string{"p1", "p2"}, nil, testLogger(), 2)
	if err == nil {
		t.Fatal("expected error from parallel RunSelected with mixed results")
	}
	if total != 2 {
		t.Errorf("expected 2 (from successful provider), got %d", total)
	}
}
