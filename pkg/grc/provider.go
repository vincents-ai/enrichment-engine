package grc

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"sync"

	"github.com/vincents-ai/enrichment-engine/pkg/storage"
)

type GRCProvider interface {
	Name() string
	Run(ctx context.Context) (int, error)
}

type providerFactory func(s storage.Backend, l *slog.Logger) GRCProvider

type Registry struct {
	providers map[string]providerFactory
}

func NewRegistry() *Registry {
	return &Registry{providers: make(map[string]providerFactory)}
}

func (r *Registry) Register(name string, fn func(s storage.Backend, l *slog.Logger) GRCProvider) {
	r.providers[name] = fn
}

func (r *Registry) Get(name string, store storage.Backend, logger *slog.Logger) (GRCProvider, error) {
	fn, ok := r.providers[name]
	if !ok {
		return nil, fmt.Errorf("provider %s not found", name)
	}
	return fn(store, logger), nil
}

func (r *Registry) List() []string {
	names := make([]string, 0, len(r.providers))
	for name := range r.providers {
		names = append(names, name)
	}
	return names
}

func (r *Registry) SortedList() []string {
	names := r.List()
	sort.Strings(names)
	return names
}

func (r *Registry) ProviderNames() []string {
	return r.List()
}

func (r *Registry) RunAll(ctx context.Context, store storage.Backend, logger *slog.Logger) (int, error) {
	return r.RunSelected(ctx, nil, store, logger, 1)
}

func (r *Registry) RunSelected(ctx context.Context, names []string, store storage.Backend, logger *slog.Logger, maxParallel int) (int, error) {
	if maxParallel <= 0 {
		maxParallel = 1
	}

	type namedProvider struct {
		name string
		fn   providerFactory
	}

	var toRun []namedProvider
	if len(names) > 0 {
		nameSet := make(map[string]bool, len(names))
		for _, n := range names {
			nameSet[n] = true
		}
		for n, fn := range r.providers {
			if nameSet[n] {
				toRun = append(toRun, namedProvider{name: n, fn: fn})
			}
		}
	} else {
		for n, fn := range r.providers {
			toRun = append(toRun, namedProvider{name: n, fn: fn})
		}
	}

	if maxParallel == 1 {
		total := 0
		for _, np := range toRun {
			p := np.fn(store, logger)
			count, err := p.Run(ctx)
			if err != nil {
				logger.Warn("provider failed", "provider", np.name, "error", err)
				continue
			}
			total += count
		}
		return total, nil
	}

	sem := make(chan struct{}, maxParallel)
	var mu sync.Mutex
	var total int
	var firstErr error
	var wg sync.WaitGroup

	for _, np := range toRun {
		wg.Add(1)
		go func(np namedProvider) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			p := np.fn(store, logger)
			count, err := p.Run(ctx)
			if err != nil {
				mu.Lock()
				if firstErr == nil {
					firstErr = fmt.Errorf("provider %s: %w", np.name, err)
				}
				mu.Unlock()
				logger.Warn("provider failed", "provider", np.name, "error", err)
				return
			}
			mu.Lock()
			total += count
			mu.Unlock()
		}(np)
	}
	wg.Wait()

	return total, firstErr
}

var (
	defaultRegistry     *Registry
	defaultRegistryOnce sync.Once
)

func DefaultRegistry() *Registry {
	defaultRegistryOnce.Do(func() {
		defaultRegistry = NewRegistry()
	})
	return defaultRegistry
}
