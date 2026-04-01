package grc

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/shift/enrichment-engine/pkg/storage"
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

func (r *Registry) ProviderNames() []string {
	return r.List()
}

func (r *Registry) RunAll(ctx context.Context, store storage.Backend, logger *slog.Logger) (int, error) {
	total := 0
	for name, fn := range r.providers {
		p := fn(store, logger)
		count, err := p.Run(ctx)
		if err != nil {
			logger.Warn("provider failed", "provider", name, "error", err)
			continue
		}
		total += count
	}
	return total, nil
}

var defaultRegistry *Registry

func DefaultRegistry() *Registry {
	if defaultRegistry == nil {
		defaultRegistry = NewRegistry()
	}
	return defaultRegistry
}
