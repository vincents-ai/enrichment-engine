package grc_test

import (
	"context"
	"testing"

	"github.com/vincents-ai/enrichment-engine/pkg/grc"
	grcbuiltin "github.com/vincents-ai/enrichment-engine/pkg/grc/builtin"
)

func TestDefaultRegistryHasAllProviders(t *testing.T) {
	reg := grcbuiltin.DefaultRegistry()
	providers := reg.List()
	if len(providers) < 43 {
		t.Errorf("expected at least 43 providers, got %d", len(providers))
	}
}

func TestRegistryGetUnknown(t *testing.T) {
	reg := grc.NewRegistry()
	_, err := reg.Get("nonexistent", nil, nil)
	if err == nil {
		t.Error("expected error for unknown provider")
	}
}

func TestRegistryListEmpty(t *testing.T) {
	reg := grc.NewRegistry()
	names := reg.List()
	if len(names) != 0 {
		t.Errorf("expected empty list, got %v", names)
	}
}

func TestRegistryRegisterAndGet(t *testing.T) {
	reg := grc.NewRegistry()
	reg.Register("test_provider", nil)

	names := reg.List()
	if len(names) != 1 || names[0] != "test_provider" {
		t.Errorf("expected [test_provider], got %v", names)
	}

	_, err := reg.Get("nonexistent_provider", nil, nil)
	if err == nil {
		t.Error("expected error for unregistered provider")
	}
}

func TestRegistryProviderNames(t *testing.T) {
	reg := grcbuiltin.DefaultRegistry()
	names := reg.ProviderNames()
	list := reg.List()
	if len(names) != len(list) {
		t.Errorf("ProviderNames() returned %d, List() returned %d", len(names), len(list))
	}
}

func TestRegistryRunAllEmpty(t *testing.T) {
	reg := grc.NewRegistry()
	total, err := reg.RunAll(context.Background(), nil, nil)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if total != 0 {
		t.Errorf("expected 0, got %d", total)
	}
}
