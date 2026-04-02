package test

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/shift/enrichment-engine/pkg/storage"
)

func SetupTestDB(t *testing.T) *storage.SQLiteBackend {
	t.Helper()
	path := t.TempDir() + "/test.db"
	backend, err := storage.NewSQLiteBackend(path)
	if err != nil {
		t.Fatalf("setup test db: %v", err)
	}
	t.Cleanup(func() { backend.Close(context.Background()) })
	return backend
}

func TestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}
