package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	_ "github.com/mattn/go-sqlite3"
)

type SQLiteBackend struct {
	db        *sql.DB
	dbPath    string
	tempPath  string
	batch     []*Envelope
	batchSize int
	mu        sync.Mutex
	closed    bool
}

type Envelope struct {
	Schema     string      `json:"schema"`
	Identifier string      `json:"identifier"`
	Item       interface{} `json:"item"`
}

func NewSQLiteBackend(path string, batchSize int) (*SQLiteBackend, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("create database directory: %w", err)
	}

	tempPath := path + ".tmp"
	if err := os.Remove(tempPath); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("remove existing temp database: %w", err)
	}

	db, err := sql.Open("sqlite3", tempPath)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	backend := &SQLiteBackend{
		db:        db,
		dbPath:    path,
		tempPath:  tempPath,
		batch:     make([]*Envelope, 0, batchSize),
		batchSize: batchSize,
	}

	if err := backend.initialize(); err != nil {
		db.Close()
		return nil, fmt.Errorf("initialize database: %w", err)
	}

	return backend, nil
}

func (s *SQLiteBackend) initialize() error {
	pragmas := []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA synchronous=NORMAL",
		"PRAGMA cache_size=10000",
		"PRAGMA temp_store=MEMORY",
		"PRAGMA wal_autocheckpoint=10000",
	}

	for _, pragma := range pragmas {
		if _, err := s.db.Exec(pragma); err != nil {
			return fmt.Errorf("execute %s: %w", pragma, err)
		}
	}

	schema := `
		CREATE TABLE IF NOT EXISTS vulnerabilities (
			id TEXT PRIMARY KEY,
			record BLOB NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_vuln_id ON vulnerabilities(id);

		CREATE TABLE IF NOT EXISTS grc_controls (
			id TEXT PRIMARY KEY,
			framework TEXT NOT NULL,
			control_id TEXT NOT NULL,
			title TEXT NOT NULL,
			family TEXT,
			description TEXT,
			related_cves TEXT,
			record BLOB NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_grc_framework ON grc_controls(framework);
		CREATE INDEX IF NOT EXISTS idx_grc_control_id ON grc_controls(control_id);

		CREATE TABLE IF NOT EXISTS vulnerability_grc_mappings (
			vulnerability_id TEXT NOT NULL,
			control_id TEXT NOT NULL,
			framework TEXT NOT NULL,
			mapping_type TEXT NOT NULL,
			confidence REAL NOT NULL,
			evidence TEXT,
			PRIMARY KEY (vulnerability_id, control_id, framework)
		);
		CREATE INDEX IF NOT EXISTS idx_mapping_vuln ON vulnerability_grc_mappings(vulnerability_id);
		CREATE INDEX IF NOT EXISTS idx_mapping_control ON vulnerability_grc_mappings(control_id);
		CREATE INDEX IF NOT EXISTS idx_mapping_framework ON vulnerability_grc_mappings(framework);
	`

	if _, err := s.db.Exec(schema); err != nil {
		return fmt.Errorf("create schema: %w", err)
	}

	return nil
}

func (s *SQLiteBackend) Write(ctx context.Context, envelope *Envelope) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return fmt.Errorf("backend is closed")
	}

	s.batch = append(s.batch, envelope)

	if len(s.batch) >= s.batchSize {
		return s.flushBatchLocked(ctx)
	}

	return nil
}

func (s *SQLiteBackend) flushBatchLocked(ctx context.Context) error {
	if len(s.batch) == 0 {
		return nil
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, "INSERT OR REPLACE INTO vulnerabilities (id, record) VALUES (?, ?)")
	if err != nil {
		return fmt.Errorf("prepare statement: %w", err)
	}
	defer stmt.Close()

	for _, envelope := range s.batch {
		recordJSON, err := json.Marshal(envelope)
		if err != nil {
			return fmt.Errorf("marshal envelope %s: %w", envelope.Identifier, err)
		}

		if _, err := stmt.ExecContext(ctx, envelope.Identifier, recordJSON); err != nil {
			return fmt.Errorf("insert record %s: %w", envelope.Identifier, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}

	s.batch = s.batch[:0]

	return nil
}

func (s *SQLiteBackend) WriteControl(ctx context.Context, envelope *Envelope, framework, controlID, title, family, description string, relatedCVEs []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return fmt.Errorf("backend is closed")
	}

	cvesJSON := "[]"
	if len(relatedCVEs) > 0 {
		cvesBytes, _ := json.Marshal(relatedCVEs)
		cvesJSON = string(cvesBytes)
	}

	recordJSON, err := json.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("marshal envelope %s: %w", envelope.Identifier, err)
	}

	_, err = s.db.ExecContext(ctx,
		`INSERT OR REPLACE INTO grc_controls (id, framework, control_id, title, family, description, related_cves, record) 
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		envelope.Identifier, framework, controlID, title, family, description, cvesJSON, recordJSON)

	if err != nil {
		return fmt.Errorf("insert control %s: %w", envelope.Identifier, err)
	}

	return nil
}

func (s *SQLiteBackend) WriteMapping(ctx context.Context, vulnID, controlID, framework, mappingType string, confidence float64, evidence string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.ExecContext(ctx,
		`INSERT OR REPLACE INTO vulnerability_grc_mappings (vulnerability_id, control_id, framework, mapping_type, confidence, evidence) 
		 VALUES (?, ?, ?, ?, ?, ?)`,
		vulnID, controlID, framework, mappingType, confidence, evidence)

	if err != nil {
		return fmt.Errorf("insert mapping %s -> %s: %w", vulnID, controlID, err)
	}

	return nil
}

func (s *SQLiteBackend) Close(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}
	s.closed = true

	if err := s.flushBatchLocked(ctx); err != nil {
		return fmt.Errorf("flush batch: %w", err)
	}

	if _, err := s.db.Exec("PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		return fmt.Errorf("checkpoint wal: %w", err)
	}

	if err := s.db.Close(); err != nil {
		return fmt.Errorf("close database: %w", err)
	}

	for _, suffix := range []string{"-wal", "-shm"} {
		sidecar := s.tempPath + suffix
		if _, err := os.Stat(sidecar); err == nil {
			os.Remove(sidecar)
		}
	}

	if _, err := os.Stat(s.tempPath); err == nil {
		if err := os.Rename(s.tempPath, s.dbPath); err != nil {
			return fmt.Errorf("move database to final location: %w", err)
		}
	}

	return nil
}
