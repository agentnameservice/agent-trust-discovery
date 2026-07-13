// Package sqlitestore is the SQLite implementation of the AgentStore and Index
// ports (design §7). It uses modernc.org/sqlite — a pure-Go SQLite — so the
// binaries build without CGO, and an FTS5 virtual table kept in sync by triggers
// backs full-text search. Schema migrations are embedded and applied on Open.
package sqlitestore

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	_ "modernc.org/sqlite" // driver name "sqlite"

	"github.com/agentnameservice/agent-trust-discovery/internal/port"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

const (
	// inMemoryPath is the SQLite DSN that opens an anonymous, in-memory
	// database. Any connection to this DSN opens an INDEPENDENT database, so
	// callers that use it must serialize through a single connection.
	inMemoryPath = ":memory:"

	// diskMaxOpenConns caps the connection pool for on-disk (WAL) databases.
	// WAL permits many concurrent readers alongside a single writer; this
	// ceiling lets readers run in parallel while keeping resource usage bounded.
	diskMaxOpenConns = 4
)

// Compile-time proof the adapter satisfies both storage ports.
var (
	_ port.AgentStore = (*DB)(nil)
	_ port.Index      = (*DB)(nil)
)

// DB is the SQLite-backed store. Construct it with Open, which applies pending
// migrations automatically.
type DB struct {
	db *sql.DB
}

// Open creates or opens the database at path and applies pending migrations.
// path == ":memory:" yields an in-memory DB (useful for tests).
func Open(ctx context.Context, path string) (*DB, error) {
	inMemory := path == inMemoryPath

	// Ensure the parent dir exists so a relative path like "./data/ans.db"
	// works without operator setup.
	if !inMemory {
		dir := filepath.Dir(path)
		if dir != "" && dir != "." {
			if err := os.MkdirAll(dir, 0o700); err != nil {
				return nil, fmt.Errorf("sqlitestore: create dir %s: %w", dir, err)
			}
		}
	}

	// Enforce foreign keys (for ON DELETE CASCADE) and a busy timeout. WAL is
	// unsupported for in-memory DBs.
	dsn := path + "?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)"
	if inMemory {
		dsn = path + "?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)"
	}

	sqlDB, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlitestore: open: %w", err)
	}
	// On disk with WAL, multiple readers can proceed concurrently with a single
	// writer; capping the pool at 1 would serialize reads behind writes and
	// negate that benefit. For :memory: each new connection opens an independent
	// database, so the pool must stay at 1 for the DB to remain coherent.
	maxOpen := diskMaxOpenConns
	if inMemory {
		maxOpen = 1
	}
	sqlDB.SetMaxOpenConns(maxOpen)
	sqlDB.SetMaxIdleConns(maxOpen)

	if err := sqlDB.PingContext(ctx); err != nil {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("sqlitestore: ping: %w", err)
	}

	d := &DB{db: sqlDB}
	if err := d.migrate(ctx); err != nil {
		_ = sqlDB.Close()
		return nil, err
	}
	return d, nil
}

// Close releases the underlying database handle.
func (d *DB) Close() error { return d.db.Close() }

// migrate applies every embedded migration not yet recorded in
// schema_migrations, in filename order, each in its own transaction.
//
// A full versioned runner (schema_migrations bookkeeping + sorted per-file
// transactions) is deliberate even though the RI ships only a couple of
// migrations today: the reference implementation is meant to show the
// migration pattern an operator would extend, not just the current schema.
// Adding a migration is dropping a new NNNN_*.sql into migrations/ — the
// runner picks it up on the next Open. An embedded one-shot schema would be
// smaller but would not teach that path.
func (d *DB) migrate(ctx context.Context) error {
	if _, err := d.db.ExecContext(ctx, `
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version       TEXT PRIMARY KEY,
            applied_at_ms INTEGER NOT NULL
        )`); err != nil {
		return fmt.Errorf("sqlitestore: create schema_migrations: %w", err)
	}

	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("sqlitestore: read migrations: %w", err)
	}
	files := make([]string, 0, len(entries))
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".sql") {
			files = append(files, e.Name())
		}
	}
	sort.Strings(files)

	applied, err := d.loadAppliedMigrations(ctx)
	if err != nil {
		return err
	}

	for _, f := range files {
		if _, ok := applied[f]; ok {
			continue
		}
		if err := d.applyMigration(ctx, f); err != nil {
			return err
		}
	}
	return nil
}

func (d *DB) applyMigration(ctx context.Context, name string) error {
	sqlBytes, err := migrationsFS.ReadFile("migrations/" + name)
	if err != nil {
		return fmt.Errorf("sqlitestore: read %s: %w", name, err)
	}
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("sqlitestore: begin tx for %s: %w", name, err)
	}
	if _, err := tx.ExecContext(ctx, string(sqlBytes)); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("sqlitestore: apply %s: %w", name, err)
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO schema_migrations(version, applied_at_ms) VALUES(?, strftime('%s','now')*1000)`,
		name); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("sqlitestore: record %s: %w", name, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("sqlitestore: commit %s: %w", name, err)
	}
	return nil
}

func (d *DB) loadAppliedMigrations(ctx context.Context) (map[string]struct{}, error) {
	rows, err := d.db.QueryContext(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return nil, fmt.Errorf("sqlitestore: query applied: %w", err)
	}
	defer func() { _ = rows.Close() }()
	applied := make(map[string]struct{})
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, fmt.Errorf("sqlitestore: scan applied: %w", err)
		}
		applied[v] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlitestore: iterate applied: %w", err)
	}
	return applied, nil
}
