package sqlitestore

import (
	"context"
	"testing"
)

func openMem(t *testing.T) *DB {
	t.Helper()
	db, err := Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestApplyMigrationReadError(t *testing.T) {
	db := openMem(t)
	if err := db.applyMigration(context.Background(), "does-not-exist.sql"); err == nil {
		t.Error("applyMigration(missing file): want error")
	}
}

func TestApplyMigrationExecErrorRollsBack(t *testing.T) {
	db := openMem(t)
	// Re-applying the initial migration conflicts with the tables it already
	// created → exec error → rollback path.
	if err := db.applyMigration(context.Background(), "0001_init.sql"); err == nil {
		t.Error("re-apply 0001_init: want exec error")
	}
}

func TestMigrateAndLoadAppliedErrors(t *testing.T) {
	db := openMem(t)
	ctx := context.Background()
	if _, err := db.db.ExecContext(ctx, `DROP TABLE schema_migrations`); err != nil {
		t.Fatalf("drop schema_migrations: %v", err)
	}
	// With the bookkeeping table gone, loading applied versions fails.
	if _, err := db.loadAppliedMigrations(ctx); err == nil {
		t.Error("loadAppliedMigrations after drop: want error")
	}
	// migrate() recreates schema_migrations, sees nothing applied, then re-applies
	// 0001 which conflicts with the still-present data tables → error propagates.
	if err := db.migrate(ctx); err == nil {
		t.Error("migrate after drop: want error from re-applying 0001")
	}
}
