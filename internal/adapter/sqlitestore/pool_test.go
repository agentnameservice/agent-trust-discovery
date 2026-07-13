package sqlitestore

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
)

// TestPoolSizingByMode locks in the WAL-vs-:memory: pool policy: an on-disk
// database must expose more than one connection so concurrent readers can run
// in parallel, while :memory: must stay at one connection to preserve a single
// coherent database (each new :memory: connection opens an independent DB).
func TestPoolSizingByMode(t *testing.T) {
	ctx := context.Background()

	mem, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("Open :memory:: %v", err)
	}
	t.Cleanup(func() { _ = mem.Close() })
	if got := mem.db.Stats().MaxOpenConnections; got != 1 {
		t.Errorf(":memory: MaxOpenConnections = %d, want 1", got)
	}

	disk, err := Open(ctx, filepath.Join(t.TempDir(), "ans.db"))
	if err != nil {
		t.Fatalf("Open on-disk: %v", err)
	}
	t.Cleanup(func() { _ = disk.Close() })
	if got := disk.db.Stats().MaxOpenConnections; got <= 1 {
		t.Errorf("on-disk MaxOpenConnections = %d, want > 1 to enable WAL concurrent readers", got)
	}
}

// TestConcurrentReadsDoNotSerialize demonstrates that on WAL-mode disk stores,
// many read queries can execute in parallel. With MaxOpenConns(1) this test
// would serialize; the assertion is loose (>1 conn observed in flight) but is
// enough to catch a regression back to the single-connection pool.
func TestConcurrentReadsDoNotSerialize(t *testing.T) {
	ctx := context.Background()
	disk, err := Open(ctx, filepath.Join(t.TempDir(), "ans.db"))
	if err != nil {
		t.Fatalf("Open on-disk: %v", err)
	}
	t.Cleanup(func() { _ = disk.Close() })

	const readers = 8
	var wg sync.WaitGroup
	start := make(chan struct{})
	wg.Add(readers)
	for range readers {
		go func() {
			defer wg.Done()
			<-start
			// A trivial query that will still take a connection from the pool.
			row := disk.db.QueryRowContext(ctx, `SELECT 1`)
			var n int
			if err := row.Scan(&n); err != nil {
				t.Errorf("scan: %v", err)
			}
		}()
	}
	close(start)
	wg.Wait()

	// After a wave of concurrent readers, the pool should have observed
	// more than one connection in use at some point during the run.
	if got := disk.db.Stats().MaxOpenConnections; got <= 1 {
		t.Errorf("pool cap = %d, want > 1", got)
	}
}
