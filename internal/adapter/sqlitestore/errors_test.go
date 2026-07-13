package sqlitestore

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/agentnameservice/agent-trust-discovery/internal/domain"
	"github.com/agentnameservice/agent-trust-discovery/internal/port"
)

func TestOpenDirCreationFails(t *testing.T) {
	f := filepath.Join(t.TempDir(), "afile")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The db path's parent is a regular file, so MkdirAll must fail.
	if _, err := Open(context.Background(), filepath.Join(f, "nested", "ans.db")); err == nil {
		t.Fatal("expected error when parent dir cannot be created")
	}
}

// Every method must surface the underlying DB error rather than swallow it.
// A closed handle is the simplest fault injector.
func TestOperationsOnClosedDBError(t *testing.T) {
	ctx := context.Background()
	db, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	now := time.Date(2026, 5, 28, 0, 0, 0, 0, time.UTC)
	a := domain.Agent{ID: "a1", DNSName: "d", DisplayName: "n", Status: domain.StatusActive, FirstSeen: now, LastUpdated: now}
	obs := domain.SignalObservation{AgentID: "a1", SignalID: "s", ObservedAt: now, Value: json.RawMessage("{}")}

	if err := db.UpsertAgent(ctx, a); err == nil {
		t.Error("UpsertAgent on closed db: want error")
	}
	if _, _, err := db.GetAgent(ctx, "a1"); err == nil {
		t.Error("GetAgent on closed db: want error")
	}
	if err := db.AppendObservation(ctx, obs); err == nil {
		t.Error("AppendObservation on closed db: want error")
	}
	if _, err := db.LatestObservation(ctx, "a1", "s"); err == nil {
		t.Error("LatestObservation on closed db: want error")
	}
	if _, err := db.Search(ctx, port.SearchQuery{}); err == nil {
		t.Error("Search on closed db: want error")
	}
	if _, err := db.Search(ctx, port.SearchQuery{TotalRequired: true}); err == nil {
		t.Error("Search(total) on closed db: want error")
	}
}

// White-box: malformed stored rows must surface decode errors per scanned
// column rather than silently return zero values. These rows bypass the normal
// writers via direct INSERTs.
func TestScanSurfacesMalformedRows(t *testing.T) {
	ctx := context.Background()
	db, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	good := time.Date(2026, 5, 28, 0, 0, 0, 0, time.UTC).Format(time.RFC3339Nano)
	const ins = `INSERT INTO agents
	    (agent_id, dns_name, display_name, status, protocols, transports, tags, capabilities, first_seen, last_updated)
	    VALUES (?, 'd', 'n', 'ACTIVE', ?, ?, ?, ?, ?, ?)`
	seed := func(id, proto, trans, tags, caps, fs, lu string) {
		t.Helper()
		if _, err := db.db.ExecContext(ctx, ins, id, proto, trans, tags, caps, fs, lu); err != nil {
			t.Fatalf("seed %s: %v", id, err)
		}
	}
	// Exactly one malformed column per row, covering every scanAgent decode branch.
	seed("bad-proto", "x", "[]", "[]", "[]", good, good)
	seed("bad-trans", "[]", "x", "[]", "[]", good, good)
	seed("bad-tags", "[]", "[]", "x", "[]", good, good)
	seed("bad-caps", "[]", "[]", "[]", "x", good, good)
	seed("bad-firstseen", "[]", "[]", "[]", "[]", "not-a-time", good)
	seed("bad-lastupdated", "[]", "[]", "[]", "[]", good, "not-a-time")

	for _, id := range []string{"bad-proto", "bad-trans", "bad-tags", "bad-caps", "bad-firstseen", "bad-lastupdated"} {
		if _, _, err := db.GetAgent(ctx, domain.AgentID(id)); err == nil {
			t.Errorf("GetAgent(%s): expected decode error", id)
		}
	}
}

func TestLatestObservationSurfacesMalformedRows(t *testing.T) {
	ctx := context.Background()
	db, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	now := time.Date(2026, 5, 28, 0, 0, 0, 0, time.UTC)
	if err := db.UpsertAgent(ctx, domain.Agent{
		ID: "a1", DNSName: "d", DisplayName: "n", Status: domain.StatusActive, FirstSeen: now, LastUpdated: now,
	}); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	const ins = `INSERT INTO signal_observations (agent_id, signal_id, observed_at, value_json, provenance_json)
	             VALUES ('a1', ?, ?, '{}', ?)`
	good := now.Format(time.RFC3339Nano)
	if _, err := db.db.ExecContext(ctx, ins, "bad-time", "not-a-timestamp", nil); err != nil {
		t.Fatalf("seed obs: %v", err)
	}
	if _, err := db.db.ExecContext(ctx, ins, "bad-prov", good, "not-json"); err != nil {
		t.Fatalf("seed obs: %v", err)
	}

	if _, err := db.LatestObservation(ctx, "a1", "bad-time"); err == nil {
		t.Error("LatestObservation(bad-time): expected time parse error")
	}
	if _, err := db.LatestObservation(ctx, "a1", "bad-prov"); err == nil {
		t.Error("LatestObservation(bad-prov): expected provenance decode error")
	}
}
