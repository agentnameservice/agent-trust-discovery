package sqlitestore

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/agentnameservice/agent-trust-discovery/internal/domain"
)

// White-box: exercises the ON DELETE CASCADE FK and the agents_ad trigger.
// No public delete method exists (design §5.2 has no delete endpoint), so this
// guards the schema invariant directly via the underlying handle.
func TestCascadeDeleteRemovesObservationsAndFTSRow(t *testing.T) {
	ctx := context.Background()
	db, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	now := time.Date(2026, 5, 28, 0, 0, 0, 0, time.UTC)
	a := domain.Agent{
		ID: "agent-001", DNSName: "ans://v1.0.0.booking.example.com", DisplayName: "Booking",
		Status: domain.StatusActive, FirstSeen: now, LastUpdated: now,
	}
	if err := db.UpsertAgent(ctx, a); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if err := db.AppendObservation(ctx, domain.SignalObservation{
		AgentID: "agent-001", SignalID: "certtype", ObservedAt: now, Value: json.RawMessage(`{"type":"DV"}`),
	}); err != nil {
		t.Fatalf("append: %v", err)
	}

	if n := countRows(t, db, `SELECT COUNT(*) FROM agents_fts WHERE agent_id = 'agent-001'`); n != 1 {
		t.Fatalf("fts rows before delete = %d, want 1", n)
	}

	if _, err := db.db.ExecContext(ctx, `DELETE FROM agents WHERE agent_id = 'agent-001'`); err != nil {
		t.Fatalf("delete: %v", err)
	}

	if n := countRows(t, db, `SELECT COUNT(*) FROM signal_observations WHERE agent_id = 'agent-001'`); n != 0 {
		t.Errorf("observations after cascade = %d, want 0", n)
	}
	if n := countRows(t, db, `SELECT COUNT(*) FROM agents_fts WHERE agent_id = 'agent-001'`); n != 0 {
		t.Errorf("fts rows after delete = %d, want 0 (agents_ad trigger)", n)
	}
	if obs, err := db.LatestObservation(ctx, "agent-001", "certtype"); err != nil || obs != nil {
		t.Errorf("LatestObservation after cascade = %+v err=%v, want nil", obs, err)
	}
}

func countRows(t *testing.T, db *DB, query string) int {
	t.Helper()
	var n int
	if err := db.db.QueryRowContext(context.Background(), query).Scan(&n); err != nil {
		t.Fatalf("count query: %v", err)
	}
	return n
}
