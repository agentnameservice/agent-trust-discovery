package sqlitestore_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/agentnameservice/agent-trust-discovery/internal/domain"
)

// TestAppendObservationDedupsIdenticalTriple guards the idempotency contract
// added in migration 0002: (agent_id, signal_id, observed_at) is UNIQUE, and
// re-inserting the same triple is a no-op. Without this, a cadence-loop or
// retry would grow the observations table unboundedly.
func TestAppendObservationDedupsIdenticalTriple(t *testing.T) {
	db := newStore(t)
	ctx := context.Background()
	if err := db.UpsertAgent(ctx, sampleAgent("agent-001")); err != nil {
		t.Fatalf("UpsertAgent: %v", err)
	}

	at := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	obs := domain.SignalObservation{
		AgentID: "agent-001", SignalID: "certtype",
		ObservedAt: at,
		Value:      json.RawMessage(`{"type":"DV"}`),
	}
	for range 5 {
		if err := db.AppendObservation(ctx, obs); err != nil {
			t.Fatalf("append: %v", err)
		}
	}

	// LatestObservation must still return the value.
	got, err := db.LatestObservation(ctx, "agent-001", "certtype")
	if err != nil || got == nil {
		t.Fatalf("LatestObservation: got=%v err=%v", got, err)
	}
	if string(got.Value) != `{"type":"DV"}` {
		t.Fatalf("value = %s, want DV", string(got.Value))
	}

	// Pruning to 100 must remove nothing — there is one distinct row.
	deleted, err := db.PruneObservations(ctx, 100)
	if err != nil {
		t.Fatalf("PruneObservations: %v", err)
	}
	if deleted != 0 {
		t.Fatalf("pruned = %d, want 0 (only one distinct row exists)", deleted)
	}
}

// TestPruneObservationsKeepsNewestK exercises the retention window: after
// pruning, only the K most recent rows per (agent_id, signal_id) survive,
// and the surviving row LatestObservation reads is unchanged.
func TestPruneObservationsKeepsNewestK(t *testing.T) {
	db := newStore(t)
	ctx := context.Background()
	if err := db.UpsertAgent(ctx, sampleAgent("agent-001")); err != nil {
		t.Fatalf("UpsertAgent: %v", err)
	}

	base := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	const n = 10
	for i := range n {
		obs := domain.SignalObservation{
			AgentID: "agent-001", SignalID: "certtype",
			ObservedAt: base.Add(time.Duration(i) * time.Hour),
			Value:      json.RawMessage(`{"type":"DV"}`),
		}
		if err := db.AppendObservation(ctx, obs); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}

	deleted, err := db.PruneObservations(ctx, 3)
	if err != nil {
		t.Fatalf("PruneObservations: %v", err)
	}
	if deleted != n-3 {
		t.Fatalf("deleted = %d, want %d", deleted, n-3)
	}

	// The engine-visible latest row must still be the most recent.
	got, err := db.LatestObservation(ctx, "agent-001", "certtype")
	if err != nil || got == nil {
		t.Fatalf("LatestObservation: got=%v err=%v", got, err)
	}
	wantTS := base.Add(time.Duration(n-1) * time.Hour)
	if !got.ObservedAt.Equal(wantTS) {
		t.Fatalf("latest observedAt = %v, want %v", got.ObservedAt, wantTS)
	}
}

// TestPruneObservationsScopedPerPair guards that pruning respects the
// (agent_id, signal_id) partition — trimming one signal's history must not
// touch another signal or another agent.
func TestPruneObservationsScopedPerPair(t *testing.T) {
	db := newStore(t)
	ctx := context.Background()
	for _, id := range []string{"agent-001", "agent-002"} {
		if err := db.UpsertAgent(ctx, sampleAgent(id)); err != nil {
			t.Fatalf("UpsertAgent %s: %v", id, err)
		}
	}

	base := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	pairs := []struct {
		agent  domain.AgentID
		signal domain.SignalID
	}{
		{"agent-001", "certtype"},
		{"agent-001", "dnssecurity"},
		{"agent-002", "certtype"},
	}
	for _, p := range pairs {
		for i := range 5 {
			obs := domain.SignalObservation{
				AgentID: p.agent, SignalID: p.signal,
				ObservedAt: base.Add(time.Duration(i) * time.Hour),
				Value:      json.RawMessage(`{"type":"DV"}`),
			}
			if err := db.AppendObservation(ctx, obs); err != nil {
				t.Fatalf("append %s/%s#%d: %v", p.agent, p.signal, i, err)
			}
		}
	}

	// Keep 2 per pair: expect 3 pairs * (5-2) = 9 deletions.
	deleted, err := db.PruneObservations(ctx, 2)
	if err != nil {
		t.Fatalf("PruneObservations: %v", err)
	}
	if deleted != 9 {
		t.Fatalf("deleted = %d, want 9", deleted)
	}

	// Every pair still has a readable latest observation.
	for _, p := range pairs {
		got, err := db.LatestObservation(ctx, p.agent, p.signal)
		if err != nil || got == nil {
			t.Fatalf("LatestObservation(%s,%s): got=%v err=%v", p.agent, p.signal, got, err)
		}
	}
}

// TestPruneObservationsZeroIsNoOp guards the boundary: keepPerPair ≤ 0 must
// be a no-op (retention disabled), never a table wipe.
func TestPruneObservationsZeroIsNoOp(t *testing.T) {
	db := newStore(t)
	ctx := context.Background()
	if err := db.UpsertAgent(ctx, sampleAgent("agent-001")); err != nil {
		t.Fatalf("UpsertAgent: %v", err)
	}
	if err := db.AppendObservation(ctx, domain.SignalObservation{
		AgentID: "agent-001", SignalID: "certtype",
		ObservedAt: time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC),
		Value:      json.RawMessage(`{"type":"DV"}`),
	}); err != nil {
		t.Fatalf("append: %v", err)
	}
	for _, k := range []int{0, -1, -100} {
		deleted, err := db.PruneObservations(ctx, k)
		if err != nil {
			t.Fatalf("PruneObservations(%d): %v", k, err)
		}
		if deleted != 0 {
			t.Fatalf("PruneObservations(%d) deleted = %d, want 0", k, deleted)
		}
	}
}
