package sqlitestore_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/agentnameservice/agent-trust-discovery/internal/domain"
)

// TestUpsertAgentsRollsBackOnRowFailure locks in the all-or-nothing contract:
// when one row in the batch fails (here: a status not in the CHECK enum), the
// earlier rows must not remain committed.
func TestUpsertAgentsRollsBackOnRowFailure(t *testing.T) {
	db := newStore(t)
	ctx := context.Background()

	good := sampleAgent("agent-001")
	bad := sampleAgent("agent-002")
	bad.Status = "NOT_A_STATUS" // violates schema CHECK constraint

	if err := db.UpsertAgents(ctx, []domain.Agent{good, bad}); err == nil {
		t.Fatal("UpsertAgents: want error from invalid status, got nil")
	}

	if _, found, err := db.GetAgent(ctx, "agent-001"); err != nil {
		t.Fatalf("GetAgent: %v", err)
	} else if found {
		t.Error("agent-001 committed despite mid-batch rollback")
	}
	if _, found, err := db.GetAgent(ctx, "agent-002"); err != nil {
		t.Fatalf("GetAgent: %v", err)
	} else if found {
		t.Error("agent-002 committed even though its row failed")
	}
}

// TestAppendObservationsRollsBackOnRowFailure exercises the same rollback path
// for the observations batch: an unknown agent_id violates the FK, and the
// prior rows in the batch must not survive.
func TestAppendObservationsRollsBackOnRowFailure(t *testing.T) {
	db := newStore(t)
	ctx := context.Background()
	if err := db.UpsertAgent(ctx, sampleAgent("agent-001")); err != nil {
		t.Fatalf("UpsertAgent: %v", err)
	}

	at := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	good := domain.SignalObservation{
		AgentID: "agent-001", SignalID: "certtype",
		ObservedAt: at, Value: json.RawMessage(`{"type":"DV"}`),
	}
	bad := domain.SignalObservation{
		AgentID: "agent-unknown", SignalID: "certtype", // FK violation
		ObservedAt: at.Add(1 * time.Second), Value: json.RawMessage(`{"type":"DV"}`),
	}

	if err := db.AppendObservations(ctx, []domain.SignalObservation{good, bad}); err == nil {
		t.Fatal("AppendObservations: want error from FK violation, got nil")
	}

	obs, err := db.LatestObservation(ctx, "agent-001", "certtype")
	if err != nil {
		t.Fatalf("LatestObservation: %v", err)
	}
	if obs != nil {
		t.Errorf("agent-001/certtype observation committed despite mid-batch rollback: %+v", obs)
	}
}

// TestBatchMethodsEmptyBatchIsNoOp guards the boundary: an empty slice is a
// harmless success (no tx opened, no state changed).
func TestBatchMethodsEmptyBatchIsNoOp(t *testing.T) {
	db := newStore(t)
	ctx := context.Background()
	if err := db.UpsertAgents(ctx, nil); err != nil {
		t.Errorf("UpsertAgents(nil): %v", err)
	}
	if err := db.AppendObservations(ctx, nil); err != nil {
		t.Errorf("AppendObservations(nil): %v", err)
	}
	if err := db.UpsertAgents(ctx, []domain.Agent{}); err != nil {
		t.Errorf("UpsertAgents(empty): %v", err)
	}
	if err := db.AppendObservations(ctx, []domain.SignalObservation{}); err != nil {
		t.Errorf("AppendObservations(empty): %v", err)
	}
}
