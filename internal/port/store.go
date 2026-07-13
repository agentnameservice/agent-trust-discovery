package port

import (
	"context"

	"github.com/agentnameservice/agent-trust-discovery/internal/domain"
)

// AgentStore is the persistence contract for agents and their signal
// observations (design §7). The sqlitestore adapter implements it (along with
// Index). UpsertAgent is keyed on agent ID; AppendObservation is append-only and
// LatestObservation returns the most recent row per (agentID, signalID), which
// is what the scoring engine reads.
type AgentStore interface {
	// UpsertAgent inserts or replaces the agent keyed on its ID, refreshing the
	// search index (design §5.2 idempotency).
	UpsertAgent(ctx context.Context, a domain.Agent) error

	// UpsertAgents runs UpsertAgent for every entry atomically: either the whole
	// batch commits or none of it does. Import services that accept multi-row
	// bodies must call this so a mid-batch storage failure never leaves earlier
	// rows committed while the caller gets a 5xx.
	UpsertAgents(ctx context.Context, agents []domain.Agent) error

	// GetAgent returns the agent and true, or the zero agent and false when no
	// row exists.
	GetAgent(ctx context.Context, id domain.AgentID) (domain.Agent, bool, error)

	// AppendObservation records a new observation row. Idempotent on the
	// (agent_id, signal_id, observed_at) triple: re-appending the same
	// observation is a no-op, so retries and prober cadence loops do not
	// grow storage unboundedly. History up to the retention window is
	// preserved; the scoring engine reads only the newest row per pair.
	AppendObservation(ctx context.Context, obs domain.SignalObservation) error

	// AppendObservations runs AppendObservation for every entry atomically —
	// same all-or-nothing semantics as UpsertAgents. Preserves the (agent,
	// signal, observedAt) idempotency contract.
	AppendObservations(ctx context.Context, obs []domain.SignalObservation) error

	// LatestObservation returns the most recent observation for the pair, or nil
	// when none has been recorded (a valid input to Signal.Evaluate).
	LatestObservation(ctx context.Context, agentID domain.AgentID, signalID domain.SignalID) (*domain.SignalObservation, error)
}
