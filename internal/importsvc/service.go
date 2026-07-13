package importsvc

import (
	"context"
	"fmt"

	"github.com/agentnameservice/agent-trust-discovery/internal/domain"
	"github.com/agentnameservice/agent-trust-discovery/internal/port"
)

// Service applies import batches to the store. It depends only on the storage
// and signal-registry ports, so it is independent of HTTP and trivially
// testable against the real SQLite adapter.
type Service struct {
	store    port.AgentStore
	registry port.SignalRegistry
}

// New constructs a Service over the given store and signal registry.
func New(store port.AgentStore, reg port.SignalRegistry) *Service {
	return &Service{store: store, registry: reg}
}

// ImportAgents upserts every agent in the batch atomically, keyed on agentId
// (design §5.2 idempotency: re-importing replaces the record and refreshes
// lastUpdated / firstSeen). Field-shape validation happens at the DTO
// boundary, so agents arriving here are already well-formed; a storage
// failure surfaces as an unexpected error (→ HTTP 500).
//
// Atomicity has two layers: (a) a batch with any invalid row is rejected
// before this method is called and nothing is persisted, and (b) the store's
// atomic UpsertAgents commits the whole batch or none of it — a mid-batch
// storage failure never leaves earlier rows committed while the caller gets
// a 5xx.
func (s *Service) ImportAgents(ctx context.Context, agents []domain.Agent) error {
	if err := s.store.UpsertAgents(ctx, agents); err != nil {
		return fmt.Errorf("importsvc: upsert agents batch (n=%d): %w", len(agents), err)
	}
	return nil
}

// ImportObservations validates the whole batch against the §5.2.1 rules and,
// only if every row passes, appends them atomically (idempotent on the
// (agent, signal, observedAt) triple; the latest row per pair is what the
// engine scores). Validation is fail-fast and atomic: the first invalid row
// rejects the entire batch. Persistence is atomic too — the store commits
// the whole batch or rolls it back on any per-row failure.
func (s *Service) ImportObservations(ctx context.Context, observations []domain.SignalObservation) error {
	for _, o := range observations {
		if err := s.validateObservation(ctx, o); err != nil {
			return err
		}
	}
	if err := s.store.AppendObservations(ctx, observations); err != nil {
		return fmt.Errorf("importsvc: append observations batch (n=%d): %w", len(observations), err)
	}
	return nil
}

// validateObservation runs the §5.2.1 checks in table order. Typed *web.Error
// values map to 422; an unexpected store error is wrapped (→ 500).
func (s *Service) validateObservation(ctx context.Context, o domain.SignalObservation) error {
	_, found, err := s.store.GetAgent(ctx, o.AgentID)
	if err != nil {
		return fmt.Errorf("importsvc: lookup agent %q: %w", o.AgentID, err)
	}
	if !found {
		return errAgentNotFound(o.AgentID)
	}

	sig, ok := s.registry.Get(o.SignalID)
	if !ok {
		return errUnknownSignal(o.SignalID)
	}
	if sig.Derived() {
		return errDerivedSignal(o.SignalID)
	}
	if err := sig.Validate(o.Value); err != nil {
		return errInvalidSignalValue(o.AgentID, o.SignalID, err)
	}
	return nil
}
