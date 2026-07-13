package search

import (
	"context"
	"fmt"

	"github.com/agentnameservice/agent-trust-discovery/internal/domain"
	"github.com/agentnameservice/agent-trust-discovery/internal/port"
)

// defaultProfileName is selected when the caller omits ?profile.
const defaultProfileName = "default"

// Evaluator is the sole contract Service needs from the scoring engine: score
// one agent under one profile. Keeping it here (an interface at the consumer)
// avoids leaking the concrete engine type into Service and lets Detail be
// unit-tested with a fake scorer. The engine's *Engine.Evaluate method
// satisfies this signature (accept interfaces, return structs).
type Evaluator interface {
	Evaluate(ctx context.Context, agent domain.Agent, profile domain.ScoringProfile) (domain.TrustEvaluation, error)
}

// Service answers the read API. Search is a thin delegation to the Index;
// Detail combines the store with the scoring engine under a chosen profile.
type Service struct {
	index    port.Index
	store    port.AgentStore
	engine   Evaluator
	profiles map[string]domain.ScoringProfile
}

// New constructs a Service. profiles is keyed by profile name (the map the
// engine's LoadProfiles produces); it must contain "default".
func New(index port.Index, store port.AgentStore, eng Evaluator, profiles map[string]domain.ScoringProfile) *Service {
	return &Service{index: index, store: store, engine: eng, profiles: profiles}
}

// Search runs the query against the index. A store/index failure is an
// unexpected error (→ 500).
func (s *Service) Search(ctx context.Context, q port.SearchQuery) (port.SearchPage, error) {
	page, err := s.index.Search(ctx, q)
	if err != nil {
		return port.SearchPage{}, fmt.Errorf("search: index query: %w", err)
	}
	return page, nil
}

// Detail returns the agent and its Trust Evaluation under the named profile.
// An empty profileName selects the default. The profile is resolved before the
// lookup so an unknown profile fails fast regardless of whether the agent
// exists. Returns a typed 404 when the agent is absent and a typed 422 when
// the profile isn't registered (semantic-value error per design §5.2); a
// store/engine failure is an unexpected error (→ 500).
func (s *Service) Detail(ctx context.Context, id domain.AgentID, profileName string) (domain.Agent, domain.TrustEvaluation, error) {
	if profileName == "" {
		profileName = defaultProfileName
	}
	profile, ok := s.profiles[profileName]
	if !ok {
		return domain.Agent{}, domain.TrustEvaluation{}, errUnknownProfile(profileName)
	}

	agent, found, err := s.store.GetAgent(ctx, id)
	if err != nil {
		return domain.Agent{}, domain.TrustEvaluation{}, fmt.Errorf("search: get agent %q: %w", id, err)
	}
	if !found {
		return domain.Agent{}, domain.TrustEvaluation{}, errAgentNotFound(id)
	}

	eval, err := s.engine.Evaluate(ctx, agent, profile)
	if err != nil {
		return domain.Agent{}, domain.TrustEvaluation{}, fmt.Errorf("search: evaluate agent %q: %w", id, err)
	}
	return agent, eval, nil
}
