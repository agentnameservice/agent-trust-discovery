// Package registry is the concrete, in-memory implementation of
// port.SignalRegistry. It lives outside internal/port (which holds only the
// interface) so the engine and import service can depend on the abstraction
// while wiring registers the built-in signals here (design §4.1, §4.3).
package registry

import (
	"errors"
	"fmt"

	"github.com/agentnameservice/agent-trust-discovery/internal/domain"
	"github.com/agentnameservice/agent-trust-discovery/internal/port"
)

// Registry holds signals keyed by ID and preserves registration order so All()
// is deterministic — the engine relies on a stable order for risk-code
// concatenation (design §4.7).
type Registry struct {
	signals map[domain.SignalID]port.Signal
	order   []domain.SignalID
}

var _ port.SignalRegistry = (*Registry)(nil)

// New returns an empty registry.
func New() *Registry {
	return &Registry{signals: make(map[domain.SignalID]port.Signal)}
}

// Register adds a signal. It rejects an empty ID and a duplicate ID so wiring
// mistakes fail loudly at startup rather than silently shadowing a signal.
func (r *Registry) Register(s port.Signal) error {
	id := s.ID()
	if id == "" {
		return errors.New("registry: signal has an empty ID")
	}
	if _, exists := r.signals[id]; exists {
		return fmt.Errorf("registry: signal %q already registered", id)
	}
	r.signals[id] = s
	r.order = append(r.order, id)
	return nil
}

// Get returns the signal and true, or nil and false when not registered.
func (r *Registry) Get(id domain.SignalID) (port.Signal, bool) {
	s, ok := r.signals[id]
	return s, ok
}

// All returns the registered signals in registration order.
func (r *Registry) All() []port.Signal {
	out := make([]port.Signal, len(r.order))
	for i, id := range r.order {
		out[i] = r.signals[id]
	}
	return out
}
