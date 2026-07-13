package signals_test

import (
	"testing"

	"github.com/agentnameservice/agent-trust-discovery/internal/domain"
	"github.com/agentnameservice/agent-trust-discovery/internal/port"
	"github.com/agentnameservice/agent-trust-discovery/internal/scoring/signals"
)

// DriftSignalIDs is the canonical drift-signal registry (§4.4 Family B). Every
// entry in it must correspond to a DriftSignal registered by BuiltIns; if the
// list gains a new ID without a matching BuiltIns entry, scoring silently
// drops the observations for it. This trap catches that at build time.
func TestDriftSignalIDs_AllRegisteredByBuiltIns(t *testing.T) {
	registered := map[domain.SignalID]bool{}
	for _, s := range signals.BuiltIns(nil) {
		if _, ok := s.(signals.DriftSignal); ok {
			registered[s.ID()] = true
		}
	}
	for _, id := range signals.DriftSignalIDs() {
		if !registered[id] {
			t.Errorf("DriftSignalIDs contains %q but BuiltIns() does not return a matching DriftSignal", id)
		}
	}
	// And the converse: every DriftSignal in BuiltIns must be in the list.
	// This catches an implementation that got wired into BuiltIns but never
	// added to the canonical list downstream producers key off.
	inList := map[domain.SignalID]bool{}
	for _, id := range signals.DriftSignalIDs() {
		inList[id] = true
	}
	for _, s := range signals.BuiltIns(nil) {
		if _, ok := s.(signals.DriftSignal); ok && !inList[s.ID()] {
			t.Errorf("BuiltIns() returns DriftSignal %q but DriftSignalIDs does not list it", s.ID())
		}
	}
}

// _ = port.Signal keeps the port import live so future changes here that need
// the interface don't have to re-add it.
var _ port.Signal = signals.CertFingerprintServer()
