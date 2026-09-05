package trustmodel_test

import (
	"testing"

	"github.com/agentnameservice/agent-trust-discovery/internal/domain"
	"github.com/agentnameservice/agent-trust-discovery/internal/scoring/signals/trustmodel"
)

// The three signals fill ANS's empty provider-fed dimensions with the shared
// scorecontainer. This asserts the registration wiring — id, dimension, and
// (critically) that solvency scores the org while behavior/safety score the
// agent (issue #9 / the #10 review). The container's scoring, validation, and
// absence behavior are covered by scorecontainer's own tests, not re-tested here.
func TestSignalsRegistration(t *testing.T) {
	type want struct {
		dim     domain.Dimension
		subject string
	}
	expect := map[domain.SignalID]want{
		"trustmodel.behavior.score": {domain.DimensionBehavior, "agent"},
		"trustmodel.safety.score":   {domain.DimensionSafety, "agent"},
		"trustmodel.solvency.score": {domain.DimensionSolvency, "org"},
	}

	sigs := trustmodel.Signals()
	if len(sigs) != len(expect) {
		t.Fatalf("Signals() returned %d signals, want %d", len(sigs), len(expect))
	}
	for _, s := range sigs {
		w, ok := expect[s.ID()]
		if !ok {
			t.Errorf("unexpected signal %q", s.ID())
			continue
		}
		if s.Dimension() != w.dim {
			t.Errorf("%s: dimension = %q, want %q", s.ID(), s.Dimension(), w.dim)
		}
		sub, ok := s.(interface{ Subject() string })
		if !ok {
			t.Errorf("%s: does not expose Subject()", s.ID())
			continue
		}
		if sub.Subject() != w.subject {
			t.Errorf("%s: subject = %q, want %q", s.ID(), sub.Subject(), w.subject)
		}
	}
}
