package registry_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/agentnameservice/agent-trust-discovery/internal/domain"
	"github.com/agentnameservice/agent-trust-discovery/internal/port"
	"github.com/agentnameservice/agent-trust-discovery/internal/scoring/registry"
)

type fakeSignal struct{ id domain.SignalID }

func (f fakeSignal) ID() domain.SignalID          { return f.id }
func (fakeSignal) Dimension() domain.Dimension    { return domain.DimensionIntegrity }
func (fakeSignal) Derived() bool                  { return false }
func (fakeSignal) Validate(json.RawMessage) error { return nil }
func (fakeSignal) Evaluate(context.Context, domain.Agent, *domain.SignalObservation) (port.SignalResult, error) {
	return port.SignalResult{}, nil
}

func TestRegisterGetAllPreservesOrder(t *testing.T) {
	r := registry.New()
	if err := r.Register(fakeSignal{"a"}); err != nil {
		t.Fatalf("register a: %v", err)
	}
	if err := r.Register(fakeSignal{"b"}); err != nil {
		t.Fatalf("register b: %v", err)
	}

	if s, ok := r.Get("a"); !ok || s.ID() != "a" {
		t.Errorf("Get(a) = %v, %v", s, ok)
	}
	if _, ok := r.Get("missing"); ok {
		t.Error("Get(missing) ok = true, want false")
	}

	all := r.All()
	if len(all) != 2 || all[0].ID() != "a" || all[1].ID() != "b" {
		t.Errorf("All() order wrong: %v %v", all[0].ID(), all[1].ID())
	}
}

func TestRegisterRejectsEmptyAndDuplicate(t *testing.T) {
	r := registry.New()
	if err := r.Register(fakeSignal{""}); err == nil {
		t.Error("Register(empty id): want error")
	}
	if err := r.Register(fakeSignal{"x"}); err != nil {
		t.Fatalf("register x: %v", err)
	}
	if err := r.Register(fakeSignal{"x"}); err == nil {
		t.Error("Register(duplicate): want error")
	}
}
