package domain_test

import (
	"testing"

	"github.com/agentnameservice/agent-trust-discovery/internal/domain"
)

func TestAllDimensionsOrderAndValues(t *testing.T) {
	got := domain.AllDimensions()
	want := []domain.Dimension{
		domain.DimensionIntegrity,
		domain.DimensionIdentity,
		domain.DimensionSolvency,
		domain.DimensionBehavior,
		domain.DimensionSafety,
	}
	if len(got) != len(want) {
		t.Fatalf("AllDimensions() len = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("AllDimensions()[%d] = %q, want %q", i, got[i], want[i])
		}
	}

	// Pin the spec/wire string values.
	pins := map[domain.Dimension]string{
		domain.DimensionIntegrity: "integrity",
		domain.DimensionIdentity:  "identity",
		domain.DimensionSolvency:  "solvency",
		domain.DimensionBehavior:  "behavior",
		domain.DimensionSafety:    "safety",
	}
	for d, want := range pins {
		if string(d) != want {
			t.Errorf("dimension const = %q, want %q", string(d), want)
		}
	}
}

// AllDimensions must hand back a fresh slice so callers cannot mutate shared
// state (immutability convention).
func TestAllDimensionsReturnsFreshSlice(t *testing.T) {
	first := domain.AllDimensions()
	first[0] = "mutated"
	if domain.AllDimensions()[0] != domain.DimensionIntegrity {
		t.Fatal("AllDimensions() returned a shared, mutable slice")
	}
}

func TestDimensionValid(t *testing.T) {
	for _, d := range domain.AllDimensions() {
		if !d.Valid() {
			t.Errorf("Dimension(%q).Valid() = false, want true", d)
		}
	}
	for _, d := range []domain.Dimension{"", "Integrity", "unknown", "trust"} {
		if d.Valid() {
			t.Errorf("Dimension(%q).Valid() = true, want false", d)
		}
	}
}
