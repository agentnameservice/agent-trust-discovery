package hydrator_test

import (
	"os"
	"testing"

	"github.com/agentnameservice/agent-trust-discovery/internal/hydrator"
)

// TestExampleCustomFixtureLoads guards the worked custom-signal example shipped
// with docs/extending-signals.md (design §8.3): it must stay a valid
// observation fixture so the documentation does not drift from the loader.
func TestExampleCustomFixtureLoads(t *testing.T) {
	b, err := os.ReadFile("../../fixtures/examples/example-custom.yaml")
	if err != nil {
		t.Fatalf("read example fixture: %v", err)
	}
	f, err := hydrator.ParseObservationFile(b)
	if err != nil {
		t.Fatalf("example fixture does not parse: %v", err)
	}
	if f.AgentID == "" || len(f.Observations) == 0 {
		t.Errorf("example fixture is empty: %+v", f)
	}
	if f.Observations[0].SignalID != "uptime" {
		t.Errorf("example fixture signalId = %q, want uptime (matches the doc)", f.Observations[0].SignalID)
	}
}
