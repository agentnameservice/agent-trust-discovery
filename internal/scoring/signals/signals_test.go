package signals_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/agentnameservice/agent-trust-discovery/internal/domain"
	"github.com/agentnameservice/agent-trust-discovery/internal/scoring/signals"
)

// validFP is a well-formed SHA256 fingerprint used across the drift tests.
var validFP = "SHA256:" + strings.Repeat("a", 64)

func obsOf(v string) *domain.SignalObservation {
	return &domain.SignalObservation{Value: json.RawMessage(v)}
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestBuiltInsShape(t *testing.T) {
	got := signals.BuiltIns(nil) // nil clock → time.Now for agentage
	type want struct {
		id      domain.SignalID
		dim     domain.Dimension
		derived bool
	}
	wants := []want{
		{"certtype", domain.DimensionIdentity, false},
		{"dnssecurity", domain.DimensionIntegrity, false},
		{"agentage", domain.DimensionIntegrity, true},
		{"versionstability", domain.DimensionIntegrity, false},
		{"certfingerprint.server", domain.DimensionIntegrity, false},
		{"certfingerprint.identity", domain.DimensionIntegrity, false},
		{"dnsrecord.ans", domain.DimensionIntegrity, false},
		{"dnsrecord.ans-badge", domain.DimensionIntegrity, false},
	}
	if len(got) != len(wants) {
		t.Fatalf("BuiltIns count = %d, want %d", len(got), len(wants))
	}
	for i, w := range wants {
		s := got[i]
		if s.ID() != w.id || s.Dimension() != w.dim || s.Derived() != w.derived {
			t.Errorf("[%d] id=%s dim=%s derived=%v, want %s/%s/%v",
				i, s.ID(), s.Dimension(), s.Derived(), w.id, w.dim, w.derived)
		}
	}
}
