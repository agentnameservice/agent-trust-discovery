package signals_test

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/agentnameservice/agent-trust-discovery/internal/domain"
	"github.com/agentnameservice/agent-trust-discovery/internal/scoring/signals"
)

func TestVersionStabilityEvaluate(t *testing.T) {
	s := signals.VersionStability{}
	cases := []struct {
		changes int
		wantRaw int
		wantRsk []string
	}{
		{0, 100, nil},
		{1, 50, nil},
		{2, 33, nil},
		{3, 25, nil},
		{4, 20, []string{signals.RiskVersionChurnHigh}},
		{5, 17, []string{signals.RiskVersionChurnHigh}},
	}
	for _, tc := range cases {
		res, err := s.Evaluate(context.Background(), domain.Agent{}, obsOf(fmt.Sprintf(`{"versionChanges30d":%d}`, tc.changes)))
		if err != nil {
			t.Fatalf("changes=%d: %v", tc.changes, err)
		}
		if res.Raw != tc.wantRaw {
			t.Errorf("changes=%d: raw=%d, want %d", tc.changes, res.Raw, tc.wantRaw)
		}
		if !sameStrings(res.RiskCodes, tc.wantRsk) {
			t.Errorf("changes=%d: risks=%v, want %v", tc.changes, res.RiskCodes, tc.wantRsk)
		}
	}
}

func TestVersionStabilityNilAndMalformed(t *testing.T) {
	res, err := signals.VersionStability{}.Evaluate(context.Background(), domain.Agent{}, nil)
	if err != nil || res.Raw != 0 {
		t.Errorf("nil obs: res=%+v err=%v", res, err)
	}
	if _, err := (signals.VersionStability{}).Evaluate(context.Background(), domain.Agent{}, obsOf(`nope`)); err == nil {
		t.Error("malformed value: want error")
	}
	// Defensive clamp: a stored negative (Validate would reject at import) scores
	// as zero changes → 100.
	res, err = (signals.VersionStability{}).Evaluate(context.Background(), domain.Agent{}, obsOf(`{"versionChanges30d":-1}`))
	if err != nil || res.Raw != 100 {
		t.Errorf("negative clamp: raw=%d err=%v, want 100", res.Raw, err)
	}
}

func TestVersionStabilityValidate(t *testing.T) {
	s := signals.VersionStability{}
	if err := s.Validate(json.RawMessage(`{"versionChanges30d":2}`)); err != nil {
		t.Errorf("Validate valid: %v", err)
	}
	invalid := []string{`{"versionChanges30d":-1}`, `not-json`}
	for _, v := range invalid {
		if err := s.Validate(json.RawMessage(v)); err == nil {
			t.Errorf("Validate(%s): want error", v)
		}
	}
}
