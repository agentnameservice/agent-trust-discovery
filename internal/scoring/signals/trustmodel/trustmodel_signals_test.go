package trustmodel

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/agentnameservice/agent-trust-discovery/internal/domain"
)

func obs(v string) *domain.SignalObservation {
	return &domain.SignalObservation{Value: json.RawMessage(v)}
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

func behavior() ScoreSignal {
	return New("trustmodel.behavior.score", domain.DimensionBehavior, DefaultLowThreshold)
}
func safety() ScoreSignal {
	return New("trustmodel.safety.score", domain.DimensionSafety, DefaultLowThreshold)
}
func solvency() ScoreSignal {
	return New("trustmodel.solvency.score", domain.DimensionSolvency, DefaultLowThreshold)
}

func TestSignalsMetadata(t *testing.T) {
	want := map[domain.SignalID]domain.Dimension{
		"trustmodel.behavior.score": domain.DimensionBehavior,
		"trustmodel.safety.score":   domain.DimensionSafety,
		"trustmodel.solvency.score": domain.DimensionSolvency,
	}
	sigs := Signals()
	if len(sigs) != len(want) {
		t.Fatalf("want %d signals, got %d", len(want), len(sigs))
	}
	for _, s := range sigs {
		dim, ok := want[s.ID()]
		if !ok {
			t.Errorf("unexpected signal id %q", s.ID())
			continue
		}
		if s.Dimension() != dim {
			t.Errorf("%s: dimension = %q, want %q", s.ID(), s.Dimension(), dim)
		}
		// vendor.dimension.name — the dimension segment must match Dimension().
		if seg := strings.Split(string(s.ID()), ".")[1]; seg != string(dim) {
			t.Errorf("%s: id dimension segment %q != Dimension() %q", s.ID(), seg, dim)
		}
		if s.Derived() {
			t.Errorf("%s: Derived() = true, want false", s.ID())
		}
	}
}

func TestEvaluateScoreAndBackstop(t *testing.T) {
	cases := []struct {
		name     string
		sig      ScoreSignal
		obs      *domain.SignalObservation
		wantRaw  int
		wantCode string // a code expected present, or "" for none
	}{
		{"behavior nil -> unknown", behavior(), nil, 0, "BEHAVIOR_TRUSTMODEL_UNKNOWN"},
		{"behavior high -> clean", behavior(), obs(`{"score":86}`), 86, ""},
		{"behavior boundary (==threshold) clean", behavior(), obs(`{"score":70}`), 70, ""},
		{"behavior low -> backstop", behavior(), obs(`{"score":40}`), 40, "BEHAVIOR_TRUSTMODEL_SCORE_LOW"},
		{"safety low -> backstop", safety(), obs(`{"score":10}`), 10, "SAFETY_TRUSTMODEL_SCORE_LOW"},
		// solvency now rides the SAME generic container (DV/OV/EV->score moved to the hydrator).
		{"solvency high -> clean", solvency(), obs(`{"score":100}`), 100, ""},
		{"solvency low -> backstop", solvency(), obs(`{"score":0}`), 0, "SOLVENCY_TRUSTMODEL_SCORE_LOW"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, err := c.sig.Evaluate(nil, domain.Agent{}, c.obs)
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if r.Raw != c.wantRaw {
				t.Errorf("raw = %d, want %d", r.Raw, c.wantRaw)
			}
			if c.wantCode == "" {
				if len(r.RiskCodes) != 0 {
					t.Errorf("expected no risk codes, got %v", r.RiskCodes)
				}
			} else if !contains(r.RiskCodes, c.wantCode) {
				t.Errorf("missing %s in %v", c.wantCode, r.RiskCodes)
			}
		})
	}
}

func TestProviderRiskCodesPassThroughAndPrefixFilter(t *testing.T) {
	// Matching-prefix provider code is kept; a wrong-dimension code is dropped;
	// the backstop is appended below threshold; explanation is surfaced.
	r, err := safety().Evaluate(nil, domain.Agent{},
		obs(`{"score":30,"riskCodes":["SAFETY_PROMPT_INJECTION","BEHAVIOR_STALE"],"explanation":"jailbreak on 2/40 probes"}`))
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !contains(r.RiskCodes, "SAFETY_PROMPT_INJECTION") {
		t.Errorf("provider code not passed through: %v", r.RiskCodes)
	}
	if contains(r.RiskCodes, "BEHAVIOR_STALE") {
		t.Errorf("wrong-dimension code not dropped: %v", r.RiskCodes)
	}
	if !contains(r.RiskCodes, "SAFETY_TRUSTMODEL_SCORE_LOW") {
		t.Errorf("backstop missing: %v", r.RiskCodes)
	}
	if r.Explanation != "jailbreak on 2/40 probes" {
		t.Errorf("explanation not surfaced, got %q", r.Explanation)
	}
}

func TestValidate(t *testing.T) {
	s := behavior()
	if err := s.Validate(json.RawMessage(`{"score":50}`)); err != nil {
		t.Errorf("valid score rejected: %v", err)
	}
	if err := s.Validate(json.RawMessage(`{"score":101}`)); err == nil {
		t.Error("expected out-of-range error")
	}
	if err := s.Validate(json.RawMessage(`{"score":50,"riskCodes":["bad-code"]}`)); err == nil {
		t.Error("expected malformed risk-code error")
	}
	codes := make([]string, maxRiskCodes+1)
	for i := range codes {
		codes[i] = "BEHAVIOR_X"
	}
	body, _ := json.Marshal(scoreValue{Score: 50, RiskCodes: codes})
	if err := s.Validate(body); err == nil {
		t.Error("expected count-cap error")
	}
}

func TestThresholdConfigurable(t *testing.T) {
	// The "magic 70" is now a per-signal config value.
	strict := New("trustmodel.safety.score", domain.DimensionSafety, 90)
	r, _ := strict.Evaluate(nil, domain.Agent{}, obs(`{"score":85}`))
	if !contains(r.RiskCodes, "SAFETY_TRUSTMODEL_SCORE_LOW") {
		t.Errorf("threshold 90: score 85 should trip backstop, got %v", r.RiskCodes)
	}
}
