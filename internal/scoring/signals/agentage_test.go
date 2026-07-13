package signals_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/agentnameservice/agent-trust-discovery/internal/domain"
	"github.com/agentnameservice/agent-trust-discovery/internal/scoring/signals"
)

func TestAgentAgeEvaluate(t *testing.T) {
	now := time.Date(2026, 6, 4, 0, 0, 0, 0, time.UTC)
	s := signals.NewAgentAge(func() time.Time { return now })

	cases := []struct {
		name      string
		firstSeen time.Time
		wantRaw   int
		wantNew   bool
	}{
		{"163 days", now.AddDate(0, 0, -163), 91, false},
		{"5 days", now.AddDate(0, 0, -5), 3, true},
		{"180 days", now.AddDate(0, 0, -180), 100, false},
		{"200 days caps at 100", now.AddDate(0, 0, -200), 100, false},
		{"future date floors at 0", now.AddDate(0, 0, 10), 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := s.Evaluate(context.Background(), domain.Agent{FirstSeen: tc.firstSeen}, nil)
			if err != nil {
				t.Fatalf("Evaluate: %v", err)
			}
			if res.Raw != tc.wantRaw {
				t.Errorf("raw = %d, want %d", res.Raw, tc.wantRaw)
			}
			hasNew := sameStrings(res.RiskCodes, []string{signals.RiskAgentNew})
			if hasNew != tc.wantNew {
				t.Errorf("RiskAgentNew present = %v, want %v (risks=%v)", hasNew, tc.wantNew, res.RiskCodes)
			}
		})
	}
}

func TestAgentAgeIsDerivedAndRejectsObservations(t *testing.T) {
	s := signals.NewAgentAge(time.Now)
	if !s.Derived() {
		t.Error("Derived() = false, want true")
	}
	if err := s.Validate(json.RawMessage(`{}`)); err == nil {
		t.Error("Validate on derived signal: want error")
	}
}
