package signals_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/agentnameservice/agent-trust-discovery/internal/domain"
	"github.com/agentnameservice/agent-trust-discovery/internal/scoring/signals"
)

func TestDNSSecurityEvaluate(t *testing.T) {
	s := signals.DNSSECurity{}
	cases := []struct {
		name    string
		value   string
		wantRaw int
		wantRsk []string
	}{
		{"both", `{"dnssec":true,"caa":true}`, 100, nil},
		{"dnssec only", `{"dnssec":true,"caa":false}`, 50, nil},
		{"caa only", `{"dnssec":false,"caa":true}`, 50, []string{signals.RiskDNSSECBroken}},
		{"neither", `{"dnssec":false,"caa":false}`, 0, []string{signals.RiskDNSSECBroken}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := s.Evaluate(context.Background(), domain.Agent{}, obsOf(tc.value))
			if err != nil {
				t.Fatalf("Evaluate: %v", err)
			}
			if res.Raw != tc.wantRaw {
				t.Errorf("raw = %d, want %d", res.Raw, tc.wantRaw)
			}
			if !sameStrings(res.RiskCodes, tc.wantRsk) {
				t.Errorf("risks = %v, want %v", res.RiskCodes, tc.wantRsk)
			}
		})
	}
}

func TestDNSSecurityNilAndMalformed(t *testing.T) {
	res, err := signals.DNSSECurity{}.Evaluate(context.Background(), domain.Agent{}, nil)
	if err != nil || res.Raw != 0 || len(res.RiskCodes) != 0 {
		t.Errorf("nil obs: res=%+v err=%v", res, err)
	}
	if _, err := (signals.DNSSECurity{}).Evaluate(context.Background(), domain.Agent{}, obsOf(`nope`)); err == nil {
		t.Error("malformed value: want error")
	}
}

func TestDNSSecurityValidate(t *testing.T) {
	s := signals.DNSSECurity{}
	if err := s.Validate(json.RawMessage(`{"dnssec":true,"caa":false}`)); err != nil {
		t.Errorf("Validate valid: %v", err)
	}
	invalid := []string{`{"dnssec":"yes"}`, `not-json`}
	for _, v := range invalid {
		if err := s.Validate(json.RawMessage(v)); err == nil {
			t.Errorf("Validate(%s): want error", v)
		}
	}
}
