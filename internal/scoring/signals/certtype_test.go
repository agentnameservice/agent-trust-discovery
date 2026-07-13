package signals_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/agentnameservice/agent-trust-discovery/internal/domain"
	"github.com/agentnameservice/agent-trust-discovery/internal/scoring/signals"
)

func TestCertTypeEvaluate(t *testing.T) {
	s := signals.CertType{}
	cases := []struct {
		name    string
		value   string
		wantRaw int
		wantRsk []string
	}{
		{"EV", `{"type":"EV"}`, 100, nil},
		{"OV", `{"type":"OV"}`, 70, nil},
		{"DV", `{"type":"DV"}`, 40, []string{signals.RiskCertDVOnly}},
		{"none", `{"type":"none"}`, 0, nil},
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
			if res.Attestation != domain.AttestationUnattested {
				t.Errorf("attestation = %v, want unattested", res.Attestation)
			}
		})
	}
}

func TestCertTypeNilObservationMissing(t *testing.T) {
	res, err := signals.CertType{}.Evaluate(context.Background(), domain.Agent{}, nil)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if res.Raw != 0 || !sameStrings(res.RiskCodes, []string{signals.RiskCertMissing}) {
		t.Errorf("nil obs: raw=%d risks=%v, want 0 + IDENTITY_CERT_MISSING", res.Raw, res.RiskCodes)
	}
}

func TestCertTypeEvaluateMalformed(t *testing.T) {
	if _, err := (signals.CertType{}).Evaluate(context.Background(), domain.Agent{}, obsOf(`not-json`)); err == nil {
		t.Error("malformed value: want error")
	}
}

func TestCertTypeValidate(t *testing.T) {
	s := signals.CertType{}
	valid := []string{`{"type":"DV"}`, `{"type":"OV"}`, `{"type":"EV"}`, `{"type":"none"}`}
	for _, v := range valid {
		if err := s.Validate(json.RawMessage(v)); err != nil {
			t.Errorf("Validate(%s): %v", v, err)
		}
	}
	invalid := []string{`{"type":"XX"}`, `{}`, `not-json`}
	for _, v := range invalid {
		if err := s.Validate(json.RawMessage(v)); err == nil {
			t.Errorf("Validate(%s): want error", v)
		}
	}
}
