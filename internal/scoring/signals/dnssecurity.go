package signals

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/agentnameservice/agent-trust-discovery/internal/domain"
	"github.com/agentnameservice/agent-trust-discovery/internal/port"
)

// DNSSECurity scores DNSSEC + CAA presence (design §4.4 Family A): both→100,
// exactly one→50, neither→0.
type DNSSECurity struct{}

func (DNSSECurity) ID() domain.SignalID         { return "dnssecurity" }
func (DNSSECurity) Dimension() domain.Dimension { return domain.DimensionIntegrity }
func (DNSSECurity) Derived() bool               { return false }

type dnssecValue struct {
	DNSSEC bool `json:"dnssec"`
	CAA    bool `json:"caa"`
}

func decodeDNSSEC(value json.RawMessage) (dnssecValue, error) {
	var v dnssecValue
	if err := json.Unmarshal(value, &v); err != nil {
		return dnssecValue{}, fmt.Errorf("dnssecurity: invalid value: %w", err)
	}
	return v, nil
}

// Validate accepts a {dnssec: bool, caa: bool} object.
func (DNSSECurity) Validate(value json.RawMessage) error {
	_, err := decodeDNSSEC(value)
	return err
}

// Evaluate scores DNSSEC+CAA. A missing dnssec bit yields INTEGRITY_DNSSEC_BROKEN
// (design §4.7). A nil observation scores 0 with no risk.
func (DNSSECurity) Evaluate(_ context.Context, _ domain.Agent, obs *domain.SignalObservation) (port.SignalResult, error) {
	if obs == nil {
		return port.SignalResult{Raw: 0, Explanation: "no DNS security observed", Attestation: domain.AttestationUnattested}, nil
	}
	v, err := decodeDNSSEC(obs.Value)
	if err != nil {
		return port.SignalResult{}, err
	}

	var (
		raw         int
		explanation string
	)
	switch {
	case v.DNSSEC && v.CAA:
		raw, explanation = 100, "dnssec + caa present"
	case v.DNSSEC:
		raw, explanation = 50, "dnssec present; caa missing"
	case v.CAA:
		raw, explanation = 50, "caa present; dnssec missing"
	default:
		raw, explanation = 0, "no dnssec or caa"
	}

	var risks []string
	if !v.DNSSEC {
		risks = []string{RiskDNSSECBroken}
	}
	return port.SignalResult{
		Raw:         raw,
		Explanation: explanation,
		Attestation: domain.AttestationUnattested,
		RiskCodes:   risks,
	}, nil
}
