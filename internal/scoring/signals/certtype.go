package signals

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/agentnameservice/agent-trust-discovery/internal/domain"
	"github.com/agentnameservice/agent-trust-discovery/internal/port"
)

// CertType scores the certificate validation tier (design §4.4 Family A):
// DV→40, OV→70, EV→100, none→0.
type CertType struct{}

func (CertType) ID() domain.SignalID         { return "certtype" }
func (CertType) Dimension() domain.Dimension { return domain.DimensionIdentity }
func (CertType) Derived() bool               { return false }

type certTypeValue struct {
	Type string `json:"type"`
}

func decodeCertType(value json.RawMessage) (certTypeValue, error) {
	var v certTypeValue
	if err := json.Unmarshal(value, &v); err != nil {
		return certTypeValue{}, fmt.Errorf("certtype: invalid value: %w", err)
	}
	return v, nil
}

// Validate enforces type ∈ {DV, OV, EV, none}.
func (CertType) Validate(value json.RawMessage) error {
	v, err := decodeCertType(value)
	if err != nil {
		return err
	}
	switch v.Type {
	case "DV", "OV", "EV", "none":
		return nil
	default:
		return fmt.Errorf("certtype: type must be one of DV|OV|EV|none, got %q", v.Type)
	}
}

// Evaluate scores the cert tier. A nil observation means no cert recorded:
// raw 0 plus the IDENTITY_CERT_MISSING risk (design §4.7).
func (CertType) Evaluate(_ context.Context, _ domain.Agent, obs *domain.SignalObservation) (port.SignalResult, error) {
	if obs == nil {
		return port.SignalResult{
			Raw:         0,
			Explanation: "no certificate observed",
			Attestation: domain.AttestationUnattested,
			RiskCodes:   []string{RiskCertMissing},
		}, nil
	}
	v, err := decodeCertType(obs.Value)
	if err != nil {
		return port.SignalResult{}, err
	}

	var (
		raw   int
		risks []string
		label string
	)
	switch v.Type {
	case "EV":
		raw, label = 100, "EV certificate"
	case "OV":
		raw, label = 70, "OV certificate"
	case "DV":
		raw, label, risks = 40, "DV certificate", []string{RiskCertDVOnly}
	default: // "none" or any unrecognized value
		raw, label = 0, "no certificate"
	}
	return port.SignalResult{
		Raw:         raw,
		Explanation: fmt.Sprintf("%s; raw %d", label, raw),
		Attestation: domain.AttestationUnattested,
		RiskCodes:   risks,
	}, nil
}
