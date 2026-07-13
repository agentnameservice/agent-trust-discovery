package signals

import (
	"context"
	"encoding/json"
	"fmt"
	"math"

	"github.com/agentnameservice/agent-trust-discovery/internal/domain"
	"github.com/agentnameservice/agent-trust-discovery/internal/port"
)

const versionChurnHighThreshold = 4

// VersionStability scores release churn (design §4.4 Family A):
// round(100 / (1 + versionChanges30d)) — a monotonic decay.
type VersionStability struct{}

func (VersionStability) ID() domain.SignalID         { return "versionstability" }
func (VersionStability) Dimension() domain.Dimension { return domain.DimensionIntegrity }
func (VersionStability) Derived() bool               { return false }

type versionValue struct {
	VersionChanges30d int `json:"versionChanges30d"`
}

func decodeVersion(value json.RawMessage) (versionValue, error) {
	var v versionValue
	if err := json.Unmarshal(value, &v); err != nil {
		return versionValue{}, fmt.Errorf("versionstability: invalid value: %w", err)
	}
	return v, nil
}

// Validate requires versionChanges30d ≥ 0.
func (VersionStability) Validate(value json.RawMessage) error {
	v, err := decodeVersion(value)
	if err != nil {
		return err
	}
	if v.VersionChanges30d < 0 {
		return fmt.Errorf("versionstability: versionChanges30d must be >= 0, got %d", v.VersionChanges30d)
	}
	return nil
}

// Evaluate scores stability. versionChanges30d ≥ 4 yields
// INTEGRITY_VERSION_CHURN_HIGH (design §4.7). A nil observation scores 0.
func (VersionStability) Evaluate(_ context.Context, _ domain.Agent, obs *domain.SignalObservation) (port.SignalResult, error) {
	if obs == nil {
		return port.SignalResult{Raw: 0, Explanation: "no version observation", Attestation: domain.AttestationUnattested}, nil
	}
	v, err := decodeVersion(obs.Value)
	if err != nil {
		return port.SignalResult{}, err
	}
	changes := v.VersionChanges30d
	if changes < 0 {
		changes = 0
	}
	raw := int(math.Round(100 / float64(1+changes)))

	var risks []string
	if changes >= versionChurnHighThreshold {
		risks = []string{RiskVersionChurnHigh}
	}
	return port.SignalResult{
		Raw:         raw,
		Explanation: fmt.Sprintf("%d version changes in 30d", changes),
		Attestation: domain.AttestationUnattested,
		RiskCodes:   risks,
	}, nil
}
