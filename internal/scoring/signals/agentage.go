package signals

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/agentnameservice/agent-trust-discovery/internal/domain"
	"github.com/agentnameservice/agent-trust-discovery/internal/port"
)

const agentAgeRampDays = 180.0

// AgentAge is a derived signal: it scores how long an agent has been known,
// computed from agent.FirstSeen, ramping linearly to 100 at 180 days (design
// §4.4). Being derived, it never accepts external observations (§5.2.1).
type AgentAge struct {
	now func() time.Time
}

// NewAgentAge builds the signal with an injectable clock; pass nil for time.Now.
func NewAgentAge(now func() time.Time) AgentAge {
	if now == nil {
		now = time.Now
	}
	return AgentAge{now: now}
}

func (AgentAge) ID() domain.SignalID         { return "agentage" }
func (AgentAge) Dimension() domain.Dimension { return domain.DimensionIntegrity }
func (AgentAge) Derived() bool               { return true }

// Validate always errors: agentage is derived, so observation imports are
// rejected (the import service screens this out first via Derived()).
func (AgentAge) Validate(json.RawMessage) error {
	return errors.New("agentage is a derived signal; observations are not accepted")
}

// Evaluate ignores obs and scores from agent.FirstSeen. A raw score < 25 yields
// INTEGRITY_AGENT_NEW (design §4.7).
func (a AgentAge) Evaluate(_ context.Context, agent domain.Agent, _ *domain.SignalObservation) (port.SignalResult, error) {
	ageDays := int(a.now().Sub(agent.FirstSeen).Hours() / 24)
	if ageDays < 0 {
		ageDays = 0
	}
	raw := int(math.Round(100 * float64(ageDays) / agentAgeRampDays))
	if raw > 100 {
		raw = 100
	}

	var risks []string
	if raw < 25 {
		risks = []string{RiskAgentNew}
	}
	return port.SignalResult{
		Raw:         raw,
		Explanation: fmt.Sprintf("%d days old; ramp to 100 at 180", ageDays),
		Attestation: domain.AttestationUnattested,
		RiskCodes:   risks,
	}, nil
}
