// Package trustmodel provides ANS Trust Index signals backed by TrustModel.
//
// The Linux Foundation Agent Name Service (ANS) ships an agent-trust-discovery
// engine whose five-dimension model leaves solvency, behavior, and safety EMPTY
// in v1 (no signals registered; dimensionWeight 0 — see config/default-profile.yaml).
// These three signals fill exactly those dimensions from TrustModel's independent
// evaluation, turning ANS's identity layer into a full trust layer.
//
// All three share ONE generic observation container (scoreValue): a 0..100
// score plus provider-asserted risk codes and an optional explanation. Core
// never re-derives tier or holds a per-dimension opinion — the provider (the
// TrustModel hydrator) computes the score and the dimension-scoped risk codes
// and hands them across the import boundary. That keeps the container reusable
// by any provider (not just TrustModel) and keeps solvency from re-deriving the
// cert tier that certtype already scores in the identity dimension.
//
// This package is meant to live inside the agent-trust-discovery module at
// internal/scoring/signals/trustmodel/ (Go's internal/ visibility rule requires
// it to be within the module) and be registered in internal/server.Build — see
// REGISTER.md. Observation values are produced by the TrustModel hydrator
// (../hydrator), which POSTs them to /v1/internal/observations/import.
package trustmodel

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/agentnameservice/agent-trust-discovery/internal/domain"
	"github.com/agentnameservice/agent-trust-discovery/internal/port"
)

// DefaultLowThreshold is the score below which the generic
// {DIMENSION}_TRUSTMODEL_SCORE_LOW backstop risk code is emitted. It is a
// per-signal field (see New) so an operator can tune it in configuration
// rather than it being a magic constant baked into Evaluate.
const DefaultLowThreshold = 70

// maxRiskCodes caps how many provider risk codes one observation may carry, so
// a hostile or buggy hydrator can't balloon the evaluation payload.
const maxRiskCodes = 16

// riskCodeRe is the spec-§7.3 risk-code shape: uppercase, digits, underscores.
var riskCodeRe = regexp.MustCompile(`^[A-Z0-9_]+$`)

// Signals returns the TrustModel Trust Index signals to register with the engine.
//
// IDs follow the vendor.dimension.name convention so the dimension segment
// matches Dimension() and a vendor can carry multiple signals per dimension
// later without an ID collision.
func Signals() []port.Signal {
	return []port.Signal{
		New("trustmodel.behavior.score", domain.DimensionBehavior, DefaultLowThreshold),
		New("trustmodel.safety.score", domain.DimensionSafety, DefaultLowThreshold),
		New("trustmodel.solvency.score", domain.DimensionSolvency, DefaultLowThreshold),
	}
}

// scoreValue is the generic observation container shared by every TrustModel
// signal. The provider computes Score and the dimension-scoped RiskCodes; core
// just carries them. Passing a bare {"score": N} still works — you then get
// only the threshold backstop, so nothing regresses for a minimal hydrator.
type scoreValue struct {
	Score       int      `json:"score"`                 // 0..100
	RiskCodes   []string `json:"riskCodes,omitempty"`   // provider-asserted, {DIMENSION}_-prefixed
	Explanation string   `json:"explanation,omitempty"` // optional; surfaced in the API response
}

// ScoreSignal is a generic provider-score signal for a single dimension. One
// instance per dimension; the ID, dimension, and low-score threshold are the
// only things that differ. Because the container is generic, this same type
// could back any provider's dimension score, not only TrustModel's.
type ScoreSignal struct {
	id        domain.SignalID
	dimension domain.Dimension
	threshold int
}

// New builds a ScoreSignal. threshold <= 0 falls back to DefaultLowThreshold.
func New(id domain.SignalID, dim domain.Dimension, threshold int) ScoreSignal {
	if threshold <= 0 {
		threshold = DefaultLowThreshold
	}
	return ScoreSignal{id: id, dimension: dim, threshold: threshold}
}

func (s ScoreSignal) ID() domain.SignalID         { return s.id }
func (s ScoreSignal) Dimension() domain.Dimension { return s.dimension }
func (s ScoreSignal) Derived() bool               { return false }

// AbsenceInformative reports false: a missing TrustModel observation means the
// agent has not been scored by TrustModel yet, not that it scored badly. The
// engine excludes this signal from the dimension roll-up when it has no
// observation for an agent (issue #13) rather than dragging the score to 0.
func (s ScoreSignal) AbsenceInformative() bool { return false }

// prefix is the required {DIMENSION}_ prefix for this signal's risk codes, e.g.
// "SOLVENCY_". Provider codes that don't carry it are dropped in Evaluate so a
// signal can't leak a code into a dimension it doesn't own.
func (s ScoreSignal) prefix() string {
	return strings.ToUpper(string(s.dimension)) + "_"
}

// Validate enforces the container schema before the observation is persisted:
// score in range, each risk code well-formed, and the count capped.
func (s ScoreSignal) Validate(value json.RawMessage) error {
	var v scoreValue
	if err := json.Unmarshal(value, &v); err != nil {
		return fmt.Errorf("%s: invalid value: %w", s.id, err)
	}
	if v.Score < 0 || v.Score > 100 {
		return fmt.Errorf("%s: score must be in [0,100], got %d", s.id, v.Score)
	}
	if len(v.RiskCodes) > maxRiskCodes {
		return fmt.Errorf("%s: too many riskCodes (%d > %d)", s.id, len(v.RiskCodes), maxRiskCodes)
	}
	for _, c := range v.RiskCodes {
		if !riskCodeRe.MatchString(c) {
			return fmt.Errorf("%s: risk code %q must match %s", s.id, c, riskCodeRe.String())
		}
	}
	return nil
}

// Evaluate maps the container onto a SignalResult: Raw is the score; RiskCodes
// are the provider's dimension-scoped codes plus the normalized
// {DIMENSION}_TRUSTMODEL_SCORE_LOW backstop when the score is below the
// configured threshold. Codes whose prefix doesn't match this signal's
// dimension are dropped.
func (s ScoreSignal) Evaluate(_ context.Context, _ domain.Agent, obs *domain.SignalObservation) (port.SignalResult, error) {
	prefix := s.prefix()
	if obs == nil {
		return port.SignalResult{
			Raw:         0,
			Explanation: fmt.Sprintf("no TrustModel %s score observed", s.dimension),
			Attestation: domain.AttestationUnattested,
			RiskCodes:   []string{prefix + "TRUSTMODEL_UNKNOWN"},
		}, nil
	}
	var v scoreValue
	if err := json.Unmarshal(obs.Value, &v); err != nil {
		return port.SignalResult{}, fmt.Errorf("%s: %w", s.id, err)
	}

	codes := make([]string, 0, len(v.RiskCodes)+1)
	for _, c := range v.RiskCodes {
		if strings.HasPrefix(c, prefix) {
			codes = append(codes, c)
		}
	}
	if v.Score < s.threshold {
		codes = append(codes, prefix+"TRUSTMODEL_SCORE_LOW")
	}

	explanation := v.Explanation
	if explanation == "" {
		explanation = fmt.Sprintf("TrustModel %s score %d/100", s.dimension, v.Score)
	}
	return port.SignalResult{
		Raw:         v.Score,
		Explanation: explanation,
		Attestation: domain.AttestationUnattested,
		RiskCodes:   codes,
	}, nil
}
