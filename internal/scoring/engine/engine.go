// Package engine evaluates an agent against a scoring profile to produce a
// spec-conformant Trust Evaluation (design §4.2): it asks each registered signal
// for a result, rolls signal scores up to dimensions and dimensions across the
// Trust Vector, classifies the recommendedProfile (§4.6), and collects risk
// factors (§4.7). The engine never parses observation values — that contract
// belongs to the signal (§5.2.1).
package engine

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/agentnameservice/agent-trust-discovery/internal/ctxlog"
	"github.com/agentnameservice/agent-trust-discovery/internal/domain"
	"github.com/agentnameservice/agent-trust-discovery/internal/port"
)

// RiskSignalEvaluationFailed is the risk code recorded when a Signal's
// Evaluate method returns an error. The engine degrades gracefully — one
// buggy third-party signal must not break scoring for every agent — and
// records this generic marker so operators can see something went wrong.
const RiskSignalEvaluationFailed = "SIGNAL_EVALUATION_FAILED"

// ObservationReader is the slice of the store the engine needs: the latest
// observation per (agent, signal). port.AgentStore satisfies it.
type ObservationReader interface {
	LatestObservation(ctx context.Context, agentID domain.AgentID, signalID domain.SignalID) (*domain.SignalObservation, error)
}

// Engine computes Trust Evaluations. Construct with New.
type Engine struct {
	store      ObservationReader
	registry   port.SignalRegistry
	thresholds Thresholds
	now        func() time.Time
}

// New builds an engine. now supplies the evaluation timestamp; pass nil for time.Now.
func New(store ObservationReader, reg port.SignalRegistry, thresholds Thresholds, now func() time.Time) *Engine {
	if now == nil {
		now = time.Now
	}
	return &Engine{store: store, registry: reg, thresholds: thresholds, now: now}
}

// Evaluate scores the agent under the given profile. It is computed lazily (no
// cache; design §3.1 #3).
func (e *Engine) Evaluate(ctx context.Context, agent domain.Agent, profile domain.ScoringProfile) (domain.TrustEvaluation, error) {
	byDimension := make(map[domain.Dimension][]domain.SignalScore)
	var allRisks []string

	log := ctxlog.From(ctx)
	for _, sig := range e.registry.All() {
		obs, err := e.store.LatestObservation(ctx, agent.ID, sig.ID())
		if err != nil {
			return domain.TrustEvaluation{}, fmt.Errorf("engine: latest observation %s/%s: %w", agent.ID, sig.ID(), err)
		}
		// Extension-boundary policies (Signal is a public plug-in surface):
		// (a) On Evaluate error, degrade — the signal contributes a Raw-0
		//     Unattested score plus a SIGNAL_EVALUATION_FAILED risk code, and
		//     the run continues. Fail-fast here would let one buggy signal
		//     take out scoring for every agent, which defeats the point of
		//     having a signal interface.
		// (b) Clamp Raw to [0,100] before it feeds the weighted average; the
		//     spec says signals return 0..100 (Appendix B), and a third-party
		//     signal returning 150 or -5 would otherwise poison the
		//     dimension score.
		res, evalErr := sig.Evaluate(ctx, agent, obs)
		if evalErr != nil {
			log.WarnContext(ctx, "engine: signal evaluation failed, degrading",
				"agentId", agent.ID, "signalId", sig.ID(), "error", evalErr)
			res = port.SignalResult{
				Raw:         0,
				Explanation: fmt.Sprintf("signal evaluation failed: %s", evalErr),
				Attestation: domain.AttestationUnattested,
				RiskCodes:   []string{RiskSignalEvaluationFailed},
			}
		}
		clamped := clampRaw(res.Raw)
		if clamped != res.Raw {
			log.WarnContext(ctx, "engine: signal Raw out of range, clamping",
				"agentId", agent.ID, "signalId", sig.ID(), "raw", res.Raw, "clamped", clamped)
		}

		weight := profile.SignalWeights[sig.ID()]
		dim := sig.Dimension()
		byDimension[dim] = append(byDimension[dim], domain.SignalScore{
			SignalID:    sig.ID(),
			Dimension:   dim,
			RawScore:    clamped,
			Weight:      weight,
			Explanation: res.Explanation,
			Attestation: res.Attestation,
		})
		// An inactive signal (weight 0) contributes neither score nor risk (§4.2).
		if weight > 0 {
			allRisks = append(allRisks, res.RiskCodes...)
		}
	}

	dims := make([]domain.DimensionScore, 0, len(domain.AllDimensions()))
	scores := make(map[domain.Dimension]int)
	active := make(map[domain.Dimension]bool)
	for _, dim := range domain.AllDimensions() {
		signalScores := byDimension[dim]
		score := weightedAverage(signalScores)
		scores[dim] = score
		dims = append(dims, domain.DimensionScore{Dimension: dim, Score: score, SignalScores: signalScores})
		active[dim] = profile.DimensionWeights[dim] > 0 && hasWeightedSignal(signalScores)
	}

	return domain.TrustEvaluation{
		AgentID:        agent.ID,
		EvaluationTime: e.now().UTC(),
		TrustVector: domain.TrustVector{
			Integrity: scores[domain.DimensionIntegrity],
			Identity:  scores[domain.DimensionIdentity],
			Solvency:  scores[domain.DimensionSolvency],
			Behavior:  scores[domain.DimensionBehavior],
			Safety:    scores[domain.DimensionSafety],
		},
		RecommendedProfile: e.thresholds.Classify(scores, active),
		RiskFactors:        dedupePreserveOrder(allRisks),
		VerificationTier:   domain.TierUnset, // v1 does not assess DNSSEC/DANE/TL (§5.5)
		Dimensions:         dims,
		ScoringProfile:     profile.Name,
	}, nil
}

// weightedAverage is round( Σ(raw·weight) / Σ(weight) ) over entries with
// weight > 0, computed in float64 and rounded to an integer in [0,100] (design
// §4.2). A dimension with no weighted signals scores 0.
func weightedAverage(scores []domain.SignalScore) int {
	var sumWeighted, sumWeight float64
	for _, s := range scores {
		if s.Weight > 0 {
			sumWeighted += float64(s.RawScore) * s.Weight
			sumWeight += s.Weight
		}
	}
	if sumWeight == 0 {
		return 0
	}
	return int(math.Round(sumWeighted / sumWeight))
}

// clampRaw pins a Signal result's Raw score into the spec's [0,100] band
// (Appendix B). Values outside that range come from third-party bugs and
// would otherwise poison a weighted dimension score.
func clampRaw(raw int) int {
	switch {
	case raw < 0:
		return 0
	case raw > 100:
		return 100
	default:
		return raw
	}
}

func hasWeightedSignal(scores []domain.SignalScore) bool {
	for _, s := range scores {
		if s.Weight > 0 {
			return true
		}
	}
	return false
}

// dedupePreserveOrder removes duplicate risk codes, keeping first occurrence
// (registry order). Returns an empty, non-nil slice when there are none.
func dedupePreserveOrder(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
