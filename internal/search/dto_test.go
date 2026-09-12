package search

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/agentnameservice/agent-trust-discovery/internal/domain"
)

// White-box test for the verificationTier mapping: unset → null pointer; a set
// tier (the v2 path) → its string. Keeps the DTO branch honest even though v1
// never emits a non-null tier.
func TestNewTrustEvaluationDTO_VerificationTier(t *testing.T) {
	base := domain.TrustEvaluation{EvaluationTime: time.Unix(0, 0).UTC()}

	if got := newTrustEvaluationDTO(base); got.VerificationTier != nil {
		t.Errorf("unset tier → %v, want nil (null)", *got.VerificationTier)
	}

	base.VerificationTier = domain.TierBronze
	got := newTrustEvaluationDTO(base)
	if got.VerificationTier == nil || *got.VerificationTier != "BRONZE" {
		t.Errorf("bronze tier → %v, want BRONZE", got.VerificationTier)
	}
}

// riskFactors must always serialise as a non-nil slice, even when the engine
// produced none.
func TestNewTrustEvaluationDTO_RiskFactorsNeverNil(t *testing.T) {
	got := newTrustEvaluationDTO(domain.TrustEvaluation{EvaluationTime: time.Unix(0, 0).UTC()})
	if got.RiskFactors == nil {
		t.Error("riskFactors is nil; want non-nil empty slice")
	}
}

// A signal score's provenance is surfaced in the DTO (under "provenance") so a
// relying party can trace the score to its source; a score with no provenance
// omits the field entirely.
func TestNewTrustEvaluationDTO_Provenance(t *testing.T) {
	ev := domain.TrustEvaluation{
		EvaluationTime: time.Unix(0, 0).UTC(),
		Dimensions: []domain.DimensionScore{{
			Dimension: domain.DimensionSafety,
			SignalScores: []domain.SignalScore{
				{
					SignalID:   "agentgraph.safety.score",
					Provenance: &domain.Provenance{AIMID: "did:web:agentgraph.co", EvidenceURL: "https://agentgraph.co/finding/1"},
				},
				{SignalID: "x.safety.score"}, // no observation -> no provenance
			},
		}},
	}
	got := newTrustEvaluationDTO(ev)
	ss := got.Dimensions[0].SignalScores

	if ss[0].Provenance == nil || ss[0].Provenance.AIMID != "did:web:agentgraph.co" {
		t.Fatalf("provenance not mapped: %+v", ss[0].Provenance)
	}
	if ss[1].Provenance != nil {
		t.Errorf("score with no provenance should map to nil, got %+v", ss[1].Provenance)
	}

	// It serialises under "provenance"; the field is omitted when nil.
	b, _ := json.Marshal(ss[0])
	if !strings.Contains(string(b), `"provenance"`) || !strings.Contains(string(b), `"did:web:agentgraph.co"`) {
		t.Errorf("provenance not in JSON: %s", b)
	}
	if b2, _ := json.Marshal(ss[1]); strings.Contains(string(b2), `"provenance"`) {
		t.Errorf("nil provenance should be omitted from JSON: %s", b2)
	}
}
