package search

import (
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
