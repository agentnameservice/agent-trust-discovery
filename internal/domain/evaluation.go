package domain

import "time"

// RecommendedProfile is the Trust Index spec §2.3 output classification, one of
// four labels the engine assigns to each evaluation as a policy hint. Distinct
// from a ScoringProfile (the weight configuration).
type RecommendedProfile string

const (
	ProfileReadOnly      RecommendedProfile = "READ_ONLY"
	ProfileTransactional RecommendedProfile = "TRANSACTIONAL"
	ProfileFiduciary     RecommendedProfile = "FIDUCIARY"
	ProfileUntrusted     RecommendedProfile = "UNTRUSTED"
)

// VerificationTier is the spec §6 Bronze/Silver/Gold tier. Unset (empty) in v1,
// which does not assess DNSSEC/DANE/TL inclusion (design §5.5); the field is
// OPTIONAL per spec §7.2.
//
// v1 emits only TierUnset. TierBronze/Silver/Gold are declared so v2 wiring
// (DNSSEC/DANE/TL-inclusion assessment) can plug in without a domain type
// change; nothing in v1 produces them.
type VerificationTier string

const (
	TierUnset  VerificationTier = ""       // v1 default; no DNSSEC/DANE/TL assessment
	TierBronze VerificationTier = "BRONZE" // v2 — declared for forward compatibility, not produced in v1
	TierSilver VerificationTier = "SILVER" // v2 — declared for forward compatibility, not produced in v1
	TierGold   VerificationTier = "GOLD"   // v2 — declared for forward compatibility, not produced in v1
)

// TrustVector is the five-dimensional score vector (spec §2.2); each member is
// an integer in [0,100].
type TrustVector struct {
	Integrity int
	Identity  int
	Solvency  int
	Behavior  int
	Safety    int
}

// SignalScore is one signal's contribution under the active scoring profile.
// The score is carried as an integer on the wire (spec Appendix B); the engine
// computes in float64 and rounds at the DTO boundary.
type SignalScore struct {
	SignalID    SignalID
	Dimension   Dimension
	RawScore    int     // 0..100
	Weight      float64 // from active scoring profile (0 means inactive)
	Explanation string  // human-readable, surfaced in the API response
	Attestation Attestation
}

// DimensionScore is one dimension's rolled-up score and its contributing signal
// scores. Empty dimensions carry Score 0 and an empty SignalScores slice but
// are still present in every response (design §3.1 decision #4).
type DimensionScore struct {
	Dimension    Dimension
	Score        int // 0..100; weighted avg of signal scores within this dimension
	SignalScores []SignalScore
}

// TrustEvaluation matches the spec's Trust Evaluation Payload (Appendix B) and
// adds the RI-specific per-dimension breakdown for pedagogy (design §3, §5.1).
type TrustEvaluation struct {
	AgentID            AgentID
	EvaluationTime     time.Time
	TrustVector        TrustVector
	RecommendedProfile RecommendedProfile
	RiskFactors        []string
	VerificationTier   VerificationTier // absent (unset) in v1
	Dimensions         []DimensionScore // RI-specific transparency aid
	ScoringProfile     string           // which weight profile was applied
}
