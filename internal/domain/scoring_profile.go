package domain

// ScoringProfile configures scoring (design §4.5). SignalWeights set how
// signals roll up within a dimension (weighted average). DimensionWeights are
// an on/off gate selecting which dimensions drive the RecommendedProfile
// cascade (§4.6 active-dimension rule): only the sign is read, so in v1 a
// DimensionWeight is 0 or 1 — magnitude is inert (no cross-dimension aggregate;
// compositeScore is declined, §5.5) and the profile loader rejects other
// values. Distinct from a RecommendedProfile (the spec output classification).
// A weight of 0 means inactive.
type ScoringProfile struct {
	Name             string
	DimensionWeights map[Dimension]float64
	SignalWeights    map[SignalID]float64
}
