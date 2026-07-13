package domain

// Dimension is one of the five Trust Index Trust Vector dimensions (spec §2.1,
// §2.2). All five MUST be present in every TrustEvaluation and MUST NOT be
// collapsed; signals are optional per dimension. In v1 only integrity and
// identity carry signals (design §3.1 decision #4).
type Dimension string

const (
	DimensionIntegrity Dimension = "integrity"
	DimensionIdentity  Dimension = "identity"
	DimensionSolvency  Dimension = "solvency" // empty in v1; no signals attached
	DimensionBehavior  Dimension = "behavior" // empty in v1; no signals attached
	DimensionSafety    Dimension = "safety"   // empty in v1; no signals attached
)

// AllDimensions returns the five dimensions in their canonical order. The
// engine iterates this so every TrustEvaluation carries all five (spec §2.1),
// and profile loading validates dimension keys against it. A fresh slice is
// returned each call so callers cannot mutate shared state.
func AllDimensions() []Dimension {
	return []Dimension{
		DimensionIntegrity,
		DimensionIdentity,
		DimensionSolvency,
		DimensionBehavior,
		DimensionSafety,
	}
}

// Valid reports whether d is one of the five known dimensions.
func (d Dimension) Valid() bool {
	for _, known := range AllDimensions() {
		if d == known {
			return true
		}
	}
	return false
}
