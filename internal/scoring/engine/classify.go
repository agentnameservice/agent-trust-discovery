package engine

import "github.com/agentnameservice/agent-trust-discovery/internal/domain"

// Thresholds are the recommendedProfile cascade cut-offs (design §4.6). The
// values are illustrative for the RI; the spec leaves them to provider choice.
type Thresholds struct {
	Untrusted         int
	Transactional     int
	Fiduciary         int
	IdentityFiduciary int
}

// DefaultThresholds returns the design defaults (20 / 50 / 80 / 90).
func DefaultThresholds() Thresholds {
	return Thresholds{Untrusted: 20, Transactional: 50, Fiduciary: 80, IdentityFiduciary: 90}
}

// Classify assigns a recommendedProfile via an ordered first-match cascade over
// the profile's active dimensions (design §4.6). A dimension is active when its
// dimensionWeight > 0 and it carries at least one weighted signal — the caller
// supplies that determination in `active`. The cascade is total: READ_ONLY is
// the explicit fallback.
func (t Thresholds) Classify(scores map[domain.Dimension]int, active map[domain.Dimension]bool) domain.RecommendedProfile {
	if !anyActive(active) {
		// No dimension carries weighted evidence — conservatively READ_ONLY
		// (an empty dimension's structural 0 must not pin the agent to UNTRUSTED).
		return domain.ProfileReadOnly
	}

	// Rule 1 — any active dimension below the untrusted floor.
	for dim, on := range active {
		if on && scores[dim] < t.Untrusted {
			return domain.ProfileUntrusted
		}
	}

	// Rule 2 — every active dimension ≥ fiduciary AND identity (itself active)
	// ≥ its higher bar. If identity is not active, this rule is unreachable.
	if allActiveAtLeast(scores, active, t.Fiduciary) &&
		active[domain.DimensionIdentity] && scores[domain.DimensionIdentity] >= t.IdentityFiduciary {
		return domain.ProfileFiduciary
	}

	// Rule 3 — every active dimension ≥ transactional.
	if allActiveAtLeast(scores, active, t.Transactional) {
		return domain.ProfileTransactional
	}

	// Rule 4 — explicit fallback.
	return domain.ProfileReadOnly
}

func anyActive(active map[domain.Dimension]bool) bool {
	for _, on := range active {
		if on {
			return true
		}
	}
	return false
}

func allActiveAtLeast(scores map[domain.Dimension]int, active map[domain.Dimension]bool, threshold int) bool {
	for dim, on := range active {
		if on && scores[dim] < threshold {
			return false
		}
	}
	return true
}
