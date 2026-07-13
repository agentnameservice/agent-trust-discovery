package engine_test

import (
	"testing"

	"github.com/agentnameservice/agent-trust-discovery/internal/domain"
	"github.com/agentnameservice/agent-trust-discovery/internal/scoring/engine"
)

func TestClassifyCascade(t *testing.T) {
	th := engine.DefaultThresholds()
	bothActive := map[domain.Dimension]bool{domain.DimensionIntegrity: true, domain.DimensionIdentity: true}
	identityOnly := map[domain.Dimension]bool{domain.DimensionIdentity: true}
	integrityOnly := map[domain.Dimension]bool{domain.DimensionIntegrity: true}

	cases := []struct {
		name   string
		scores map[domain.Dimension]int
		active map[domain.Dimension]bool
		want   domain.RecommendedProfile
	}{
		{"worked example → READ_ONLY", scoreMap(89, 40), bothActive, domain.ProfileReadOnly},
		{"all high → FIDUCIARY", scoreMap(100, 100), bothActive, domain.ProfileFiduciary},
		{"fiduciary boundary 80/90", scoreMap(80, 90), bothActive, domain.ProfileFiduciary},
		{"high integrity, identity 85 → TRANSACTIONAL", scoreMap(100, 85), bothActive, domain.ProfileTransactional},
		{"both 50 → TRANSACTIONAL", scoreMap(50, 50), bothActive, domain.ProfileTransactional},
		{"identity 49 → READ_ONLY", scoreMap(100, 49), bothActive, domain.ProfileReadOnly},
		{"integrity 19 → UNTRUSTED", scoreMap(19, 100), bothActive, domain.ProfileUntrusted},
		{"integrity exactly 20 → READ_ONLY (not UNTRUSTED)", scoreMap(20, 100), bothActive, domain.ProfileReadOnly},
		{"identity-strict 100 → FIDUCIARY", scoreMap(0, 100), identityOnly, domain.ProfileFiduciary},
		{"identity-strict 70 → TRANSACTIONAL", scoreMap(0, 70), identityOnly, domain.ProfileTransactional},
		{"integrity-only 100, no identity → TRANSACTIONAL (fiduciary unreachable)", scoreMap(100, 0), integrityOnly, domain.ProfileTransactional},
		{"no active dims → READ_ONLY", scoreMap(0, 0), map[domain.Dimension]bool{}, domain.ProfileReadOnly},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := th.Classify(tc.scores, tc.active); got != tc.want {
				t.Errorf("Classify = %s, want %s", got, tc.want)
			}
		})
	}
}

func scoreMap(integrity, identity int) map[domain.Dimension]int {
	return map[domain.Dimension]int{
		domain.DimensionIntegrity: integrity,
		domain.DimensionIdentity:  identity,
		domain.DimensionSolvency:  0,
		domain.DimensionBehavior:  0,
		domain.DimensionSafety:    0,
	}
}
