package domain_test

import (
	"testing"

	"github.com/agentnameservice/agent-trust-discovery/internal/domain"
)

// recommendedProfile is one of four spec §2.3 labels emitted on the wire.
func TestRecommendedProfileValues(t *testing.T) {
	pins := map[domain.RecommendedProfile]string{
		domain.ProfileReadOnly:      "READ_ONLY",
		domain.ProfileTransactional: "TRANSACTIONAL",
		domain.ProfileFiduciary:     "FIDUCIARY",
		domain.ProfileUntrusted:     "UNTRUSTED",
	}
	for p, want := range pins {
		if string(p) != want {
			t.Errorf("recommendedProfile const = %q, want %q", string(p), want)
		}
	}
}

// verificationTier is OPTIONAL (spec §7.2); the v1 default is unset (empty).
func TestVerificationTierValues(t *testing.T) {
	if string(domain.TierUnset) != "" {
		t.Errorf("TierUnset = %q, want empty", string(domain.TierUnset))
	}
	pins := map[domain.VerificationTier]string{
		domain.TierBronze: "BRONZE",
		domain.TierSilver: "SILVER",
		domain.TierGold:   "GOLD",
	}
	for tier, want := range pins {
		if string(tier) != want {
			t.Errorf("verificationTier const = %q, want %q", string(tier), want)
		}
	}
}
