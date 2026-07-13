package domain_test

import (
	"testing"

	"github.com/agentnameservice/agent-trust-discovery/internal/domain"
)

// Attestation strings appear on the wire (signalScore.attestation) and satisfy
// spec §3.1's MUST to distinguish TL-attested from unattested inputs. Pin them.
func TestAttestationValues(t *testing.T) {
	pins := map[domain.Attestation]string{
		domain.AttestationUnattested:   "unattested",
		domain.AttestationTLAttested:   "tl_attested",
		domain.AttestationCardAttested: "card_attested",
	}
	for a, want := range pins {
		if string(a) != want {
			t.Errorf("attestation const = %q, want %q", string(a), want)
		}
	}
}
