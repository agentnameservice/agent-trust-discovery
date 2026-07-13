package hydrator

import (
	"testing"

	"github.com/agentnameservice/agent-trust-discovery/internal/scoring/signals"
	"github.com/agentnameservice/agent-trust-discovery/internal/tlevent"
)

// The hydrator's driftBaseline must recognize every drift-signal ID the
// scoring layer registers (signals.DriftSignalIDs is the canonical list).
// A new drift signal added there without a matching case here would silently
// fall through to the raw-signal path, so the hydrator would forward the
// observation's Value as-is with no sealed baseline paired — every score
// would drop to "not sealed" for that signal.
func TestDriftBaseline_CoversCanonicalIDs(t *testing.T) {
	att := tlevent.Attestations{
		ServerCert:            tlevent.CertAttestation{Fingerprint: "SHA256:srv"},
		IdentityCert:          tlevent.CertAttestation{Fingerprint: "SHA256:idn"},
		DNSRecordsProvisioned: tlevent.DNSRecords{ANS: "v=ans1", ANSBadge: "v=ansb1"},
	}
	for _, id := range signals.DriftSignalIDs() {
		t.Run(string(id), func(t *testing.T) {
			got, isDrift := driftBaseline(string(id), att)
			if !isDrift {
				t.Errorf("driftBaseline(%q): isDrift=false; every ID in signals.DriftSignalIDs must be recognized", id)
			}
			if got == "" {
				t.Errorf("driftBaseline(%q): baseline is empty; the case must pluck a real Attestations field", id)
			}
		})
	}
}
