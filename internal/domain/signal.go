package domain

import (
	"encoding/json"
	"time"
)

// SignalID identifies a trust signal (e.g. "certtype", "dnsrecord.ans").
type SignalID string

// Attestation labels the strongest evidence tier behind a SignalScore. The
// signal sets it on the result it returns from Evaluate by inspecting the
// observation's expectedSource (design §3.1 decision #8, §4.1); the engine
// never derives it.
type Attestation string

const (
	AttestationUnattested   Attestation = "unattested"    // default
	AttestationTLAttested   Attestation = "tl_attested"   // expected sourced from a TL event
	AttestationCardAttested Attestation = "card_attested" // expected sourced from a Trust Card hash (v2)
)

// SignalObservation is the most recent evidence recorded for one agent and one
// signal. Value's shape is owned by the signal (design §5.2.1: "the signal is
// the schema"); the engine never parses it.
type SignalObservation struct {
	AgentID    AgentID
	SignalID   SignalID
	ObservedAt time.Time
	Value      json.RawMessage // shape defined per signal
	Provenance *Provenance     // optional; identifies the producing AIM/hydrator
}

// Provenance optionally identifies the producing AIM/hydrator. It is opaque to
// the engine: stored alongside the observation and surfaced in the explanation
// field. v1 stores it but does not verify signatures or apply quorum (design §9).
type Provenance struct {
	AIMID       string // e.g. "did:web:aim.example.com"
	EvidenceURL string // optional URL pointing at the AIM's published finding
}
