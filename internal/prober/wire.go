package prober

import "encoding/json"

// Wire shapes for /v1/internal/observations/import (design §5.2). The prober
// owns these so it does not import internal/importsvc (§6.4).
//
// observationWire / provenanceWire / driftValue are intentionally duplicated
// with internal/hydrator/wire.go rather than factored into a shared package.
// The two producers (hydrator, prober) are independent reference examples of
// "how to POST to the import API"; each reads top-to-bottom on its own, which
// is the point of the RI. A shared internal/importclient would satisfy §6.4
// too, but it would couple the two producers and make each harder to read in
// isolation. The HTTP JSON contract — not a Go type — is the intended coupling.

type observationImportRequest struct {
	Observations []observationWire `json:"observations"`
}

type observationWire struct {
	AgentID    string          `json:"agentId"`
	SignalID   string          `json:"signalId"`
	ObservedAt string          `json:"observedAt"`
	Value      json.RawMessage `json:"value"`
	Provenance *provenanceWire `json:"provenance,omitempty"`
}

type provenanceWire struct {
	AIMID       string `json:"aimId,omitempty"`
	EvidenceURL string `json:"evidenceUrl,omitempty"`
}

// driftValue is the verdict shape for drift-verdict signals (design §3.1 #8);
// observedSource is live_tls_handshake / live_dns_query for the prober.
type driftValue struct {
	Expected       string `json:"expected"`
	Observed       string `json:"observed"`
	Matched        bool   `json:"matched"`
	ExpectedSource string `json:"expectedSource"`
	ObservedSource string `json:"observedSource"`
}
