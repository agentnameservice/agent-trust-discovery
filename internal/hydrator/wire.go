package hydrator

import "encoding/json"

// Wire shapes for the agent-trust-discovery import contract (design §5.2). The hydrator
// defines these itself rather than importing internal/importsvc, keeping the
// dependency one-way (§6.4): the HTTP JSON is the only coupling.
//
// The observationWire / provenanceWire types here are intentionally duplicated
// with internal/prober/wire.go, not factored into a shared package. The
// hydrator and prober are independent reference producers; each is meant to
// read top-to-bottom on its own. See prober/wire.go for the fuller rationale.

type agentImportRequest struct {
	Agents []agentWire `json:"agents"`
}

type agentWire struct {
	AgentID      string   `json:"agentId"`
	DNSName      string   `json:"dnsName"`
	DisplayName  string   `json:"displayName"`
	Description  string   `json:"description,omitempty"`
	ProviderID   string   `json:"providerId,omitempty"`
	Status       string   `json:"status"`
	Protocols    []string `json:"protocols,omitempty"`
	Transports   []string `json:"transports,omitempty"`
	Tags         []string `json:"tags,omitempty"`
	Capabilities []string `json:"capabilities,omitempty"`
	FirstSeen    string   `json:"firstSeen"`
	LastUpdated  string   `json:"lastUpdated"`
}

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

// driftValue is the verdict-shaped payload for drift-verdict signals (design
// §3.1 #8): the hydrator pairs a sealed baseline (expected) with a live-side
// value (observed) and labels the sources.
type driftValue struct {
	Expected       string `json:"expected"`
	Observed       string `json:"observed"`
	Matched        bool   `json:"matched"`
	ExpectedSource string `json:"expectedSource"`
	ObservedSource string `json:"observedSource"`
}
