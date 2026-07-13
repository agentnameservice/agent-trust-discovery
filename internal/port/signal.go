package port

import (
	"context"
	"encoding/json"

	"github.com/agentnameservice/agent-trust-discovery/internal/domain"
)

// SignalResult is everything Evaluate produces about an agent under a given
// observation. The signal owns this end-to-end: the raw score, the
// human-readable explanation, the attestation tier the underlying evidence
// earns, and the risk codes (if any). The engine does not parse the observation
// value — that contract belongs to the signal (design §5.2.1: "the signal is
// the schema").
type SignalResult struct {
	Raw         int                // 0..100, per spec Appendix B
	Explanation string             // human-readable, surfaced in the API response
	Attestation domain.Attestation // tier of the evidence backing this score
	RiskCodes   []string           // zero or more spec-§7.3 risk codes
}

// Signal is the plug-in contract (design §4.1). Implement it in any package,
// register it inside agent-trust-discovery, and ship a weight in a scoring profile.
type Signal interface {
	ID() domain.SignalID
	Dimension() domain.Dimension

	// Derived reports whether this signal computes itself from agent state and
	// never accepts external observations. Derived signals reject imports
	// (design §5.2.1).
	Derived() bool

	// Validate checks that the incoming observation value matches this signal's
	// typed schema. Called by the import service before persisting; returns a
	// human-readable error on schema mismatch, nil on success. Never called for
	// derived signals.
	Validate(value json.RawMessage) error

	// Evaluate returns the full SignalResult plus an error. obs is the most
	// recent observation for this agent and signal; nil means "no observation
	// recorded" — a valid input the signal decides how to handle. ctx lets
	// signal implementations that call the network (OCSP, DNS, external APIs)
	// honor request deadlines and cancellation; the v1 built-in signals are
	// all pure and ignore it.
	Evaluate(ctx context.Context, agent domain.Agent, obs *domain.SignalObservation) (SignalResult, error)
}

// SignalRegistry holds the signals a binary knows about. The concrete
// implementation lives with the scoring engine (design §4) to avoid an import
// cycle; this port lets the import and search services depend on the abstraction.
type SignalRegistry interface {
	Register(s Signal) error
	Get(id domain.SignalID) (Signal, bool)
	All() []Signal
}
