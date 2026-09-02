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
	// DimensionCap, when non-nil, caps this signal's dimension score at the given
	// value no matter how the other signals in the dimension score — the signal
	// GATES the dimension rather than contributing a term to its average. nil
	// (the default) means a normal term, so existing signals are unaffected.
	//
	// A hard stop (a sanctions/compliance block, a safety hard-fail) returns
	// Raw:0 with DimensionCap:0, so "blocked" is a verdict rather than a 0 that
	// averages up to a passing score against co-registered signals. The engine
	// applies score = min(weightedAverage, min(caps)) over a dimension's gating
	// signals; caps only pull a dimension DOWN (there is no floor in v1, where
	// the real cases all lower the score and min composes cleanly). Only a
	// weighted (active) signal's cap applies, matching risk-code handling.
	DimensionCap *int
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

// AbsenceAware is an OPTIONAL interface a Signal may implement to declare
// whether a missing observation is informative. When a signal implements it and
// returns false, the engine EXCLUDES that signal from the dimension roll-up for
// an agent it has no observation for, instead of scoring it 0 (issue #13):
// absence in a sparse, provider-fed dimension (solvency, behavior, safety)
// carries no information about the agent — only that no provider has covered it
// yet. Scoring it 0 at full weight penalizes the agent for a coverage gap and
// makes adding any provider a global downgrade for every agent it hasn't seen.
//
// Signals that do NOT implement this interface, or return true, keep the v1
// behavior: a missing observation scores 0 and counts toward the dimension.
// That is correct for the zero-marginal-cost integrity built-ins, where a
// missing observation (no DNSSEC record) is itself meaningful.
type AbsenceAware interface {
	AbsenceInformative() bool
}

// SignalRegistry holds the signals a binary knows about. The concrete
// implementation lives with the scoring engine (design §4) to avoid an import
// cycle; this port lets the import and search services depend on the abstraction.
type SignalRegistry interface {
	Register(s Signal) error
	Get(id domain.SignalID) (Signal, bool)
	All() []Signal
}
