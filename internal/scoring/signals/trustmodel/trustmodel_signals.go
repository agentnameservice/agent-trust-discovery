// Package trustmodel registers the ANS Trust Index signals backed by TrustModel.
//
// The Linux Foundation Agent Name Service (ANS) ships an agent-trust-discovery
// engine whose five-dimension model leaves solvency, behavior, and safety EMPTY
// in v1 (no signals registered; dimensionWeight 0 — see config/default-profile.yaml).
// These three signals fill exactly those dimensions from TrustModel's independent
// evaluation, turning ANS's identity layer into a full trust layer.
//
// They add NO scoring logic to core. Each is an instance of the shared
// scorecontainer (internal/scoring/signals/scorecontainer, #15): the neutral
// 0..100 container that owns validation, dimension-scoped risk codes, the
// low-score backstop, and absent-!=-scored-0 semantics. TrustModel's hydrator
// POSTs observations of the shape {score, riskCodes, explanation} to
// /v1/internal/observations/import for the ids below and rides its evidence on
// the observation's provenance envelope; core never re-derives a tier or holds a
// per-dimension opinion. The same container backs any other provider's
// vendor.dimension.name signal.
//
// solvency scores the controlling ORGANIZATION, not the agent (subject "org"):
// it measures the accountability of the party behind the agent — a different
// subject from behavior/safety — so an index never averages an org score into an
// agent score (issue #9 and the #10 review). behavior and safety score the agent.
//
// Once config-driven registration (#16) lands, these three become entries in a
// score-signals.yaml with no Go at all and this package goes away; until then
// they register in internal/server.Build.
package trustmodel

import (
	"github.com/agentnameservice/agent-trust-discovery/internal/domain"
	"github.com/agentnameservice/agent-trust-discovery/internal/port"
	"github.com/agentnameservice/agent-trust-discovery/internal/scoring/signals/scorecontainer"
)

// Signals returns the TrustModel Trust Index signals to register with the engine.
//
// IDs follow scorecontainer's vendor.dimension.name convention so the dimension
// segment matches Dimension() and TrustModel can carry more than one signal per
// dimension later without an ID collision. A nil threshold takes the container's
// default low-score backstop; an operator retunes it in config, not here.
func Signals() []port.Signal {
	return []port.Signal{
		scorecontainer.New("trustmodel.behavior.score", domain.DimensionBehavior, nil),
		scorecontainer.New("trustmodel.safety.score", domain.DimensionSafety, nil),
		// solvency scores the controlling org, not the agent (subject "org").
		scorecontainer.NewWithSubject("trustmodel.solvency.score", domain.DimensionSolvency, "org", nil),
	}
}
