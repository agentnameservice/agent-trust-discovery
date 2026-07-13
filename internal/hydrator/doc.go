// Package hydrator is the Bootstrap-archetype signal hydrator (design §6.3): it
// reads simulated TL events and fixture observations, projects each event into
// an agent import, pairs the events' sealed baselines against the fixtures'
// live-side values to compute drift verdicts, and POSTs both to agent-trust-discovery's
// public import contract.
//
// It speaks only that HTTP contract plus the tlevent schema — it deliberately
// does not import internal/search, internal/scoring, or internal/importsvc
// (design §6.4; enforced by boundary_test.go). The hydrator owns its own wire
// DTOs so the dependency stays one-way.
package hydrator
