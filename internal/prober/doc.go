// Package prober is the AIM-archetype real-signal producer (design §6.6): it
// keeps the sealed `expected` baselines from the simulated TL events but derives
// the live `observed` side from real DNS queries and TLS handshakes, then POSTs
// verdict-shaped and raw observations to agent-trust-discovery's import contract.
//
// The network operations sit behind the Probe interface so the projection and
// HTTP logic here are unit-testable with a mock; the real net/crypto-tls probe
// lives in cmd/agent-prober. Like the hydrator, this package speaks only the
// public HTTP contract and the tlevent schema — it does not import
// internal/search, internal/scoring, or internal/importsvc (design §6.4,
// enforced by boundary_test.go). It is not part of `make demo`.
package prober
