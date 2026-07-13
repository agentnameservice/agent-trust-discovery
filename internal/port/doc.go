// Package port declares the interface contracts (ports) the agent-trust-discovery core
// depends on: the Signal plug-in interface and its registry, and the storage
// ports (AgentStore, Index). Adapters under internal/adapter implement these;
// the search and scoring packages consume them. Keeping the contracts here lets
// the core depend on abstractions, not concrete infrastructure (design §2.1, §4.1).
package port
