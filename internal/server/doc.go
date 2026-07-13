// Package server wires the read and import handlers onto a chi router with the
// §5.6 observability stack (request-ID, structured request logging, per-import
// audit) and exposes Build, the composition root the cmd/agent-trust-discovery binary
// calls. Keeping the wiring here — rather than in package main — lets it be
// exercised end-to-end in tests against a temp database.
package server
