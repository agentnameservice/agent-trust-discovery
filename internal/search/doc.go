// Package search implements the public read API (design §5.1): the two search
// routes (GET query-param and POST JSON-body), the agent-detail route that
// embeds a Trust Evaluation, and the unauthenticated /health probe. Search is
// delegated to port.Index; detail combines port.AgentStore with the scoring
// engine under a selectable scoring profile.
//
// Split by concern: service.go (search delegation + detail evaluation), dto.go
// (wire response shapes + mapping from domain), params.go (query/body →
// port.SearchQuery), handler.go (HTTP plumbing + link building), errors.go (the
// Problem-Details codes). Error responses are RFC 7807 via internal/web; the
// collection envelope ({items, links, totalItems?, totalPages?}) is
// byte-compatible with ans-search-api (design §5.5).
package search
