// Package importsvc implements the operator-only import endpoints (design §5.2,
// §5.2.1, §5.3): POST /v1/internal/agents/import (upsert) and POST
// /v1/internal/observations/import (append-only). It validates each batch
// against the §5.2.1 rules before persisting any row — a single failure rejects
// the whole batch — and guards both routes with a static admin bearer key.
//
// The package is split by concern: service.go (validation + persistence),
// dto.go (wire shapes + request→domain conversion and its 400-class checks),
// auth.go (admin-key middleware), handler.go (HTTP plumbing), and errors.go
// (the Problem-Details codes). All error responses are RFC 7807 via internal/web.
package importsvc
