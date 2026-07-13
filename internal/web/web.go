// Package web holds the shared HTTP response helpers used by every handler in
// the RI: JSON encoding and RFC 7807 Problem Details (design §5.4, mirroring
// the sibling `ans` repo's error convention). It is deliberately tiny and
// depends only on the standard library so both the import service (§5.2) and
// the search service (§5.1) can render errors identically.
package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/agentnameservice/agent-trust-discovery/internal/ctxlog"
)

// Error is a typed application error carrying everything the HTTP layer needs
// to render an RFC 7807 Problem: the HTTP status, a programmatic code clients
// switch on, and a human-readable detail. Services and DTO conversion return
// it; WriteProblem renders it. Anything that is not an *Error is treated as an
// unexpected internal error (HTTP 500) and is never surfaced to the client.
type Error struct {
	Status int
	Code   string
	Detail string
}

// NewError builds a typed error. status is an http.Status*, code is a stable
// programmatic identifier (e.g. AGENT_NOT_FOUND), detail is safe to show
// callers (it must not embed secrets or internal state).
func NewError(status int, code, detail string) *Error {
	return &Error{Status: status, Code: code, Detail: detail}
}

// Error implements the error interface. It carries the code and detail so the
// value is self-describing in logs.
func (e *Error) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Detail)
}

// Problem is the RFC 7807 response body. type is always "about:blank" in the
// RI (we do not publish a problem-type registry); clients read code for
// programmatic handling (design §5.4).
type Problem struct {
	Type   string `json:"type"`
	Title  string `json:"title"`
	Status int    `json:"status"`
	Detail string `json:"detail,omitempty"`
	Code   string `json:"code,omitempty"`
}

// WriteJSON writes value as JSON with the given status. A nil value writes the
// status line only (used for 204-style or empty 200 acks).
func WriteJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if value != nil {
		_ = json.NewEncoder(w).Encode(value)
	}
}

// WriteProblem renders err as an RFC 7807 application/problem+json response.
// A *web.Error (anywhere in the chain — errors.As unwraps) maps to its own
// status/code/detail. Any other error maps to a 500 with a generic detail; the
// underlying message is intentionally withheld so storage/internal errors never
// leak to clients (design §5.6).
//
// Prefer WriteProblemCtx from request handlers: it logs the underlying cause
// on the request-scoped logger so unexpected 500s are diagnosable. WriteProblem
// is kept for call sites that log the cause themselves (e.g. the panic
// recoverer, which logs the panic value before rendering the problem).
func WriteProblem(w http.ResponseWriter, err error) {
	writeProblem(w, err)
}

// WriteProblemCtx is WriteProblem plus a log line at the point of conversion:
// when err is not a *web.Error the wrapped cause is logged at ERROR level via
// the request-scoped logger stored in ctx (ctxlog.From). This makes generic
// 500s diagnosable — the client sees "an unexpected internal error occurred",
// operators see the wrapped error with requestId correlation.
func WriteProblemCtx(ctx context.Context, w http.ResponseWriter, err error) {
	var we *Error
	if !errors.As(err, &we) {
		ctxlog.From(ctx).ErrorContext(ctx, "internal error", "error", err)
	}
	writeProblem(w, err)
}

func writeProblem(w http.ResponseWriter, err error) {
	p := problemFor(err)
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(p.Status)
	_ = json.NewEncoder(w).Encode(p)
}

func problemFor(err error) Problem {
	var we *Error
	if errors.As(err, &we) {
		status := sanitizeErrorStatus(we.Status)
		return Problem{
			Type:   "about:blank",
			Title:  http.StatusText(status),
			Status: status,
			Detail: we.Detail,
			Code:   we.Code,
		}
	}
	return Problem{
		Type:   "about:blank",
		Title:  http.StatusText(http.StatusInternalServerError),
		Status: http.StatusInternalServerError,
		Detail: "an unexpected internal error occurred",
	}
}

// sanitizeErrorStatus clamps a caller-supplied HTTP status to a well-formed
// 4xx/5xx. A future NewError with an out-of-range value would otherwise give
// an empty http.StatusText title, and net/http.WriteHeader panics for codes
// outside [100, 1000). Anything outside 400–599 becomes 500 — a Problem
// response that ever carries a 2xx or 3xx is a bug, and hiding it behind a
// silent misrender is worse than surfacing it as a generic internal error.
func sanitizeErrorStatus(status int) int {
	if status < 400 || status > 599 {
		return http.StatusInternalServerError
	}
	return status
}
