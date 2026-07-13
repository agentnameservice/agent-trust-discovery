package server

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/agentnameservice/agent-trust-discovery/internal/auditctx"
	"github.com/agentnameservice/agent-trust-discovery/internal/ctxlog"
	"github.com/agentnameservice/agent-trust-discovery/internal/web"
)

// requestIDHeader is the inbound/echoed correlation header (design §5.6).
const requestIDHeader = "X-Request-Id"

// maxRequestIDLen caps the length of an accepted inbound X-Request-Id. Real
// correlation IDs (UUIDs, ULIDs, hex random) are ≤ 64 bytes; anything longer
// is a client mistake or a probing attempt. Go's http.ResponseWriter already
// strips CR/LF so response-splitting isn't reachable — but a downstream
// service that re-emits this ID somewhere else (a log aggregator, a
// distributed trace) may not, so we validate it here as cheap insurance.
const maxRequestIDLen = 64

// maxAdminBodyBytes caps admin import request bodies. audit runs before
// adminAuth (router.go), so an unauthenticated caller must not be able to
// force the server to buffer an unbounded body just to reach the 401. 1 MiB is
// well above the largest legitimate batch imports we generate.
const maxAdminBodyBytes = 1 << 20

// requestID is the outermost app middleware: it honors an inbound X-Request-Id
// (or mints one), echoes it, and attaches a request-scoped logger carrying it so
// every downstream line is correlatable (design §5.6).
func requestID(base *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := r.Header.Get(requestIDHeader)
			if !isValidRequestID(id) {
				id = newRequestID()
			}
			w.Header().Set(requestIDHeader, id)
			ctx := ctxlog.With(r.Context(), base.With("requestId", id))
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// isValidRequestID reports whether an inbound X-Request-Id passes the
// charset/length gate for echo and log correlation. Accept the character set
// used by UUIDs, ULIDs, hex, and RFC-shaped trace IDs — letters, digits,
// underscore, and hyphen — and reject anything else (control chars,
// whitespace, quotes, angle brackets) so a downstream re-emit stays safe.
// Empty string is invalid so the caller mints a fresh ID.
func isValidRequestID(s string) bool {
	if s == "" || len(s) > maxRequestIDLen {
		return false
	}
	for i := range len(s) {
		c := s[i]
		switch {
		case c >= '0' && c <= '9',
			c >= 'a' && c <= 'z',
			c >= 'A' && c <= 'Z',
			c == '-', c == '_':
			// ok
		default:
			return false
		}
	}
	return true
}

func newRequestID() string {
	var b [16]byte
	_, _ = rand.Read(b[:]) // crypto/rand.Read does not fail in practice
	return hex.EncodeToString(b[:])
}

// recoverer turns a panic into a logged 500 RFC 7807 response so a single bad
// request never takes the process down (design §5.6 ERROR level).
func recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				ctxlog.From(r.Context()).ErrorContext(r.Context(), "panic recovered",
					"panic", fmt.Sprint(rec), "route", r.URL.Path)
				web.WriteProblem(w, errors.New("panic"))
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// requestLogger emits one structured line per public request: INFO for 2xx/3xx,
// WARN for 4xx (rejections), ERROR for 5xx (infrastructure), each with the
// route, query, status, duration, and — for problem responses — the code
// (design §5.6). route is the bare path; query carries the raw query string
// (e.g. profile=identity-strict) so an operator can see which profile and
// search params a request used without it polluting the route cardinality.
//
// The log line is deferred so a downstream panic still emits it — the
// recoverer (mounted above this middleware) turns the panic into a 500 which
// this deferred logger then sees on rec.status. Without the defer, the panic
// unwinds past ServeHTTP and no per-request line is ever written.
func requestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		defer func() {
			dur := time.Since(start).Milliseconds()
			l := ctxlog.From(r.Context())
			switch {
			case rec.status >= http.StatusInternalServerError:
				l.ErrorContext(r.Context(), "request failed",
					"route", r.URL.Path, "query", r.URL.RawQuery, "method", r.Method, "status", rec.status, "durationMs", dur, "code", rec.problemCode())
			case rec.status >= http.StatusBadRequest:
				l.WarnContext(r.Context(), "request rejected",
					"route", r.URL.Path, "query", r.URL.RawQuery, "method", r.Method, "status", rec.status, "durationMs", dur, "code", rec.problemCode())
			default:
				l.InfoContext(r.Context(), "request served",
					"route", r.URL.Path, "query", r.URL.RawQuery, "method", r.Method, "status", rec.status, "durationMs", dur)
			}
		}()
		next.ServeHTTP(rec, r)
	})
}

// audit emits the one mandatory line per /v1/internal/* request — accepted or
// rejected — capturing whether it was authenticated, the batch size the
// handler reported, and the outcome (design §5.6). It wraps the auth
// middleware so 401s are audited too, and caps the request body to
// maxAdminBodyBytes before any other work so an unauthenticated caller cannot
// force the server to buffer an unbounded body.
//
// batchSize is sourced from an auditctx.Info the middleware installs on the
// request context; handlers set Accepted after processing. This keeps the
// import wire shape ({agents} vs {observations}) inside importsvc rather than
// re-parsing the body here for a log field.
//
// The audit line is deferred so a downstream panic still emits it — the
// recoverer (mounted above) turns the panic into a 500, which this deferred
// logger then sees on rec.status. The audit line is mandatory (§5.6): every
// admin call must produce one, panicking handler or not.
func audit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		presentedKey := r.Header.Get("Authorization") != ""

		ctx, info := auditctx.With(r.Context())
		r = r.WithContext(ctx)

		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		defer func() {
			outcome := "accepted"
			if rec.status >= http.StatusBadRequest {
				outcome = "rejected"
			}
			batchSize := 0
			if info != nil {
				batchSize = info.Accepted
			}
			ctxlog.From(r.Context()).InfoContext(r.Context(), "admin import",
				"route", r.URL.Path,
				"authenticated", presentedKey && rec.status != http.StatusUnauthorized,
				"batchSize", batchSize,
				"outcome", outcome,
				"status", rec.status,
				"durationMs", time.Since(start).Milliseconds())
		}()

		// Cap the body BEFORE the auth check so an unauthenticated caller can
		// never make us buffer an unbounded body just to reach the 401. Read
		// into memory bounded by the cap, produce a 413 up front on overflow,
		// then restore the body for the handler. This does one full read per
		// admin call but zero JSON parses — the wire shape (agents vs
		// observations envelope) stays inside importsvc.
		if r.Body != nil {
			body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxAdminBodyBytes))
			if err != nil {
				var maxErr *http.MaxBytesError
				if errors.As(err, &maxErr) {
					web.WriteProblem(rec, web.NewError(
						http.StatusRequestEntityTooLarge,
						"REQUEST_TOO_LARGE",
						fmt.Sprintf("request body exceeds %d bytes", maxAdminBodyBytes),
					))
					return
				}
				web.WriteProblem(rec, web.NewError(
					http.StatusBadRequest,
					"INVALID_REQUEST",
					"request body could not be read",
				))
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
		}

		next.ServeHTTP(rec, r)
	})
}

// statusRecorder captures the response status and, only for error responses,
// the (small) problem body so the logger can surface its code.
type statusRecorder struct {
	http.ResponseWriter
	status int
	body   *bytes.Buffer
}

// Unwrap lets http.ResponseController reach the underlying ResponseWriter for
// Flush/Hijack/etc., so a future streaming handler behind these middlewares
// keeps working. Without this, wrappers between the handler and w silently
// hide interfaces the underlying writer implements.
func (rec *statusRecorder) Unwrap() http.ResponseWriter { return rec.ResponseWriter }

func (rec *statusRecorder) WriteHeader(code int) {
	rec.status = code
	if code >= http.StatusBadRequest {
		rec.body = &bytes.Buffer{}
	}
	rec.ResponseWriter.WriteHeader(code)
}

func (rec *statusRecorder) Write(b []byte) (int, error) {
	if rec.body != nil {
		rec.body.Write(b)
	}
	return rec.ResponseWriter.Write(b)
}

func (rec *statusRecorder) problemCode() string {
	if rec.body == nil {
		return ""
	}
	var p struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(rec.body.Bytes(), &p)
	return p.Code
}
