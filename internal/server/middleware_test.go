package server

import (
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/agentnameservice/agent-trust-discovery/internal/auditctx"
	"github.com/agentnameservice/agent-trust-discovery/internal/web"
)

func bufLogger() (*slog.Logger, *strings.Builder) {
	b := &strings.Builder{}
	return slog.New(slog.NewJSONHandler(b, &slog.HandlerOptions{Level: slog.LevelInfo})), b
}

// A panicking handler must still produce the per-request log line and the
// mandatory admin audit line, and the recorded status must be 500 (not the
// pre-panic 200). The router mounts recoverer INSIDE the logging middlewares
// so the logger's statusRecorder observes the recovered 500 response.
func TestRequestLogger_LogsPanicAs500(t *testing.T) {
	logger, logs := bufLogger()
	chain := requestID(logger)(requestLogger(recoverer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("boom")
	}))))

	chain.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/v1/ans/registered-agents", nil))

	out := logs.String()
	if !strings.Contains(out, "request failed") {
		t.Errorf("expected request-failed line on panic; got %s", out)
	}
	if !strings.Contains(out, `"status":500`) {
		t.Errorf("expected 500 status in request line; got %s", out)
	}
}

func TestAudit_LogsPanicAs500(t *testing.T) {
	logger, logs := bufLogger()
	chain := requestID(logger)(audit(recoverer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("boom")
	}))))

	chain.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/v1/internal/agents/import", strings.NewReader(`{"agents":[]}`)))

	out := logs.String()
	if !strings.Contains(out, `"admin import"`) {
		t.Errorf("expected audit line on panic; got %s", out)
	}
	if !strings.Contains(out, `"status":500`) {
		t.Errorf("expected 500 status in audit line; got %s", out)
	}
	if !strings.Contains(out, `"outcome":"rejected"`) {
		t.Errorf("expected rejected outcome on panic; got %s", out)
	}
}

func TestRecoverer_PanicBecomes500(t *testing.T) {
	logger, logs := bufLogger()
	chain := requestID(logger)(recoverer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("boom")
	})))

	rec := httptest.NewRecorder()
	chain.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
		t.Errorf("Content-Type = %q, want application/problem+json", ct)
	}
	if !strings.Contains(logs.String(), "panic recovered") {
		t.Errorf("expected a panic-recovered log; got %s", logs.String())
	}
}

func TestRequestLogger_ErrorLevelFor5xx(t *testing.T) {
	logger, logs := bufLogger()
	chain := requestID(logger)(requestLogger(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		web.WriteProblem(w, errors.New("infra failure")) // unknown error → 500
	})))

	rec := httptest.NewRecorder()
	chain.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/ans/registered-agents", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	out := logs.String()
	if !strings.Contains(out, `"level":"ERROR"`) || !strings.Contains(out, "request failed") {
		t.Errorf("expected an ERROR request-failed line; got %s", out)
	}
}

func TestRequestLogger_InfoLevelFor2xx(t *testing.T) {
	logger, logs := bufLogger()
	chain := requestID(logger)(requestLogger(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		web.WriteJSON(w, http.StatusOK, map[string]string{"ok": "yes"})
	})))

	rec := httptest.NewRecorder()
	chain.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/ans/registered-agents", nil))

	if !strings.Contains(logs.String(), "request served") || !strings.Contains(logs.String(), `"level":"INFO"`) {
		t.Errorf("expected an INFO request-served line; got %s", logs.String())
	}
}

// The request log surfaces the query string alongside the route so an operator
// can see which profile (and other params) a request carried (design §5.6).
func TestRequestLogger_LogsQueryString(t *testing.T) {
	logger, logs := bufLogger()
	chain := requestID(logger)(requestLogger(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		web.WriteJSON(w, http.StatusOK, map[string]string{"ok": "yes"})
	})))

	rec := httptest.NewRecorder()
	chain.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/ans/registered-agents/agent-001?profile=identity-strict", nil))

	out := logs.String()
	if !strings.Contains(out, `"route":"/v1/ans/registered-agents/agent-001"`) {
		t.Errorf("expected route field without the query string; got %s", out)
	}
	if !strings.Contains(out, `"query":"profile=identity-strict"`) {
		t.Errorf("expected query field carrying the profile param; got %s", out)
	}
}

// A request with no query string still logs an (empty) query field rather than
// omitting it, keeping the line shape stable for log consumers.
func TestRequestLogger_EmptyQueryIsStillLogged(t *testing.T) {
	logger, logs := bufLogger()
	chain := requestID(logger)(requestLogger(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		web.WriteJSON(w, http.StatusOK, map[string]string{"ok": "yes"})
	})))

	rec := httptest.NewRecorder()
	chain.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/ans/registered-agents", nil))

	if !strings.Contains(logs.String(), `"query":""`) {
		t.Errorf("expected an empty query field; got %s", logs.String())
	}
}

// The audit middleware runs before adminAuth, so it must not buffer an
// arbitrarily large request body from an unauthenticated caller. A body over
// the cap returns 413 without reaching the handler, and the audit line still
// fires so the attempt is observable.
func TestAudit_CapsRequestBodySize(t *testing.T) {
	logger, logs := bufLogger()
	handlerCalled := false
	chain := requestID(logger)(audit(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		handlerCalled = true
	})))

	big := strings.Repeat("x", maxAdminBodyBytes+1)
	body := `{"agents":["` + big + `"]}`
	r := httptest.NewRequest(http.MethodPost, "/v1/internal/agents/import", strings.NewReader(body))
	rec := httptest.NewRecorder()
	chain.ServeHTTP(rec, r)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want 413", rec.Code)
	}
	if handlerCalled {
		t.Errorf("handler should not run once cap is exceeded")
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
		t.Errorf("Content-Type = %q, want application/problem+json", ct)
	}
	if !strings.Contains(logs.String(), `"admin import"`) {
		t.Errorf("expected audit line even on 413; got %s", logs.String())
	}
}

// TestAudit_ReadsBatchSizeFromAuditCtx exercises the new source of the
// batchSize log field: the audit middleware installs a per-request
// auditctx.Info, the handler reports the count it accepted via that Info,
// and the deferred audit line reads it. This replaces the older
// peekBatchSize approach that re-parsed the request body just to log a
// number.
func TestAudit_ReadsBatchSizeFromAuditCtx(t *testing.T) {
	logger, logs := bufLogger()
	// A handler that reports 7 accepted rows via auditctx and returns 200.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if info := auditctx.From(r.Context()); info != nil {
			info.Accepted = 7
		}
		w.WriteHeader(http.StatusOK)
	})
	chain := requestID(logger)(audit(handler))

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/v1/internal/agents/import", strings.NewReader(`{"agents":[]}`))
	chain.ServeHTTP(rec, r)

	if !strings.Contains(logs.String(), `"batchSize":7`) {
		t.Errorf("audit line should carry batchSize:7 from handler, got %s", logs.String())
	}
}

// TestAudit_BatchSizeZeroWhenHandlerDoesNotReport guards the "no handler
// reported" case — a request that never reaches the import path (e.g. 401)
// logs batchSize:0 rather than a spurious count.
func TestAudit_BatchSizeZeroWhenHandlerDoesNotReport(t *testing.T) {
	logger, logs := bufLogger()
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	chain := requestID(logger)(audit(handler))

	rec := httptest.NewRecorder()
	chain.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/internal/agents/import", strings.NewReader(`{}`)))

	if !strings.Contains(logs.String(), `"batchSize":0`) {
		t.Errorf("audit line should carry batchSize:0 when handler does not report, got %s", logs.String())
	}
}

// TestRequestID_EchoesValidInboundID asserts a well-formed inbound
// X-Request-Id is preserved on the response so distributed correlation
// works, and TestRequestID_RejectsMalformed exercises the charset/length
// gate against inputs a hostile or buggy client might send.
func TestRequestID_EchoesValidInboundID(t *testing.T) {
	logger, _ := bufLogger()
	chain := requestID(logger)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	valid := "aB3-1234_5678_defG"
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set(requestIDHeader, valid)
	rec := httptest.NewRecorder()
	chain.ServeHTTP(rec, r)
	if got := rec.Header().Get(requestIDHeader); got != valid {
		t.Errorf("echoed X-Request-Id = %q, want %q", got, valid)
	}
}

func TestRequestID_RejectsMalformedIDs(t *testing.T) {
	tooLong := strings.Repeat("a", maxRequestIDLen+1)
	bad := []string{
		"has space",
		"has\r\ncrlf",        // control chars — response-splitting defense
		"has\ttab",           // other whitespace
		`quoted"value`,       // quote
		"<script>",           // angle brackets
		tooLong,              // over the length cap
		"café",               // non-ASCII
		string([]byte{0x00}), // NUL
	}

	for _, in := range bad {
		t.Run(in, func(t *testing.T) {
			logger, _ := bufLogger()
			chain := requestID(logger)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.Header.Set(requestIDHeader, in)
			rec := httptest.NewRecorder()
			chain.ServeHTTP(rec, r)
			got := rec.Header().Get(requestIDHeader)
			if got == in {
				t.Errorf("malformed X-Request-Id %q was echoed verbatim; want a freshly minted ID", in)
			}
			if got == "" {
				t.Errorf("expected a minted X-Request-Id when input is rejected, got empty")
			}
			// Minted IDs are 32-char lowercase hex.
			if len(got) != 32 {
				t.Errorf("minted ID length = %d, want 32 (hex-encoded 16 bytes)", len(got))
			}
		})
	}
}
