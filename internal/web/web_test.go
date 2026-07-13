package web_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/agentnameservice/agent-trust-discovery/internal/ctxlog"
	"github.com/agentnameservice/agent-trust-discovery/internal/web"
)

func TestWriteJSON(t *testing.T) {
	rec := httptest.NewRecorder()

	web.WriteJSON(rec, http.StatusOK, map[string]string{"hello": "world"})

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	var got map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("body not JSON: %v", err)
	}
	if got["hello"] != "world" {
		t.Errorf("body = %v, want hello=world", got)
	}
}

func TestWriteJSON_NilValueWritesStatusOnly(t *testing.T) {
	rec := httptest.NewRecorder()

	web.WriteJSON(rec, http.StatusNoContent, nil)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
	if rec.Body.Len() != 0 {
		t.Errorf("body = %q, want empty", rec.Body.String())
	}
}

func TestError_ErrorString(t *testing.T) {
	e := web.NewError(http.StatusUnprocessableEntity, "AGENT_NOT_FOUND", "agent \"x\" not found")
	msg := e.Error()
	if msg == "" {
		t.Fatal("Error() returned empty string")
	}
	// The string must carry both the code and the detail so logs are useful.
	for _, want := range []string{"AGENT_NOT_FOUND", "not found"} {
		if !containsSub(msg, want) {
			t.Errorf("Error() = %q, missing %q", msg, want)
		}
	}
}

func TestNewError_Fields(t *testing.T) {
	e := web.NewError(http.StatusBadRequest, "INVALID_REQUEST", "bad")
	if e.Status != http.StatusBadRequest || e.Code != "INVALID_REQUEST" || e.Detail != "bad" {
		t.Errorf("NewError fields = %+v", e)
	}
}

func TestWriteProblem_TypedError(t *testing.T) {
	rec := httptest.NewRecorder()
	err := web.NewError(http.StatusUnprocessableEntity, "UNKNOWN_SIGNAL", "signal \"foo\" not registered")

	web.WriteProblem(rec, err)

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
		t.Errorf("Content-Type = %q, want application/problem+json", ct)
	}
	var p web.Problem
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatalf("body not JSON: %v", err)
	}
	if p.Type != "about:blank" {
		t.Errorf("type = %q, want about:blank", p.Type)
	}
	if p.Status != http.StatusUnprocessableEntity {
		t.Errorf("status = %d, want 422", p.Status)
	}
	if p.Code != "UNKNOWN_SIGNAL" {
		t.Errorf("code = %q, want UNKNOWN_SIGNAL", p.Code)
	}
	if p.Title != http.StatusText(http.StatusUnprocessableEntity) {
		t.Errorf("title = %q, want %q", p.Title, http.StatusText(http.StatusUnprocessableEntity))
	}
	if p.Detail != "signal \"foo\" not registered" {
		t.Errorf("detail = %q", p.Detail)
	}
}

func TestWriteProblem_WrappedTypedError(t *testing.T) {
	rec := httptest.NewRecorder()
	base := web.NewError(http.StatusBadRequest, "INVALID_REQUEST", "bad body")
	wrapped := fmt.Errorf("decode failed: %w", base)

	web.WriteProblem(rec, wrapped)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (errors.As should unwrap)", rec.Code)
	}
	var p web.Problem
	_ = json.Unmarshal(rec.Body.Bytes(), &p)
	if p.Code != "INVALID_REQUEST" {
		t.Errorf("code = %q, want INVALID_REQUEST", p.Code)
	}
}

func TestWriteProblem_UnknownErrorIs500AndDoesNotLeak(t *testing.T) {
	rec := httptest.NewRecorder()
	secret := errors.New("sqlite: disk image is malformed at /var/secret/path")

	web.WriteProblem(rec, secret)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
		t.Errorf("Content-Type = %q, want application/problem+json", ct)
	}
	var p web.Problem
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatalf("body not JSON: %v", err)
	}
	if p.Status != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", p.Status)
	}
	// The internal error string must NOT be surfaced to the client.
	if containsSub(p.Detail, "secret") || containsSub(p.Detail, "sqlite") {
		t.Errorf("detail leaks internal error: %q", p.Detail)
	}
	if p.Title != http.StatusText(http.StatusInternalServerError) {
		t.Errorf("title = %q, want %q", p.Title, http.StatusText(http.StatusInternalServerError))
	}
}

// WriteProblemCtx must log the wrapped cause via the request-scoped logger so a
// generic 500 is diagnosable (design §5.6). The client body still hides the
// cause; only the log line surfaces it.
func TestWriteProblemCtx_LogsWrappedCauseOn500(t *testing.T) {
	buf := &strings.Builder{}
	logger := slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelError}))
	ctx := ctxlog.With(context.Background(), logger.With("requestId", "test-req"))

	rec := httptest.NewRecorder()
	secret := errors.New("sqlite: disk image is malformed at /var/secret/path")

	web.WriteProblemCtx(ctx, rec, secret)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	var p web.Problem
	_ = json.Unmarshal(rec.Body.Bytes(), &p)
	if containsSub(p.Detail, "secret") {
		t.Errorf("client body leaks: %q", p.Detail)
	}
	// The log line MUST contain the underlying cause and the requestId.
	out := buf.String()
	if !containsSub(out, "sqlite: disk image is malformed") {
		t.Errorf("log line missing wrapped cause: %q", out)
	}
	if !containsSub(out, `"requestId":"test-req"`) {
		t.Errorf("log line missing requestId correlation: %q", out)
	}
}

// WriteProblemCtx must NOT log when the error is a *web.Error (4xx are
// intentional, not something to alarm operators about).
func TestWriteProblemCtx_DoesNotLogTypedErrors(t *testing.T) {
	buf := &strings.Builder{}
	logger := slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelError}))
	ctx := ctxlog.With(context.Background(), logger)

	rec := httptest.NewRecorder()
	web.WriteProblemCtx(ctx, rec, web.NewError(http.StatusBadRequest, "INVALID_REQUEST", "bad"))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if buf.Len() != 0 {
		t.Errorf("expected no log line for typed 4xx; got %q", buf.String())
	}
}

// A future constructor that hands WriteProblem an out-of-range status (0, a
// 2xx, or an unknown 6xx) must never render an empty Problem title or panic
// net/http.WriteHeader. sanitizeErrorStatus clamps to 500 for anything outside
// 400-599; verify at the WriteProblem boundary because that's where the
// stdlib would panic without the clamp.
func TestWriteProblem_ClampsOutOfRangeStatus(t *testing.T) {
	cases := []struct {
		name       string
		status     int
		wantStatus int
	}{
		{"zero → 500", 0, http.StatusInternalServerError},
		{"success is not an error → 500", http.StatusOK, http.StatusInternalServerError},
		{"redirect is not an error → 500", http.StatusFound, http.StatusInternalServerError},
		{"above 599 → 500", 999, http.StatusInternalServerError},
		{"400 preserved", http.StatusBadRequest, http.StatusBadRequest},
		{"418 preserved", http.StatusTeapot, http.StatusTeapot},
		{"503 preserved", http.StatusServiceUnavailable, http.StatusServiceUnavailable},
		{"599 preserved (upper boundary)", 599, 599},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			web.WriteProblem(rec, web.NewError(tc.status, "SOMETHING", "detail"))

			if rec.Code != tc.wantStatus {
				t.Errorf("WriteHeader status = %d, want %d", rec.Code, tc.wantStatus)
			}
			var p web.Problem
			if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
				t.Fatalf("body not JSON: %v", err)
			}
			if p.Status != tc.wantStatus {
				t.Errorf("body status = %d, want %d", p.Status, tc.wantStatus)
			}
		})
	}
}

// The clamp exists so a future NewError call with a stdlib-registered but
// non-error code (e.g. 200) can't render an empty title on the wire. After
// clamping to 500, the title must be the registered "Internal Server Error"
// text, not "OK".
func TestWriteProblem_ClampReplacesRedirectTitle(t *testing.T) {
	rec := httptest.NewRecorder()
	web.WriteProblem(rec, web.NewError(http.StatusOK, "BUG", "should not render as success"))

	var p web.Problem
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatalf("body not JSON: %v", err)
	}
	if p.Title != http.StatusText(http.StatusInternalServerError) {
		t.Errorf("title = %q, want %q — clamp did not rewrite the title alongside the status",
			p.Title, http.StatusText(http.StatusInternalServerError))
	}
}

func containsSub(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
