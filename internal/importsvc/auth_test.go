package importsvc_test

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/agentnameservice/agent-trust-discovery/internal/importsvc"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// okHandler returns an inner handler that records whether it ran and writes 200.
func okHandler() (http.Handler, *bool) {
	called := new(bool)
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		*called = true
		w.WriteHeader(http.StatusOK)
	})
	return h, called
}

func TestAdminAuth_CorrectKeyPasses(t *testing.T) {
	mw, err := importsvc.NewAdminAuth(importsvc.AdminAuthConfig{RequireKey: true, Key: "s3cret"}, discardLogger())
	if err != nil {
		t.Fatalf("NewAdminAuth: %v", err)
	}
	inner, called := okHandler()
	req := httptest.NewRequest(http.MethodPost, "/v1/internal/agents/import", nil)
	req.Header.Set("Authorization", "Bearer s3cret")
	rec := httptest.NewRecorder()

	mw(inner).ServeHTTP(rec, req)

	if !*called {
		t.Error("inner handler was not called with a valid key")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestAdminAuth_WrongKey401(t *testing.T) {
	mw, _ := importsvc.NewAdminAuth(importsvc.AdminAuthConfig{RequireKey: true, Key: "s3cret"}, discardLogger())
	inner, called := okHandler()
	req := httptest.NewRequest(http.MethodPost, "/v1/internal/agents/import", nil)
	req.Header.Set("Authorization", "Bearer wrong")
	rec := httptest.NewRecorder()

	mw(inner).ServeHTTP(rec, req)

	if *called {
		t.Error("inner handler must not run on a bad key")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
		t.Errorf("Content-Type = %q, want application/problem+json", ct)
	}
	if !strings.Contains(rec.Body.String(), importsvc.CodeUnauthorized) {
		t.Errorf("body missing code %q: %s", importsvc.CodeUnauthorized, rec.Body.String())
	}
}

func TestAdminAuth_MissingHeader401(t *testing.T) {
	mw, _ := importsvc.NewAdminAuth(importsvc.AdminAuthConfig{RequireKey: true, Key: "s3cret"}, discardLogger())
	inner, called := okHandler()
	req := httptest.NewRequest(http.MethodPost, "/v1/internal/agents/import", nil)
	rec := httptest.NewRecorder()

	mw(inner).ServeHTTP(rec, req)

	if *called {
		t.Error("inner handler must not run without a key")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestAdminAuth_EmptyKeyBootFails(t *testing.T) {
	_, err := importsvc.NewAdminAuth(importsvc.AdminAuthConfig{RequireKey: true, Key: ""}, discardLogger())
	if err == nil {
		t.Fatal("expected a boot-fail error when requireKey=true and key is empty (§5.3)")
	}
}

func TestAdminAuth_NilLoggerDefaulted(t *testing.T) {
	// A nil logger must be defaulted, not panic. Use the require-key success
	// path so no warning is emitted (keeps test output pristine).
	mw, err := importsvc.NewAdminAuth(importsvc.AdminAuthConfig{RequireKey: true, Key: "k"}, nil)
	if err != nil {
		t.Fatalf("NewAdminAuth: %v", err)
	}
	inner, called := okHandler()
	req := httptest.NewRequest(http.MethodPost, "/v1/internal/agents/import", nil)
	req.Header.Set("Authorization", "Bearer k")
	rec := httptest.NewRecorder()

	mw(inner).ServeHTTP(rec, req)

	if !*called {
		t.Error("inner handler not called with a nil (defaulted) logger")
	}
}

func TestAdminAuth_NoAuthPassesWithoutPerRequestWarn(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	mw, err := importsvc.NewAdminAuth(importsvc.AdminAuthConfig{RequireKey: false}, logger)
	if err != nil {
		t.Fatalf("NewAdminAuth: %v", err)
	}
	inner, called := okHandler()
	req := httptest.NewRequest(http.MethodPost, "/v1/internal/agents/import", nil) // no auth header
	rec := httptest.NewRecorder()

	mw(inner).ServeHTTP(rec, req)

	if !*called {
		t.Error("inner handler must run when auth is disabled")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	// The per-request unauthenticated WARN was removed as log noise; the boot
	// warning + audit authenticated:false field cover the posture. Assert the
	// middleware stays silent on the hot path.
	if strings.Contains(buf.String(), "unauthenticated") {
		t.Errorf("per-request unauthenticated WARN should be gone, got: %s", buf.String())
	}
}
