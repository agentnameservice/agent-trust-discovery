package server_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/agentnameservice/agent-trust-discovery/internal/config"
	"github.com/agentnameservice/agent-trust-discovery/internal/server"
)

const (
	agentBody = `{"agents":[{"agentId":"a1","dnsName":"ans://v1.0.0.a1.example.com","displayName":"A1","status":"ACTIVE","firstSeen":"2025-01-01T00:00:00Z","lastUpdated":"2026-01-01T00:00:00Z"}]}`
	obsBody   = `{"observations":[{"agentId":"a1","signalId":"certtype","observedAt":"2026-05-28T08:00:00Z","value":{"type":"DV"}}]}`
)

func buildServer(t *testing.T, requireKey bool, key string) (http.Handler, *strings.Builder) {
	t.Helper()
	logs := &strings.Builder{}
	logger := slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelInfo}))
	cfg := config.Config{
		ListenAddr:      ":0",
		DBPath:          ":memory:",
		AdminRequireKey: requireKey,
		AdminKey:        key,
		LogLevel:        "info",
		Classify:        config.Classify{Untrusted: 20, Transactional: 50, Fiduciary: 80, IdentityFiduciary: 90},
	}
	h, db, err := server.Build(context.Background(), cfg, "../../config/default-profile.yaml", "../../config/profiles", logger)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return h, logs
}

func do(h http.Handler, method, target, body, auth string) *httptest.ResponseRecorder {
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, target, nil)
	} else {
		r = httptest.NewRequest(method, target, strings.NewReader(body))
	}
	if auth != "" {
		r.Header.Set("Authorization", auth)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func TestBuild_BootFailsOnEmptyAdminKey(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(&strings.Builder{}, nil))
	cfg := config.Config{DBPath: ":memory:", AdminRequireKey: true, AdminKey: ""}
	_, db, err := server.Build(context.Background(), cfg, "../../config/default-profile.yaml", "../../config/profiles", logger)
	if err == nil {
		if db != nil {
			_ = db.Close()
		}
		t.Fatal("expected boot failure when requireKey=true and key is empty")
	}
}

func TestBuild_BootFailsOnBadProfilePath(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(&strings.Builder{}, nil))
	cfg := config.Config{DBPath: ":memory:", AdminRequireKey: false}
	_, _, err := server.Build(context.Background(), cfg, "/no/such/profile.yaml", "/no/such/dir", logger)
	if err == nil {
		t.Fatal("expected boot failure when profiles cannot be loaded")
	}
}

func TestBuild_BootFailsOnUnopenableDBPath(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(&strings.Builder{}, nil))
	// A path whose parent cannot be created (/dev/null is not a directory).
	cfg := config.Config{DBPath: "/dev/null/cannot/ans.db", AdminRequireKey: false}
	_, _, err := server.Build(context.Background(), cfg, "../../config/default-profile.yaml", "../../config/profiles", logger)
	if err == nil {
		t.Fatal("expected boot failure when the store cannot be opened")
	}
}

func TestHealth(t *testing.T) {
	h, _ := buildServer(t, false, "")
	rec := do(h, http.MethodGet, "/health", "", "")
	if rec.Code != http.StatusOK || rec.Body.String() != "ok" {
		t.Errorf("health = %d %q, want 200 ok", rec.Code, rec.Body.String())
	}
}

func TestImportSearchDetailFlow(t *testing.T) {
	h, _ := buildServer(t, false, "")

	if rec := do(h, http.MethodPost, "/v1/internal/agents/import", agentBody, ""); rec.Code != http.StatusOK {
		t.Fatalf("import agents = %d; body=%s", rec.Code, rec.Body.String())
	}
	if rec := do(h, http.MethodPost, "/v1/internal/observations/import", obsBody, ""); rec.Code != http.StatusOK {
		t.Fatalf("import observations = %d; body=%s", rec.Code, rec.Body.String())
	}

	// Search finds the imported agent.
	srec := do(h, http.MethodGet, "/v1/ans/registered-agents", "", "")
	if srec.Code != http.StatusOK {
		t.Fatalf("search = %d; body=%s", srec.Code, srec.Body.String())
	}
	var results struct {
		Items []map[string]any `json:"items"`
	}
	_ = json.Unmarshal(srec.Body.Bytes(), &results)
	if len(results.Items) != 1 || results.Items[0]["agentId"] != "a1" {
		t.Errorf("search items = %v, want [a1]", results.Items)
	}

	// Detail embeds the trust evaluation (identity 40 for the DV cert).
	drec := do(h, http.MethodGet, "/v1/ans/registered-agents/a1", "", "")
	if drec.Code != http.StatusOK {
		t.Fatalf("detail = %d; body=%s", drec.Code, drec.Body.String())
	}
	var detail struct {
		TrustEvaluation struct {
			TrustVector struct {
				Identity int `json:"identity"`
			} `json:"trustVector"`
		} `json:"trustEvaluation"`
	}
	_ = json.Unmarshal(drec.Body.Bytes(), &detail)
	if detail.TrustEvaluation.TrustVector.Identity != 40 {
		t.Errorf("identity = %d, want 40", detail.TrustEvaluation.TrustVector.Identity)
	}
}

func TestDetail404(t *testing.T) {
	h, _ := buildServer(t, false, "")
	rec := do(h, http.MethodGet, "/v1/ans/registered-agents/ghost", "", "")
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404; body=%s", rec.Code, rec.Body.String())
	}
}

func TestAdminAuthEnforced(t *testing.T) {
	h, _ := buildServer(t, true, "s3cret")

	if rec := do(h, http.MethodPost, "/v1/internal/agents/import", agentBody, ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("no-key import = %d, want 401", rec.Code)
	}
	if rec := do(h, http.MethodPost, "/v1/internal/agents/import", agentBody, "Bearer s3cret"); rec.Code != http.StatusOK {
		t.Errorf("keyed import = %d, want 200", rec.Code)
	}
}

func TestRequestID_EchoAndPropagate(t *testing.T) {
	h, _ := buildServer(t, false, "")

	// Minted when absent.
	rec := do(h, http.MethodGet, "/health", "", "")
	if rec.Header().Get("X-Request-Id") == "" {
		t.Error("expected a minted X-Request-Id")
	}

	// Honored when present.
	r := httptest.NewRequest(http.MethodGet, "/health", nil)
	r.Header.Set("X-Request-Id", "trace-abc")
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, r)
	if got := rec2.Header().Get("X-Request-Id"); got != "trace-abc" {
		t.Errorf("X-Request-Id = %q, want trace-abc", got)
	}
}

func TestAuditLineEmittedPerImport(t *testing.T) {
	h, logs := buildServer(t, false, "")

	// A malformed batch is still audited (accepted or rejected).
	_ = do(h, http.MethodPost, "/v1/internal/agents/import", `{`, "")
	if !strings.Contains(logs.String(), "admin import") || !strings.Contains(logs.String(), "batchSize") {
		t.Errorf("expected an audit line per import; logs=%s", logs.String())
	}
}

func TestUnmountedRouteIs404(t *testing.T) {
	h, _ := buildServer(t, false, "")
	rec := do(h, http.MethodGet, "/v1/ans/does-not-exist", "", "")
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 (unimplemented = unregistered)", rec.Code)
	}
}

func TestBootWarnsWhenAuthDisabled(t *testing.T) {
	_, logs := buildServer(t, false, "")
	if !strings.Contains(logs.String(), "unauthenticated") {
		t.Errorf("expected a boot warning about unauthenticated routes; logs=%s", logs.String())
	}
}
