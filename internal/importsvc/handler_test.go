package importsvc_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/agentnameservice/agent-trust-discovery/internal/adapter/sqlitestore"
	"github.com/agentnameservice/agent-trust-discovery/internal/importsvc"
	"github.com/agentnameservice/agent-trust-discovery/internal/scoring/registry"
	"github.com/agentnameservice/agent-trust-discovery/internal/scoring/signals"
	"github.com/agentnameservice/agent-trust-discovery/internal/web"
)

func newHandler(t *testing.T) (*importsvc.Handler, *sqlitestore.DB) {
	t.Helper()
	svc, store := newService(t)
	return importsvc.NewHandler(svc), store
}

func doPost(h http.HandlerFunc, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	rec := httptest.NewRecorder()
	h(rec, req)
	return rec
}

func assertProblemCode(t *testing.T, rec *httptest.ResponseRecorder, code string) {
	t.Helper()
	if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
		t.Errorf("Content-Type = %q, want application/problem+json", ct)
	}
	var p web.Problem
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatalf("body is not problem JSON: %v; body=%s", err, rec.Body.String())
	}
	if p.Code != code {
		t.Errorf("code = %q, want %q (body=%s)", p.Code, code, rec.Body.String())
	}
}

func TestHandlerImportAgents_Happy(t *testing.T) {
	h, store := newHandler(t)
	body := `{"agents":[{"agentId":"a1","dnsName":"ans://v1.0.0.a1.example.com","displayName":"A1","providerId":"godaddy","status":"ACTIVE","protocols":["A2A","MCP"],"tags":["t"],"firstSeen":"2025-01-01T00:00:00Z","lastUpdated":"2026-01-01T00:00:00Z"}]}`

	rec := doPost(h.ImportAgents, body)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	got, found, err := store.GetAgent(context.Background(), "a1")
	if err != nil || !found {
		t.Fatalf("agent not persisted (found=%v err=%v)", found, err)
	}
	if got.DisplayName != "A1" || got.Status != "ACTIVE" || len(got.Protocols) != 2 {
		t.Errorf("agent not round-tripped: %+v", got)
	}
}

func TestHandlerImportAgents_BadRequests(t *testing.T) {
	const ts = `"firstSeen":"2025-01-01T00:00:00Z","lastUpdated":"2026-01-01T00:00:00Z"`
	cases := []struct{ name, body string }{
		{"bad json", `{`},
		{"empty batch", `{"agents":[]}`},
		{"missing agentId", `{"agents":[{"dnsName":"ans://x","displayName":"X","status":"ACTIVE",` + ts + `}]}`},
		{"missing dnsName", `{"agents":[{"agentId":"a1","displayName":"X","status":"ACTIVE",` + ts + `}]}`},
		{"missing displayName", `{"agents":[{"agentId":"a1","dnsName":"ans://x","status":"ACTIVE",` + ts + `}]}`},
		{"invalid status", `{"agents":[{"agentId":"a1","dnsName":"ans://x","displayName":"X","status":"BOGUS",` + ts + `}]}`},
		{"bad firstSeen", `{"agents":[{"agentId":"a1","dnsName":"ans://x","displayName":"X","status":"ACTIVE","firstSeen":"nope","lastUpdated":"2026-01-01T00:00:00Z"}]}`},
		{"missing lastUpdated", `{"agents":[{"agentId":"a1","dnsName":"ans://x","displayName":"X","status":"ACTIVE","firstSeen":"2025-01-01T00:00:00Z"}]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, _ := newHandler(t)
			rec := doPost(h.ImportAgents, tc.body)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
			}
			assertProblemCode(t, rec, importsvc.CodeInvalidRequest)
		})
	}
}

func TestHandlerImportObservations_HappyWithProvenance(t *testing.T) {
	h, store := newHandler(t)
	seedAgent(t, store, "a1")
	body := `{"observations":[{"agentId":"a1","signalId":"certtype","observedAt":"2026-05-28T08:00:00Z","value":{"type":"EV"},"provenance":{"aimId":"did:web:demo-aim.local","evidenceUrl":"https://demo-aim.local/f.json"}}]}`

	rec := doPost(h.ImportObservations, body)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	got, _ := store.LatestObservation(context.Background(), "a1", "certtype")
	if got == nil || got.Provenance == nil || got.Provenance.AIMID != "did:web:demo-aim.local" {
		t.Errorf("observation/provenance not round-tripped: %+v", got)
	}
}

func TestHandlerImport_ServiceErrorIs500(t *testing.T) {
	reg := registry.New()
	for _, s := range signals.BuiltIns(nil) {
		_ = reg.Register(s)
	}

	// Agents: the upsert fails → handler maps the unexpected error to 500.
	ha := importsvc.NewHandler(importsvc.New(failingStore{}, reg))
	rec := doPost(ha.ImportAgents,
		`{"agents":[{"agentId":"a1","dnsName":"ans://x","displayName":"X","status":"ACTIVE","firstSeen":"2025-01-01T00:00:00Z","lastUpdated":"2026-01-01T00:00:00Z"}]}`)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("agents: status = %d, want 500; body=%s", rec.Code, rec.Body.String())
	}

	// Observations: validation passes but the append fails → 500.
	ho := importsvc.NewHandler(importsvc.New(appendFailingStore{}, reg))
	rec2 := doPost(ho.ImportObservations,
		`{"observations":[{"agentId":"a1","signalId":"certtype","observedAt":"2026-05-28T08:00:00Z","value":{"type":"EV"}}]}`)
	if rec2.Code != http.StatusInternalServerError {
		t.Errorf("observations: status = %d, want 500; body=%s", rec2.Code, rec2.Body.String())
	}
}

func TestHandlerImportObservations_Errors(t *testing.T) {
	cases := []struct {
		name   string
		body   string
		status int
		code   string
		seed   bool
	}{
		{"bad json", `{`, http.StatusBadRequest, importsvc.CodeInvalidRequest, false},
		{"empty batch", `{"observations":[]}`, http.StatusBadRequest, importsvc.CodeInvalidRequest, false},
		{"missing agentId", `{"observations":[{"signalId":"certtype","observedAt":"2026-05-28T08:00:00Z","value":{"type":"EV"}}]}`, http.StatusBadRequest, importsvc.CodeInvalidRequest, false},
		{"missing signalId", `{"observations":[{"agentId":"a1","observedAt":"2026-05-28T08:00:00Z","value":{"type":"EV"}}]}`, http.StatusBadRequest, importsvc.CodeInvalidRequest, true},
		{"missing value", `{"observations":[{"agentId":"a1","signalId":"certtype","observedAt":"2026-05-28T08:00:00Z"}]}`, http.StatusBadRequest, importsvc.CodeInvalidRequest, true},
		{"null value", `{"observations":[{"agentId":"a1","signalId":"certtype","observedAt":"2026-05-28T08:00:00Z","value":null}]}`, http.StatusBadRequest, importsvc.CodeInvalidRequest, true},
		{"bad observedAt", `{"observations":[{"agentId":"a1","signalId":"certtype","observedAt":"nope","value":{"type":"EV"}}]}`, http.StatusBadRequest, importsvc.CodeInvalidRequest, true},
		{"agent not found", `{"observations":[{"agentId":"ghost","signalId":"certtype","observedAt":"2026-05-28T08:00:00Z","value":{"type":"EV"}}]}`, http.StatusUnprocessableEntity, importsvc.CodeAgentNotFound, false},
		{"unknown signal", `{"observations":[{"agentId":"a1","signalId":"nope","observedAt":"2026-05-28T08:00:00Z","value":{}}]}`, http.StatusUnprocessableEntity, importsvc.CodeUnknownSignal, true},
		{"derived signal", `{"observations":[{"agentId":"a1","signalId":"agentage","observedAt":"2026-05-28T08:00:00Z","value":{}}]}`, http.StatusUnprocessableEntity, importsvc.CodeInvalidSignal, true},
		{"invalid value", `{"observations":[{"agentId":"a1","signalId":"certtype","observedAt":"2026-05-28T08:00:00Z","value":{"type":"BOGUS"}}]}`, http.StatusUnprocessableEntity, importsvc.CodeInvalidSignalValue, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, store := newHandler(t)
			if tc.seed {
				seedAgent(t, store, "a1")
			}
			rec := doPost(h.ImportObservations, tc.body)
			if rec.Code != tc.status {
				t.Errorf("status = %d, want %d; body=%s", rec.Code, tc.status, rec.Body.String())
			}
			assertProblemCode(t, rec, tc.code)
		})
	}
}
