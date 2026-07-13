package hydrator_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/agentnameservice/agent-trust-discovery/internal/hydrator"
	"github.com/agentnameservice/agent-trust-discovery/internal/tlevent"
)

type capturedReq struct {
	path string
	body []byte
	auth string
}

func recordingServer(t *testing.T, status int) (string, *[]capturedReq) {
	t.Helper()
	var (
		mu   sync.Mutex
		reqs []capturedReq
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		reqs = append(reqs, capturedReq{path: r.URL.Path, body: b, auth: r.Header.Get("Authorization")})
		mu.Unlock()
		if status == http.StatusOK {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"imported":1}`))
			return
		}
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"code":"INVALID_SIGNAL_VALUE"}`))
	}))
	t.Cleanup(srv.Close)
	return srv.URL, &reqs
}

func sampleEvent() tlevent.Event {
	return tlevent.Event{
		ANSID:       "agent-001",
		Status:      "ACTIVE",
		ProviderID:  "godaddy",
		FirstSeen:   "2025-12-23T10:00:00Z",
		LastUpdated: "2026-05-28T08:00:00Z",
		Agent: tlevent.Agent{
			Host: "booking.example.com", Version: "v1.0.0", Name: "Booking",
			Description: "Hotel booking agent",
			Tags:        []string{"travel"},
			Endpoints: []tlevent.Endpoint{
				{Protocol: "A2A", Transport: "HTTP"},
				{Protocol: "MCP", Transport: "HTTP"},
			},
		},
		Attestations: tlevent.Attestations{
			ServerCert:            tlevent.CertAttestation{Fingerprint: "SHA256:server"},
			IdentityCert:          tlevent.CertAttestation{Fingerprint: "SHA256:identity"},
			DNSRecordsProvisioned: tlevent.DNSRecords{ANS: "v=ans1; ok", ANSBadge: "v=badge1"},
		},
	}
}

func decodeAgents(t *testing.T, body []byte) []map[string]any {
	t.Helper()
	var req struct {
		Agents []map[string]any `json:"agents"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		t.Fatalf("decode agents: %v; body=%s", err, body)
	}
	return req.Agents
}

func decodeObs(t *testing.T, body []byte) []map[string]any {
	t.Helper()
	var req struct {
		Observations []map[string]any `json:"observations"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		t.Fatalf("decode observations: %v; body=%s", err, body)
	}
	return req.Observations
}

func TestRun_MockImportsAgentsThenObservations(t *testing.T) {
	url, reqs := recordingServer(t, http.StatusOK)
	h := hydrator.New(hydrator.Config{BaseURL: url, AIMID: "did:web:demo-aim.local"}, nil)

	obs := []hydrator.ObservationFile{{
		AgentID: "agent-001",
		Observations: []hydrator.ObservationEntry{
			{SignalID: "certtype", ObservedAt: "2026-05-28T08:00:00Z", Value: map[string]any{"type": "DV"}},
			{SignalID: "certfingerprint.server", ObservedAt: "2026-05-28T08:00:00Z", Observed: "SHA256:server"}, // matches baseline
			{SignalID: "dnsrecord.ans", ObservedAt: "2026-05-28T08:00:00Z", Observed: "v=ans1; TAMPERED"},       // mismatch
		},
	}}

	summary, err := h.Run(context.Background(), []tlevent.Event{sampleEvent()}, obs, true)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if summary.AgentsImported != 1 || summary.ObservationsImported != 3 {
		t.Errorf("summary = %+v, want 1 agent / 3 obs", summary)
	}

	if len(*reqs) != 2 {
		t.Fatalf("got %d requests, want 2 (agents then observations)", len(*reqs))
	}
	// Ordering: agents before observations (§6.5 rule 1).
	if (*reqs)[0].path != "/v1/internal/agents/import" || (*reqs)[1].path != "/v1/internal/observations/import" {
		t.Fatalf("request order = %q, %q", (*reqs)[0].path, (*reqs)[1].path)
	}

	// Agent projection.
	agents := decodeAgents(t, (*reqs)[0].body)
	a := agents[0]
	if a["agentId"] != "agent-001" {
		t.Errorf("agentId = %v", a["agentId"])
	}
	if a["dnsName"] != "ans://v1.0.0.booking.example.com" {
		t.Errorf("dnsName = %v", a["dnsName"])
	}
	if a["displayName"] != "Booking" {
		t.Errorf("displayName = %v", a["displayName"])
	}
	protocols := toStrings(a["protocols"])
	if len(protocols) != 2 || protocols[0] != "A2A" || protocols[1] != "MCP" {
		t.Errorf("protocols = %v, want [A2A MCP] from endpoints", protocols)
	}

	// Observation projection: raw forwarded, drift verdicts computed.
	obsWire := decodeObs(t, (*reqs)[1].body)
	bySignal := map[string]map[string]any{}
	for _, o := range obsWire {
		bySignal[o["signalId"].(string)] = o
	}

	raw := bySignal["certtype"]["value"].(map[string]any)
	if raw["type"] != "DV" {
		t.Errorf("raw certtype value = %v, want type DV", raw)
	}

	server := bySignal["certfingerprint.server"]["value"].(map[string]any)
	if server["matched"] != true || server["expected"] != "SHA256:server" || server["expectedSource"] != "tl_attestation" || server["observedSource"] != "fixture" {
		t.Errorf("server drift verdict = %v", server)
	}

	dns := bySignal["dnsrecord.ans"]["value"].(map[string]any)
	if dns["matched"] != false || dns["observed"] != "v=ans1; TAMPERED" {
		t.Errorf("dns drift verdict = %v, want matched=false", dns)
	}

	// Provenance attached.
	prov, ok := bySignal["certtype"]["provenance"].(map[string]any)
	if !ok || prov["aimId"] != "did:web:demo-aim.local" {
		t.Errorf("provenance = %v, want aimId did:web:demo-aim.local", bySignal["certtype"]["provenance"])
	}
}

func TestRun_RealModeImportsAgentsOnly(t *testing.T) {
	url, reqs := recordingServer(t, http.StatusOK)
	h := hydrator.New(hydrator.Config{BaseURL: url}, nil)

	summary, err := h.Run(context.Background(), []tlevent.Event{sampleEvent()},
		[]hydrator.ObservationFile{{AgentID: "agent-001", Observations: []hydrator.ObservationEntry{{SignalID: "certtype", ObservedAt: "2026-05-28T08:00:00Z", Value: map[string]any{"type": "DV"}}}}}, false)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if summary.ObservationsImported != 0 {
		t.Errorf("real mode imported %d observations, want 0", summary.ObservationsImported)
	}
	if len(*reqs) != 1 || (*reqs)[0].path != "/v1/internal/agents/import" {
		t.Errorf("real mode made %d requests; want only the agents import", len(*reqs))
	}
}

func TestRun_SetsAuthorizationWhenKeyed(t *testing.T) {
	url, reqs := recordingServer(t, http.StatusOK)
	h := hydrator.New(hydrator.Config{BaseURL: url, AdminKey: "s3cret"}, nil)
	if _, err := h.Run(context.Background(), []tlevent.Event{sampleEvent()}, nil, true); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if (*reqs)[0].auth != "Bearer s3cret" {
		t.Errorf("Authorization = %q, want Bearer s3cret", (*reqs)[0].auth)
	}
}

func TestRun_StopsOnRejection(t *testing.T) {
	url, _ := recordingServer(t, http.StatusUnprocessableEntity)
	h := hydrator.New(hydrator.Config{BaseURL: url}, nil)
	_, err := h.Run(context.Background(), []tlevent.Event{sampleEvent()}, nil, true)
	if err == nil {
		t.Fatal("expected Run to surface a non-200 import (honor INVALID_SIGNAL_VALUE)")
	}
}

func TestRun_TransportError(t *testing.T) {
	// Nothing is listening on this port → client.Do fails → Run surfaces it.
	h := hydrator.New(hydrator.Config{BaseURL: "http://127.0.0.1:1"}, nil)
	if _, err := h.Run(context.Background(), []tlevent.Event{sampleEvent()}, nil, true); err == nil {
		t.Fatal("expected a transport error")
	}
}

func TestRun_ObservationsImportRejected(t *testing.T) {
	// Agents accepted, observations rejected → Run surfaces the second failure.
	var n int
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		n++
		first := n == 1
		mu.Unlock()
		if first {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"imported":1}`))
			return
		}
		w.WriteHeader(http.StatusUnprocessableEntity)
	}))
	t.Cleanup(srv.Close)

	h := hydrator.New(hydrator.Config{BaseURL: srv.URL}, nil)
	obs := []hydrator.ObservationFile{{AgentID: "agent-001", Observations: []hydrator.ObservationEntry{
		{SignalID: "certtype", ObservedAt: "2026-05-28T08:00:00Z", Value: map[string]any{"type": "DV"}},
	}}}
	if _, err := h.Run(context.Background(), []tlevent.Event{sampleEvent()}, obs, true); err == nil {
		t.Fatal("expected the observations import rejection to surface")
	}
}

func toStrings(v any) []string {
	arr, _ := v.([]any)
	out := make([]string, len(arr))
	for i, e := range arr {
		out[i], _ = e.(string)
	}
	return out
}
