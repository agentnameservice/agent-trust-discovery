package prober_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/agentnameservice/agent-trust-discovery/internal/prober"
	"github.com/agentnameservice/agent-trust-discovery/internal/scoring/signals"
	"github.com/agentnameservice/agent-trust-discovery/internal/tlevent"
)

// mockProbe returns canned live-probe results.
type mockProbe struct {
	cert    prober.CertResult
	certErr error
	txt     map[string]string
	txtErr  error
	caa     bool
}

func (m mockProbe) Cert(context.Context, string) (prober.CertResult, error) {
	return m.cert, m.certErr
}
func (m mockProbe) TXT(_ context.Context, name string) (string, error) {
	if m.txtErr != nil {
		return "", m.txtErr
	}
	return m.txt[name], nil
}
func (m mockProbe) CAA(context.Context, string) (bool, error) { return m.caa, nil }

func recordingServer(t *testing.T, status int) (string, *[]byte) {
	t.Helper()
	var (
		mu   sync.Mutex
		last []byte
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		last = b
		mu.Unlock()
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	return srv.URL, &last
}

func sampleEvent() tlevent.Event {
	return tlevent.Event{
		ANSID: "agent-001", Status: "ACTIVE",
		FirstSeen: "2025-12-23T10:00:00Z", LastUpdated: "2026-05-28T08:00:00Z",
		Agent: tlevent.Agent{Host: "booking.example.com", Version: "v1.0.0", Name: "Booking"},
		Attestations: tlevent.Attestations{
			ServerCert:            tlevent.CertAttestation{Fingerprint: "SHA256:sealedserver"},
			DNSRecordsProvisioned: tlevent.DNSRecords{ANS: "v=ans1; ok", ANSBadge: "v=badge1"},
		},
	}
}

func decodeObs(t *testing.T, body []byte) map[string]map[string]any {
	t.Helper()
	var req struct {
		Observations []map[string]any `json:"observations"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		t.Fatalf("decode: %v; body=%s", err, body)
	}
	out := map[string]map[string]any{}
	for _, o := range req.Observations {
		out[o["signalId"].(string)] = o
	}
	return out
}

func TestRunOnce_LiveProbesMatch(t *testing.T) {
	url, last := recordingServer(t, http.StatusOK)
	p := prober.New(prober.Config{BaseURL: url, AIMID: "did:web:demo-prober.local"}, mockProbe{
		cert: prober.CertResult{Fingerprint: "SHA256:sealedserver", Type: "EV"},
		txt:  map[string]string{"_ans.booking.example.com": "v=ans1; ok", "_ans-badge.booking.example.com": "v=badge1"},
		caa:  true,
	}, nil)

	summary, err := p.RunOnce(context.Background(), []tlevent.Event{sampleEvent()})
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if summary.ObservationsEmitted == 0 {
		t.Fatal("no observations emitted")
	}

	obs := decodeObs(t, *last)

	// Raw certtype reflects the probed tier.
	if obs["certtype"]["value"].(map[string]any)["type"] != "EV" {
		t.Errorf("certtype = %v, want EV", obs["certtype"]["value"])
	}
	// Server-cert drift verdict matches the sealed baseline, sourced from the handshake.
	srv := obs["certfingerprint.server"]["value"].(map[string]any)
	if srv["matched"] != true || srv["expected"] != "SHA256:sealedserver" || srv["observedSource"] != "live_tls_handshake" {
		t.Errorf("server verdict = %v", srv)
	}
	// DNS drift verdict, sourced from the live query.
	ans := obs["dnsrecord.ans"]["value"].(map[string]any)
	if ans["matched"] != true || ans["observedSource"] != "live_dns_query" {
		t.Errorf("ans verdict = %v", ans)
	}
	// dnssecurity raw carries the probed CAA (DNSSEC stubbed false in v1).
	sec := obs["dnssecurity"]["value"].(map[string]any)
	if sec["caa"] != true || sec["dnssec"] != false {
		t.Errorf("dnssecurity = %v", sec)
	}
	// Provenance tagged.
	if obs["certtype"]["provenance"].(map[string]any)["aimId"] != "did:web:demo-prober.local" {
		t.Errorf("provenance = %v", obs["certtype"]["provenance"])
	}
}

func TestRunOnce_UnreachableEmitsScoreZeroNeverSkips(t *testing.T) {
	url, last := recordingServer(t, http.StatusOK)
	p := prober.New(prober.Config{BaseURL: url}, mockProbe{
		certErr: errors.New("handshake failed"),
		txtErr:  errors.New("nxdomain"),
	}, nil)

	if _, err := p.RunOnce(context.Background(), []tlevent.Event{sampleEvent()}); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	obs := decodeObs(t, *last)

	// Unreachable must still emit observations (never a silent skip, §6.6).
	for _, id := range []string{"certtype", "certfingerprint.server", "dnsrecord.ans", "dnsrecord.ans-badge", "dnssecurity"} {
		if _, ok := obs[id]; !ok {
			t.Errorf("missing observation for %s on an unreachable agent", id)
		}
	}
	// certtype degrades to none; drift observed is empty (→ score 0 at evaluation).
	if obs["certtype"]["value"].(map[string]any)["type"] != "none" {
		t.Errorf("unreachable certtype = %v, want none", obs["certtype"]["value"])
	}
	if obs["certfingerprint.server"]["value"].(map[string]any)["observed"] != "" {
		t.Errorf("unreachable server observed = %v, want empty", obs["certfingerprint.server"]["value"])
	}
}

// A failed probe still emits a score-0 observation, but must also log a WARN
// naming the agent, host, and signal so the zero is diagnosable from logs
// rather than requiring an openssl s_client (PR #5 review).
func TestRunOnce_LogsWarnOnProbeFailure(t *testing.T) {
	url, _ := recordingServer(t, http.StatusOK)
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	p := prober.New(prober.Config{BaseURL: url, Logger: logger}, mockProbe{
		certErr: errors.New("handshake failed"),
		txtErr:  errors.New("nxdomain"),
	}, nil)

	if _, err := p.RunOnce(context.Background(), []tlevent.Event{sampleEvent()}); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "prober: probe failed") {
		t.Fatalf("expected a probe-failed WARN, got: %s", out)
	}
	// The cert failure and both DNS failures must each be named by signal.
	for _, sig := range []string{"certfingerprint.server", "dnsrecord.ans", "dnsrecord.ans-badge"} {
		if !strings.Contains(out, sig) {
			t.Errorf("probe-failed logs missing signal %q; got: %s", sig, out)
		}
	}
	// The agent host should appear so the operator can go straight to it.
	if !strings.Contains(out, sampleEvent().Agent.Host) {
		t.Errorf("probe-failed logs missing host %q; got: %s", sampleEvent().Agent.Host, out)
	}
}

// A clean pass emits no probe-failed WARN — the log line is reserved for real
// failures so it stays greppable.
func TestRunOnce_NoWarnOnCleanPass(t *testing.T) {
	url, _ := recordingServer(t, http.StatusOK)
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	ev := sampleEvent()
	p := prober.New(prober.Config{BaseURL: url, Logger: logger}, mockProbe{
		cert: prober.CertResult{Type: "OV", Fingerprint: ev.Attestations.ServerCert.Fingerprint},
		txt: map[string]string{
			"_ans." + ev.Agent.Host:       ev.Attestations.DNSRecordsProvisioned.ANS,
			"_ans-badge." + ev.Agent.Host: ev.Attestations.DNSRecordsProvisioned.ANSBadge,
		},
		caa: true,
	}, nil)

	if _, err := p.RunOnce(context.Background(), []tlevent.Event{ev}); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if strings.Contains(buf.String(), "probe failed") {
		t.Errorf("clean pass should emit no probe-failed WARN; got: %s", buf.String())
	}
}

func TestRunOnce_PostRejectionSurfaces(t *testing.T) {
	url, _ := recordingServer(t, http.StatusUnprocessableEntity)
	p := prober.New(prober.Config{BaseURL: url}, mockProbe{}, nil)
	if _, err := p.RunOnce(context.Background(), []tlevent.Event{sampleEvent()}); err == nil {
		t.Fatal("expected a non-200 import to surface as an error")
	}
}

func TestRunOnce_SetsAuthAndStampsObservedAt(t *testing.T) {
	var (
		mu   sync.Mutex
		auth string
		body []byte
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		auth = r.Header.Get("Authorization")
		body = b
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	p := prober.New(prober.Config{
		BaseURL:  srv.URL,
		AdminKey: "s3cret",
		Now:      func() string { return "2026-07-01T00:00:00Z" },
	}, mockProbe{cert: prober.CertResult{Type: "OV"}}, nil)

	if _, err := p.RunOnce(context.Background(), []tlevent.Event{sampleEvent()}); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if auth != "Bearer s3cret" {
		t.Errorf("Authorization = %q, want Bearer s3cret", auth)
	}
	obs := decodeObs(t, body)
	if obs["certtype"]["observedAt"] != "2026-07-01T00:00:00Z" {
		t.Errorf("observedAt = %v, want the injected stamp", obs["certtype"]["observedAt"])
	}
}

func TestRunOnce_TransportError(t *testing.T) {
	p := prober.New(prober.Config{BaseURL: "http://127.0.0.1:1"}, mockProbe{}, nil)
	if _, err := p.RunOnce(context.Background(), []tlevent.Event{sampleEvent()}); err == nil {
		t.Fatal("expected a transport error")
	}
}

// v1LiveProberGaps enumerates drift signals the live prober intentionally
// does NOT emit (documented in prober.go's probeAgent). Adding a new gap
// requires an explicit entry here — a new drift signal that quietly falls
// out of the emit set without being added to this map would fail
// TestRunOnce_EmitsCanonicalDriftSet.
var v1LiveProberGaps = map[string]string{
	"certfingerprint.identity": "requires the AIM identity endpoint (v2)",
}

// The live prober must emit every canonical drift signal (signals.DriftSignalIDs)
// except those explicitly listed as v1 gaps. This trap catches two failure
// modes at once: (a) a new drift signal added to the canonical registry
// without a matching emit line in probeAgent, and (b) an existing signal
// silently dropped from probeAgent (a regression).
func TestRunOnce_EmitsCanonicalDriftSet(t *testing.T) {
	url, last := recordingServer(t, http.StatusOK)
	p := prober.New(prober.Config{BaseURL: url}, mockProbe{
		cert: prober.CertResult{Fingerprint: "SHA256:x", Type: "DV"},
		txt:  map[string]string{"_ans.booking.example.com": "v=ans1", "_ans-badge.booking.example.com": "v=badge1"},
	}, nil)
	if _, err := p.RunOnce(context.Background(), []tlevent.Event{sampleEvent()}); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	obs := decodeObs(t, *last)

	for _, id := range signals.DriftSignalIDs() {
		key := string(id)
		if reason, gap := v1LiveProberGaps[key]; gap {
			if _, present := obs[key]; present {
				t.Errorf("%s is in v1 gap set (%q) but was emitted; either produce it in v1 or remove the gap entry", key, reason)
			}
			continue
		}
		if _, present := obs[key]; !present {
			t.Errorf("canonical drift signal %q was not emitted; probeAgent must cover it (or add a v1LiveProberGaps entry)", key)
		}
	}
}

func TestRunOnce_NoEventsNoPost(t *testing.T) {
	url, last := recordingServer(t, http.StatusOK)
	p := prober.New(prober.Config{BaseURL: url}, mockProbe{}, nil)
	if _, err := p.RunOnce(context.Background(), nil); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if len(*last) != 0 {
		t.Errorf("expected no POST for an empty event set, got %s", *last)
	}
}
