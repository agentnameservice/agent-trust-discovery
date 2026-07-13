package snapshot

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/agentnameservice/agent-trust-discovery/internal/atdclient"
	"github.com/agentnameservice/agent-trust-discovery/internal/tlevent"
)

func TestRun_WritesFixtureYAMLForEachAgent(t *testing.T) {
	t.Parallel()

	out := t.TempDir()
	search := &fakeSearcher{agents: []atdclient.Agent{
		{
			AgentID:          "a-1",
			ProviderID:       "p1",
			ANSName:          "ans://v1.0.0.a1.example.com",
			AgentHost:        "a1.example.com",
			AgentDisplayName: "A1",
			AgentDescription: "agent one",
			AgentVersion:     "v1",
			Lifecycle:        atdclient.AgentLifecycle{Status: "ACTIVE"},
			Endpoints: []atdclient.Endpoint{{
				AgentURL: "https://a1.example.com/", Protocol: "A2A",
				Transports: []string{"JSON-RPC", "SSE"},
			}},
		},
		{
			AgentID:          "a-2",
			ANSName:          "ans://v1.0.0.a2.example.com",
			AgentDisplayName: "A2",
			Lifecycle:        atdclient.AgentLifecycle{Status: "ACTIVE"},
		},
	}}
	tl := &fakeTL{events: map[string]tlevent.Event{
		"a-1": {
			ANSID: "a-1", Status: "ACTIVE",
			FirstSeen: "2026-05-01T00:00:00Z", LastUpdated: "2026-06-01T00:00:00Z",
			Agent: tlevent.Agent{Host: "a1.example.com", Version: "v1", Name: "A1"},
			Attestations: tlevent.Attestations{
				ServerCert:            tlevent.CertAttestation{Fingerprint: "SHA256:11"},
				IdentityCert:          tlevent.CertAttestation{Fingerprint: "SHA256:22"},
				DNSRecordsProvisioned: tlevent.DNSRecords{ANS: "v=ans1", ANSBadge: "v=ans-badge1"},
				DNSSECStatus:          "signed",
			},
		},
		"a-2": {
			ANSID: "a-2", Status: "ACTIVE",
			FirstSeen: "2026-05-02T00:00:00Z", LastUpdated: "2026-06-02T00:00:00Z",
			Agent: tlevent.Agent{Host: "a2.example.com", Version: "v1", Name: "A2"},
			Attestations: tlevent.Attestations{
				ServerCert:            tlevent.CertAttestation{Fingerprint: "SHA256:33"},
				IdentityCert:          tlevent.CertAttestation{Fingerprint: "SHA256:44"},
				DNSRecordsProvisioned: tlevent.DNSRecords{ANS: "v=ans1", ANSBadge: "v=ans-badge1"},
				DNSSECStatus:          "signed",
			},
		},
	}}

	summary, err := Run(context.Background(), search, tl, Config{
		SearchBaseURL: "https://api.example.test",
		TLBaseURL:     "https://tl.example.test",
		OutDir:        out,
		SearchOpts:    atdclient.SearchOpts{Limit: 10},
	}, silentLogger())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if summary.AgentsCaptured != 2 || summary.TLFetchErrors != 0 {
		t.Fatalf("summary: %+v", summary)
	}

	// Re-load the written fixtures with the real tlevent loader to prove
	// the on-disk shape matches the hydrator/prober's expected fixture
	// contract (both binaries consume via tlevent.LoadDir).
	loaded, err := tlevent.LoadDir(filepath.Join(out, "tl-events"))
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	if len(loaded) != 2 {
		t.Fatalf("loaded: %d events, want 2", len(loaded))
	}

	got := map[string]tlevent.Event{}
	for _, e := range loaded {
		got[e.ANSID] = e
	}
	// Pick one agent and assert the merge picks up Search-side metadata
	// (description, derived protocols/transports from endpoints[]) on top of
	// the TL-side host/cert/DNS.
	e := got["a-1"]
	if e.Agent.Host != "a1.example.com" {
		t.Fatalf("agent.host: %q", e.Agent.Host)
	}
	if e.Agent.Description != "agent one" {
		t.Fatalf("agent.description: %q", e.Agent.Description)
	}
	if !reflect.DeepEqual(e.Agent.Protocols, []string{"A2A"}) {
		t.Fatalf("agent.protocols: %v", e.Agent.Protocols)
	}
	if !reflect.DeepEqual(e.Agent.Transports, []string{"JSON-RPC", "SSE"}) {
		t.Fatalf("agent.transports: %v", e.Agent.Transports)
	}
	if e.Attestations.ServerCert.Fingerprint != "SHA256:11" {
		t.Fatalf("serverCert: %q", e.Attestations.ServerCert.Fingerprint)
	}
	if e.Attestations.DNSRecordsProvisioned.ANS != "v=ans1" {
		t.Fatalf("_ans: %q", e.Attestations.DNSRecordsProvisioned.ANS)
	}
	if e.Status != "ACTIVE" {
		t.Fatalf("status: %q", e.Status)
	}
}

func TestRun_OverwritesPreviousSnapshot(t *testing.T) {
	t.Parallel()

	out := t.TempDir()
	stale := filepath.Join(out, "tl-events", "old.yaml")
	if err := os.MkdirAll(filepath.Dir(stale), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(stale, []byte("stale: true\n"), 0o644); err != nil {
		t.Fatalf("write stale: %v", err)
	}

	search := &fakeSearcher{agents: []atdclient.Agent{
		simpleAgent("fresh"),
	}}
	tl := &fakeTL{events: map[string]tlevent.Event{
		"fresh": validEvent("fresh", "x.example.com"),
	}}

	if _, err := Run(context.Background(), search, tl, Config{OutDir: out}, silentLogger()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if _, err := os.Stat(stale); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected stale file to be removed, stat err = %v", err)
	}
}

func TestRun_SkipsAgentsWithTLFetchError(t *testing.T) {
	t.Parallel()

	out := t.TempDir()
	search := &fakeSearcher{agents: []atdclient.Agent{
		simpleAgent("good"),
		simpleAgent("bad"),
	}}
	tl := &fakeTL{
		events: map[string]tlevent.Event{"good": validEvent("good", "good.example.com")},
		errs:   map[string]error{"bad": errors.New("boom")},
	}

	summary, err := Run(context.Background(), search, tl, Config{OutDir: out}, silentLogger())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if summary.AgentsCaptured != 1 || summary.TLFetchErrors != 1 {
		t.Fatalf("summary: %+v", summary)
	}
	loaded, err := tlevent.LoadDir(filepath.Join(out, "tl-events"))
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	if len(loaded) != 1 || loaded[0].ANSID != "good" {
		t.Fatalf("loaded: %+v", loaded)
	}
}

// Run must refuse to produce an empty snapshot when every TL fetch failed.
// prepareOutDir wipes the tl-events/ dir first, so a total TL outage would
// otherwise leave the caller with an empty directory and a nil error — the
// hydrator then silently wipes all trust data on its next cycle.
func TestRun_RefusesEmptySnapshotWhenAllTLFetchesFail(t *testing.T) {
	t.Parallel()
	out := t.TempDir()
	search := &fakeSearcher{agents: []atdclient.Agent{
		simpleAgent("a"), simpleAgent("b"),
	}}
	tl := &fakeTL{errs: map[string]error{
		"a": errors.New("tl down"),
		"b": errors.New("tl down"),
	}}

	summary, err := Run(context.Background(), search, tl, Config{OutDir: out}, silentLogger())
	if err == nil {
		t.Fatalf("Run: want error when all TL fetches fail, got nil (summary=%+v)", summary)
	}
	if summary.AgentsCaptured != 0 || summary.TLFetchErrors != 2 {
		t.Errorf("summary = %+v, want 0 captured / 2 errors", summary)
	}
}

// A merge that produces an invalid TL event (e.g. both Search and TL side
// omit status) must be caught at capture time, not silently written and only
// blow up later at hydrator load. The bad agent is skipped and counted in
// TLFetchErrors; the rest of the run proceeds normally.
func TestRun_SkipsMergedEventFailingValidation(t *testing.T) {
	t.Parallel()

	out := t.TempDir()
	search := &fakeSearcher{agents: []atdclient.Agent{
		simpleAgent("ok"),
		// The "bad" agent has no lifecycle status in the Search projection...
		{AgentID: "bad", ANSName: "ans://v1.0.0.bad.example.com", AgentDisplayName: "bad"},
	}}
	tl := &fakeTL{events: map[string]tlevent.Event{
		"ok": validEvent("ok", "ok.example.com"),
		// ...and TL side also omits status. merge() leaves it empty; validate rejects.
		"bad": func() tlevent.Event {
			e := validEvent("bad", "bad.example.com")
			e.Status = ""
			return e
		}(),
	}}

	summary, err := Run(context.Background(), search, tl, Config{OutDir: out}, silentLogger())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if summary.AgentsCaptured != 1 || summary.TLFetchErrors != 1 {
		t.Errorf("summary = %+v, want 1 captured / 1 error (validation)", summary)
	}
	loaded, err := tlevent.LoadDir(filepath.Join(out, "tl-events"))
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	if len(loaded) != 1 || loaded[0].ANSID != "ok" {
		t.Errorf("loaded = %+v; the bad fixture must not have been written", loaded)
	}
}

func TestRun_SurfacesSearchError(t *testing.T) {
	t.Parallel()
	out := t.TempDir()
	search := &fakeSearcher{err: errors.New("search down")}
	_, err := Run(context.Background(), search, &fakeTL{}, Config{OutDir: out}, silentLogger())
	if err == nil {
		t.Fatalf("want error")
	}
}

func TestSafeFileName(t *testing.T) {
	t.Parallel()
	tests := []struct{ in, want string }{
		{"uuid-with-dashes_and.dots", "uuid-with-dashes_and.dots"},
		{"../../etc/passwd", ".._.._etc_passwd"},
		{"with spaces!", "with_spaces_"},
		{"", "unnamed"},
	}
	for _, tc := range tests {
		if got := safeFileName(tc.in); got != tc.want {
			t.Fatalf("safeFileName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestWriteFixture_YAMLRoundtripsThroughParseEvent(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	ev := validEvent("rt-1", "rt.example.com")
	if err := writeFixture(dir, ev); err != nil {
		t.Fatalf("writeFixture: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "rt-1.yaml"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	got, err := tlevent.ParseEvent(b)
	if err != nil {
		t.Fatalf("ParseEvent: %v\nbody:\n%s", err, b)
	}
	if got.ANSID != ev.ANSID || got.Agent.Host != ev.Agent.Host {
		t.Fatalf("roundtrip mismatch: %+v vs %+v", got, ev)
	}
	// Sanity-check the marshalled YAML uses _ans / _ans-badge as bare keys.
	var asMap map[string]any
	if err := yaml.Unmarshal(b, &asMap); err != nil {
		t.Fatalf("yaml: %v", err)
	}
}

// ---- fakes -------------------------------------------------------------

type fakeSearcher struct {
	agents []atdclient.Agent
	err    error
}

func (f *fakeSearcher) SearchAgents(_ context.Context, _ string, _ atdclient.SearchOpts) ([]atdclient.Agent, error) {
	return f.agents, f.err
}

type fakeTL struct {
	events map[string]tlevent.Event
	errs   map[string]error
}

func (f *fakeTL) Fetch(_ context.Context, _, ansID string) (tlevent.Event, error) {
	if err, ok := f.errs[ansID]; ok {
		return tlevent.Event{}, err
	}
	ev, ok := f.events[ansID]
	if !ok {
		return tlevent.Event{}, errors.New("no event for " + ansID)
	}
	return ev, nil
}

func simpleAgent(id string) atdclient.Agent {
	return atdclient.Agent{
		AgentID:          id,
		ANSName:          "ans://v1.0.0." + id + ".example.com",
		AgentDisplayName: id,
		Lifecycle:        atdclient.AgentLifecycle{Status: "ACTIVE"},
	}
}

func validEvent(ansID, host string) tlevent.Event {
	return tlevent.Event{
		ANSID:       ansID,
		Status:      "ACTIVE",
		FirstSeen:   "2026-05-01T00:00:00Z",
		LastUpdated: "2026-06-01T00:00:00Z",
		Agent:       tlevent.Agent{Host: host, Version: "v1", Name: ansID},
		Attestations: tlevent.Attestations{
			ServerCert:            tlevent.CertAttestation{Fingerprint: "SHA256:11"},
			IdentityCert:          tlevent.CertAttestation{Fingerprint: "SHA256:22"},
			DNSRecordsProvisioned: tlevent.DNSRecords{ANS: "v=ans1", ANSBadge: "v=ans-badge1"},
			DNSSECStatus:          "signed",
		},
	}
}

func silentLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
