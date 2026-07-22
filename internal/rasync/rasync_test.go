package rasync

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/agentnameservice/agent-trust-discovery/internal/raclient"
	"github.com/agentnameservice/agent-trust-discovery/internal/tlevent"
)

func TestToEvent_BadgeEnriched(t *testing.T) {
	fa := foldedAgent{
		AgentID: "a1", Host: "x.example.com", Version: "v1.0.0", DisplayName: "X",
		Description: "desc from feed", Status: "ACTIVE",
		FirstSeenFallback: "2020-01-01T00:00:00Z", LastUpdated: "2026-02-01T00:00:00Z",
		Endpoints: []raclient.Endpoint{{AgentURL: "https://x.example.com", Protocol: "A2A", Transports: []string{"HTTP", "SSE"}}},
	}
	badge := tlevent.Event{
		FirstSeen:   "2025-05-05T00:00:00Z", // authoritative — must win over fallback
		LastUpdated: "2025-05-05T00:00:00Z",
		Agent:       tlevent.Agent{Host: "x.example.com", Version: "v1.0.0", Name: "X"},
		Attestations: tlevent.Attestations{
			ServerCert:   tlevent.CertAttestation{Fingerprint: "SHA256:abc"},
			DNSSECStatus: "secure",
		},
	}

	ev := toEvent(fa, badge, true)

	if ev.FirstSeen != "2025-05-05T00:00:00Z" {
		t.Errorf("FirstSeen = %q, want the badge value (authoritative)", ev.FirstSeen)
	}
	if ev.Attestations.ServerCert.Fingerprint != "SHA256:abc" || ev.Attestations.DNSSECStatus != "secure" {
		t.Errorf("attestations not carried from badge: %+v", ev.Attestations)
	}
	if ev.Agent.Description != "desc from feed" {
		t.Errorf("Description = %q, want feed value", ev.Agent.Description)
	}
	if ev.Status != "ACTIVE" || ev.ANSID != "a1" {
		t.Errorf("status/ansId wrong: %+v", ev)
	}
	// Endpoints fanned per transport; protocols/transports deduped onto the agent.
	if len(ev.Agent.Endpoints) != 2 {
		t.Errorf("endpoints = %d, want 2 (one per transport)", len(ev.Agent.Endpoints))
	}
	if len(ev.Agent.Transports) != 2 || ev.Agent.Protocols[0] != "A2A" {
		t.Errorf("protocols/transports not derived: %+v / %+v", ev.Agent.Protocols, ev.Agent.Transports)
	}
	if err := ev.Validate(); err != nil {
		t.Errorf("merged event invalid: %v", err)
	}
}

func TestToEvent_FeedOnlyFallbackWhenNoBadge(t *testing.T) {
	fa := foldedAgent{
		AgentID: "a1", Host: "x", Version: "v1", DisplayName: "", // empty display name
		Status: "ACTIVE", FirstSeenFallback: "2026-01-01T00:00:00Z", LastUpdated: "2026-01-02T00:00:00Z",
	}
	ev := toEvent(fa, tlevent.Event{}, false)
	if ev.FirstSeen != "2026-01-01T00:00:00Z" {
		t.Errorf("FirstSeen = %q, want fold fallback when badge absent", ev.FirstSeen)
	}
	if ev.Agent.Name != "x" {
		t.Errorf("Name = %q, want host fallback for empty displayName", ev.Agent.Name)
	}
	if err := ev.Validate(); err != nil {
		t.Errorf("fallback event invalid: %v", err)
	}
}

// fakeTL returns a canned badge, or an error for ansIDs in failFor.
type fakeTL struct {
	byID    map[string]tlevent.Event
	failFor map[string]bool
}

func (f fakeTL) Fetch(_ context.Context, _, ansID string) (tlevent.Event, error) {
	if f.failFor[ansID] {
		return tlevent.Event{}, os.ErrDeadlineExceeded
	}
	return f.byID[ansID], nil
}

func TestRun_WritesParseableFixtures(t *testing.T) {
	feed := &fakeFeed{pages: []raclient.EventPage{
		{Items: []raclient.EventItem{
			{LogID: "1", EventType: "AGENT_REGISTERED", CreatedAt: "2026-01-01T00:00:00Z",
				AgentID: "a1", AnsName: "ans://v1.0.0.x", AgentHost: "x", Version: "v1.0.0", AgentDisplayName: "X"},
			{LogID: "2", EventType: "AGENT_REGISTERED", CreatedAt: "2026-01-01T00:00:00Z",
				AgentID: "a2", AnsName: "ans://v1.0.0.y", AgentHost: "y", Version: "v1.0.0", AgentDisplayName: "Y"},
		}, LastLogID: "2"},
	}}
	tl := fakeTL{
		byID: map[string]tlevent.Event{
			"a1": {FirstSeen: "2025-01-01T00:00:00Z", LastUpdated: "2025-01-01T00:00:00Z",
				Agent:        tlevent.Agent{Host: "x", Version: "v1.0.0", Name: "X"},
				Attestations: tlevent.Attestations{ServerCert: tlevent.CertAttestation{Fingerprint: "SHA256:a1"}}},
		},
		failFor: map[string]bool{"a2": true}, // a2 → feed-only fallback
	}
	dir := t.TempDir()
	sum, err := Run(context.Background(), feed, tl, Config{RABaseURL: "http://ra", TLBaseURL: "http://tl", OutDir: dir, PageSize: 100}, slog.New(slog.NewTextHandler(os.Stdout, nil)))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if sum.AgentsCaptured != 2 {
		t.Errorf("AgentsCaptured = %d, want 2", sum.AgentsCaptured)
	}
	for _, id := range []string{"a1", "a2"} {
		b, rerr := os.ReadFile(filepath.Join(dir, "tl-events", id+".yaml"))
		if rerr != nil {
			t.Fatalf("read fixture %s: %v", id, rerr)
		}
		if _, perr := tlevent.ParseEvent(b); perr != nil {
			t.Errorf("fixture %s does not parse: %v", id, perr)
		}
	}
}

func TestRun_TracksValidationDrops(t *testing.T) {
	// One valid agent and one that projects to an invalid event (no host,
	// version, or display name → tlevent validation fails). The invalid one is
	// dropped, but the drop must be counted in the Summary, not only logged.
	feed := &fakeFeed{pages: []raclient.EventPage{
		{Items: []raclient.EventItem{
			{LogID: "1", EventType: "AGENT_REGISTERED", CreatedAt: "2026-01-01T00:00:00Z",
				AgentID: "good", AgentHost: "x", Version: "v1.0.0", AgentDisplayName: "X"},
			{LogID: "2", EventType: "AGENT_REGISTERED", CreatedAt: "2026-01-01T00:00:00Z",
				AgentID: "bad"}, // no host/version/name
		}, LastLogID: "2"},
	}}
	dir := t.TempDir()
	sum, err := Run(context.Background(), feed, fakeTL{}, Config{RABaseURL: "http://ra", TLBaseURL: "http://tl", OutDir: dir, PageSize: 100}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if sum.AgentsCaptured != 1 {
		t.Errorf("AgentsCaptured = %d, want 1", sum.AgentsCaptured)
	}
	if sum.ValidationDrops != 1 {
		t.Errorf("ValidationDrops = %d, want 1", sum.ValidationDrops)
	}
}

func TestNormalizePageSize(t *testing.T) {
	cases := map[string]struct {
		in, want int
	}{
		"zero falls back to default":     {0, defaultPageSize},
		"negative falls back to default": {-5, defaultPageSize},
		"in range is unchanged":          {50, 50},
		"lower bound is unchanged":       {1, 1},
		"upper bound is unchanged":       {maxPageSize, maxPageSize},
		"above max is clamped":           {500, maxPageSize},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := normalizePageSize(tc.in); got != tc.want {
				t.Errorf("normalizePageSize(%d) = %d, want %d", tc.in, got, tc.want)
			}
		})
	}
}

func TestRun_RefusesEmptyFeed(t *testing.T) {
	feed := &fakeFeed{pages: []raclient.EventPage{{Items: nil, LastLogID: ""}}}
	dir := t.TempDir()
	if _, err := Run(context.Background(), feed, fakeTL{}, Config{RABaseURL: "http://ra", TLBaseURL: "http://tl", OutDir: dir, PageSize: 100}, nil); err == nil {
		t.Fatal("expected error refusing to write an empty fixture set")
	}
}
