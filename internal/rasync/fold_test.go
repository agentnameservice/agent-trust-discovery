package rasync

import (
	"context"
	"testing"

	"github.com/agentnameservice/agent-trust-discovery/internal/raclient"
)

// fakeFeed serves canned pages in order, then an empty tail page.
type fakeFeed struct {
	pages []raclient.EventPage
	calls int
}

func (f *fakeFeed) FetchEvents(_ context.Context, _, _ string, _ int) (raclient.EventPage, error) {
	if f.calls >= len(f.pages) {
		return raclient.EventPage{Items: nil, LastLogID: ""}, nil
	}
	p := f.pages[f.calls]
	f.calls++
	return p, nil
}

func TestStatusForEventType(t *testing.T) {
	cases := map[string]string{
		raclient.EventTypeAgentRegistered: "ACTIVE",
		raclient.EventTypeAgentRenewed:    "ACTIVE",
		raclient.EventTypeAgentRevoked:    "REVOKED",
		raclient.EventTypeAgentDeprecated: "DEPRECATED",
		"SOMETHING_ELSE":                  "",
	}
	for in, want := range cases {
		if got := statusForEventType(in); got != want {
			t.Errorf("statusForEventType(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDrainAndFold_LastEventWinsAndFirstSeenIsEarliestRegistered(t *testing.T) {
	feed := &fakeFeed{pages: []raclient.EventPage{
		{Items: []raclient.EventItem{
			{LogID: "1", EventType: "AGENT_REGISTERED", CreatedAt: "2026-01-01T00:00:00Z",
				AgentID: "a1", AnsName: "ans://v1.0.0.x", AgentHost: "x", Version: "v1.0.0", AgentDisplayName: "X"},
		}, LastLogID: "1"},
		{Items: []raclient.EventItem{
			{LogID: "2", EventType: "AGENT_RENEWED", CreatedAt: "2026-02-01T00:00:00Z",
				AgentID: "a1", AnsName: "ans://v1.0.0.x", AgentHost: "x", Version: "v1.0.0", AgentDisplayName: "X2"},
			{LogID: "3", EventType: "AGENT_REVOKED", CreatedAt: "2026-03-01T00:00:00Z",
				AgentID: "a2", AnsName: "ans://v1.0.0.y", AgentHost: "y", Version: "v1.0.0", AgentDisplayName: "Y"},
		}, LastLogID: "3"},
	}}

	got, err := drainAndFold(context.Background(), feed, "http://ra", 100)
	if err != nil {
		t.Fatalf("drainAndFold: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("agents = %d, want 2", len(got))
	}
	a1 := got["a1"]
	if a1.Status != "ACTIVE" || a1.DisplayName != "X2" {
		t.Errorf("a1 = %+v, want ACTIVE/X2 (last event wins)", a1)
	}
	if a1.FirstSeenFallback != "2026-01-01T00:00:00Z" {
		t.Errorf("a1.FirstSeenFallback = %q, want earliest REGISTERED", a1.FirstSeenFallback)
	}
	if a1.LastUpdated != "2026-02-01T00:00:00Z" {
		t.Errorf("a1.LastUpdated = %q, want latest event", a1.LastUpdated)
	}
	if got["a2"].Status != "REVOKED" {
		t.Errorf("a2.Status = %q, want REVOKED", got["a2"].Status)
	}
}

func TestDrainAndFold_StopsWhenCursorDoesNotAdvance(t *testing.T) {
	// A page that returns the same cursor must not loop forever.
	feed := &fakeFeed{pages: []raclient.EventPage{
		{Items: []raclient.EventItem{{LogID: "1", EventType: "AGENT_REGISTERED",
			CreatedAt: "2026-01-01T00:00:00Z", AgentID: "a1", AgentHost: "x", Version: "v1", AgentDisplayName: "X"}},
			LastLogID: "1"},
		{Items: []raclient.EventItem{{LogID: "1", EventType: "AGENT_REGISTERED",
			CreatedAt: "2026-01-01T00:00:00Z", AgentID: "a1", AgentHost: "x", Version: "v1", AgentDisplayName: "X"}},
			LastLogID: "1"}, // same cursor → must stop
	}}
	if _, err := drainAndFold(context.Background(), feed, "http://ra", 100); err != nil {
		t.Fatalf("drainAndFold: %v", err)
	}
	if feed.calls > 2 {
		t.Errorf("calls = %d, want <= 2 (must stop on non-advancing cursor)", feed.calls)
	}
}
