package rasync

import (
	"context"
	"strconv"
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

// runawayFeed always returns one item with a strictly-advancing cursor, so
// drainAndFold never hits a natural termination condition — until an internal
// safety cap far above maxFeedPages, so the test itself can never hang even if
// the guard under test is missing.
type runawayFeed struct {
	calls int
	cap   int
}

func (f *runawayFeed) FetchEvents(_ context.Context, _, _ string, _ int) (raclient.EventPage, error) {
	if f.calls >= f.cap {
		return raclient.EventPage{Items: nil, LastLogID: ""}, nil
	}
	f.calls++
	id := strconv.Itoa(f.calls)
	return raclient.EventPage{
		Items: []raclient.EventItem{{
			LogID: id, EventType: "AGENT_REGISTERED", CreatedAt: "2026-01-01T00:00:00Z",
			AgentID: "a" + id, AgentHost: "h", Version: "v1", AgentDisplayName: "N",
		}},
		LastLogID: id,
	}, nil
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

func TestDrainAndFold_BoundsRunawayFeed(t *testing.T) {
	// A feed whose cursor advances forever (buggy or adversarial) must be
	// bounded, not drained until OOM. cap is above maxFeedPages so the guard,
	// not the fake, is what stops the loop.
	feed := &runawayFeed{cap: maxFeedPages + 5}
	if _, err := drainAndFold(context.Background(), feed, "http://ra", 100); err == nil {
		t.Fatal("expected an error when the feed never terminates")
	}
	if feed.calls > maxFeedPages {
		t.Errorf("fetched %d pages, want <= maxFeedPages (%d)", feed.calls, maxFeedPages)
	}
}

func TestDrainAndFold_SparseStatusEventPreservesMetadata(t *testing.T) {
	// A later lifecycle event that omits the agent block (a sparse
	// status-change event) must update status + timestamp without blanking the
	// host/version/name/description/endpoints an earlier event established.
	feed := &fakeFeed{pages: []raclient.EventPage{
		{Items: []raclient.EventItem{
			{LogID: "1", EventType: "AGENT_REGISTERED", CreatedAt: "2026-01-01T00:00:00Z",
				AgentID: "a1", AnsName: "ans://v1.0.0.x", AgentHost: "x.example.com",
				Version: "v1.0.0", AgentDisplayName: "X", AgentDescription: "desc",
				Endpoints: []raclient.Endpoint{{AgentURL: "https://x.example.com", Protocol: "A2A", Transports: []string{"HTTP"}}}},
			// Sparse revoke: only the lifecycle fields carry values.
			{LogID: "2", EventType: "AGENT_REVOKED", CreatedAt: "2026-03-01T00:00:00Z", AgentID: "a1"},
		}, LastLogID: "2"},
	}}

	got, err := drainAndFold(context.Background(), feed, "http://ra", 100)
	if err != nil {
		t.Fatalf("drainAndFold: %v", err)
	}
	a1 := got["a1"]
	if a1.Status != "REVOKED" {
		t.Errorf("a1.Status = %q, want REVOKED (latest event wins)", a1.Status)
	}
	if a1.LastUpdated != "2026-03-01T00:00:00Z" {
		t.Errorf("a1.LastUpdated = %q, want the revoke timestamp", a1.LastUpdated)
	}
	if a1.Host != "x.example.com" || a1.Version != "v1.0.0" || a1.DisplayName != "X" || a1.Description != "desc" {
		t.Errorf("sparse revoke blanked metadata: %+v", a1)
	}
	if a1.AnsName != "ans://v1.0.0.x" {
		t.Errorf("a1.AnsName = %q, want preserved from register", a1.AnsName)
	}
	if len(a1.Endpoints) != 1 {
		t.Errorf("a1.Endpoints = %d, want 1 (preserved from register)", len(a1.Endpoints))
	}
	if a1.FirstSeenFallback != "2026-01-01T00:00:00Z" {
		t.Errorf("a1.FirstSeenFallback = %q, want earliest REGISTERED", a1.FirstSeenFallback)
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
