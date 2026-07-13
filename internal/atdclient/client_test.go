package atdclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
)

func TestSearchAgents_BuildsQueryStringFromOpts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		opts SearchOpts
		want url.Values
	}{
		{
			name: "empty opts only has implicit defaults",
			opts: SearchOpts{},
			want: url.Values{},
		},
		{
			name: "scalar fields are set; arrays become repeated keys",
			opts: SearchOpts{
				Query:            "weather",
				Profile:          "default",
				PageSize:         50,
				KeywordAlgorithm: "SIMPLE",
				ProviderIDs:      []string{"p1", "p2"},
				AgentDomains:     []string{"weather.com"},
				Protocols:        []string{"A2A", "MCP"},
				Transports:       []string{"HTTP", "REST"},
				Tags:             []string{"finance"},
				Capabilities:     []string{"summarize", "translate"},
			},
			want: url.Values{
				"query":            []string{"weather"},
				"profile":          []string{"default"},
				"pageSize":         []string{"50"},
				"keywordAlgorithm": []string{"SIMPLE"},
				"providerIds":      []string{"p1", "p2"},
				"agentDomains":     []string{"weather.com"},
				"protocols":        []string{"A2A", "MCP"},
				"transports":       []string{"HTTP", "REST"},
				"tags":             []string{"finance"},
				"capabilities":     []string{"summarize", "translate"},
			},
		},
		{
			name: "keywordExtraction with query renders as true",
			opts: SearchOpts{Query: "fx", KeywordExtraction: true},
			want: url.Values{
				"query":             []string{"fx"},
				"keywordExtraction": []string{"true"},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var gotQuery url.Values
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotQuery = r.URL.Query()
				_ = json.NewEncoder(w).Encode(searchResults{Items: []Agent{}, Links: nil})
			}))
			t.Cleanup(srv.Close)

			_, err := New(srv.Client()).SearchAgents(context.Background(), srv.URL, tc.opts)
			if err != nil {
				t.Fatalf("SearchAgents: %v", err)
			}

			normalizeRepeatedValues(gotQuery)
			normalizeRepeatedValues(tc.want)
			if !reflect.DeepEqual(gotQuery, tc.want) {
				t.Fatalf("query mismatch:\n got: %v\nwant: %v", gotQuery, tc.want)
			}
		})
	}
}

func TestSearchAgents_AppendsPathPreservingBasePath(t *testing.T) {
	t.Parallel()

	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_ = json.NewEncoder(w).Encode(searchResults{Items: []Agent{}, Links: nil})
	}))
	t.Cleanup(srv.Close)

	_, err := New(srv.Client()).SearchAgents(context.Background(), srv.URL+"/", SearchOpts{})
	if err != nil {
		t.Fatalf("SearchAgents: %v", err)
	}
	if gotPath != "/v1/ans/registered-agents" {
		t.Fatalf("path: got %q, want /v1/ans/registered-agents", gotPath)
	}
}

func TestSearchAgents_PaginationStopsAtLimit(t *testing.T) {
	t.Parallel()

	page1 := mkPage([]string{"a1", "a2"}, "/v1/ans/registered-agents?pageToken=p2")
	page2 := mkPage([]string{"a3", "a4"}, "/v1/ans/registered-agents?pageToken=p3")
	page3 := mkPage([]string{"a5"}, "") // no next link

	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		tok := r.URL.Query().Get("pageToken")
		switch tok {
		case "":
			_ = json.NewEncoder(w).Encode(page1)
		case "p2":
			_ = json.NewEncoder(w).Encode(page2)
		case "p3":
			_ = json.NewEncoder(w).Encode(page3)
		default:
			http.Error(w, "unexpected token", http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)

	got, err := New(srv.Client()).SearchAgents(context.Background(), srv.URL, SearchOpts{Limit: 3})
	if err != nil {
		t.Fatalf("SearchAgents: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d agents, want 3", len(got))
	}
	ids := []string{got[0].AgentID, got[1].AgentID, got[2].AgentID}
	if !reflect.DeepEqual(ids, []string{"a1", "a2", "a3"}) {
		t.Fatalf("agent IDs: got %v, want [a1 a2 a3]", ids)
	}
	if hits != 2 {
		t.Fatalf("server hits: got %d, want 2 (limit stops before page 3)", hits)
	}
}

func TestSearchAgents_PaginationWalksAllPagesWhenLimitNotSet(t *testing.T) {
	t.Parallel()

	page1 := mkPage([]string{"a1"}, "/v1/ans/registered-agents?pageToken=p2")
	page2 := mkPage([]string{"a2", "a3"}, "")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("pageToken") {
		case "":
			_ = json.NewEncoder(w).Encode(page1)
		case "p2":
			_ = json.NewEncoder(w).Encode(page2)
		}
	}))
	t.Cleanup(srv.Close)

	got, err := New(srv.Client()).SearchAgents(context.Background(), srv.URL, SearchOpts{})
	if err != nil {
		t.Fatalf("SearchAgents: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("agents: got %d, want 3", len(got))
	}
}

func TestSearchAgents_RejectsKeywordExtractionWithoutQuery(t *testing.T) {
	t.Parallel()

	_, err := New(nil).SearchAgents(context.Background(), "http://example.invalid",
		SearchOpts{KeywordExtraction: true})
	if err == nil || !strings.Contains(err.Error(), "keywordExtraction") {
		t.Fatalf("want ErrKeywordExtractionRequiresQuery, got %v", err)
	}
}

func TestSearchAgents_PropagatesNon200(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"detail":"bad request"}`, http.StatusBadRequest)
	}))
	t.Cleanup(srv.Close)

	_, err := New(srv.Client()).SearchAgents(context.Background(), srv.URL, SearchOpts{})
	if err == nil || !strings.Contains(err.Error(), "400") {
		t.Fatalf("want 400 error, got %v", err)
	}
}

func TestSearchAgents_InvalidBaseURL(t *testing.T) {
	t.Parallel()

	_, err := New(nil).SearchAgents(context.Background(), "://bad", SearchOpts{})
	if err == nil {
		t.Fatalf("want parse error, got nil")
	}
}

func TestSearchAgents_DecodesAgentBody(t *testing.T) {
	t.Parallel()

	// Wire shape uses prod field names: ansName/agentHost/agentDisplayName/
	// agentDescription/agentVersion plus nested lifecycle.status and endpoints[].
	const body = `{
		"items": [{
			"agentId": "a1",
			"providerId": "weather-co",
			"ansName": "ans://v1.0.0.weather.example.com",
			"agentHost": "weather.example.com",
			"agentDisplayName": "Weather",
			"agentDescription": "forecast agent",
			"agentVersion": "v1.0.0",
			"indexedAt": "2026-06-30T01:58:12Z",
			"expiresAt": "2027-06-21T17:48:42Z",
			"lifecycle": {"status": "ACTIVE"},
			"endpoints": [{
				"agentUrl": "https://weather.example.com/",
				"protocol": "A2A",
				"transports": ["JSON-RPC"]
			}]
		}],
		"links": []
	}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)

	got, err := New(srv.Client()).SearchAgents(context.Background(), srv.URL, SearchOpts{})
	if err != nil {
		t.Fatalf("SearchAgents: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("agents: got %d, want 1", len(got))
	}
	a := got[0]
	if a.AgentID != "a1" || a.AgentDisplayName != "Weather" {
		t.Fatalf("agentId/displayName: %q / %q", a.AgentID, a.AgentDisplayName)
	}
	if a.AgentHost != "weather.example.com" || a.AgentDescription != "forecast agent" {
		t.Fatalf("agentHost/description: %q / %q", a.AgentHost, a.AgentDescription)
	}
	if a.AgentVersion != "v1.0.0" || a.Lifecycle.Status != "ACTIVE" {
		t.Fatalf("version/lifecycle.status: %q / %q", a.AgentVersion, a.Lifecycle.Status)
	}
	if len(a.Endpoints) != 1 || a.Endpoints[0].Protocol != "A2A" {
		t.Fatalf("endpoints: %+v", a.Endpoints)
	}
}

func mkPage(ids []string, nextHref string) searchResults {
	items := make([]Agent, 0, len(ids))
	for _, id := range ids {
		items = append(items, Agent{
			AgentID:          id,
			ANSName:          "ans://" + id,
			AgentDisplayName: id,
			Lifecycle:        AgentLifecycle{Status: "ACTIVE"},
		})
	}
	out := searchResults{Items: items, Links: []link{{Rel: "self", Method: "GET", Href: "self"}}}
	if nextHref != "" {
		out.Links = append(out.Links, link{Rel: "next", Method: "GET", Href: nextHref})
	}
	return out
}

// normalizeRepeatedValues sorts multi-valued keys so DeepEqual is
// order-insensitive across array params (url.Values stores insertion order).
func normalizeRepeatedValues(v url.Values) {
	for _, vs := range v {
		if len(vs) > 1 {
			sort.Strings(vs)
		}
	}
}

// TestSearchAgents_RejectsCrossOriginNextHref exercises the host-pin guard:
// an upstream that emits an absolute `next` href pointing at a different host
// must not cause a follow-up request to that host.
func TestSearchAgents_RejectsCrossOriginNextHref(t *testing.T) {
	t.Parallel()

	// The evil host records any hit; the primary host emits a next link that
	// tries to redirect the walk there.
	var evilHits int32
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&evilHits, 1)
		_ = json.NewEncoder(w).Encode(searchResults{})
	}))
	t.Cleanup(evil.Close)

	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		page := mkPage([]string{"a1"}, evil.URL+"/v1/ans/registered-agents?pageToken=p2")
		_ = json.NewEncoder(w).Encode(page)
	}))
	t.Cleanup(primary.Close)

	_, err := New(primary.Client()).SearchAgents(context.Background(), primary.URL, SearchOpts{})
	if !errors.Is(err, ErrNextHrefHostMismatch) {
		t.Fatalf("want ErrNextHrefHostMismatch, got %v", err)
	}
	if got := atomic.LoadInt32(&evilHits); got != 0 {
		t.Fatalf("evil host was hit %d times; want 0", got)
	}
}

// TestSearchAgents_PaginationCeiling exercises the page-count guard against a
// looping upstream that always emits a fresh next link.
func TestSearchAgents_PaginationCeiling(t *testing.T) {
	t.Parallel()

	var pageCount int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := atomic.AddInt32(&pageCount, 1)
		// Always advertise another page.
		page := mkPage([]string{fmt.Sprintf("a%d", n)},
			fmt.Sprintf("/v1/ans/registered-agents?pageToken=p%d", n+1))
		_ = json.NewEncoder(w).Encode(page)
	}))
	t.Cleanup(srv.Close)

	_, err := New(srv.Client()).SearchAgents(context.Background(), srv.URL, SearchOpts{})
	if !errors.Is(err, ErrPaginationLimitExceeded) {
		t.Fatalf("want ErrPaginationLimitExceeded, got %v", err)
	}
	if got := atomic.LoadInt32(&pageCount); got != maxPagesWalk {
		t.Fatalf("pages served = %d, want %d", got, maxPagesWalk)
	}
}

// TestSearchAgents_ResponseBodyCap rejects a page that exceeds the size cap
// rather than reading it fully into memory.
func TestSearchAgents_ResponseBodyCap(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Emit a valid JSON envelope wrapping a huge padding string.
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"items":[],"links":[],"pad":"`))
		buf := make([]byte, 1<<20)
		for i := range buf {
			buf[i] = 'x'
		}
		for range 33 { // 33 MiB payload — above the 32 MiB cap
			_, _ = w.Write(buf)
		}
		_, _ = w.Write([]byte(`"}`))
	}))
	t.Cleanup(srv.Close)

	_, err := New(srv.Client()).SearchAgents(context.Background(), srv.URL, SearchOpts{})
	if !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("want ErrResponseTooLarge, got %v", err)
	}
}
