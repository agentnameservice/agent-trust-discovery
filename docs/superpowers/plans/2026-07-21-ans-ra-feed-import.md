# ANS RA Feed Import (`agent-ra-sync`) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a new producer, `agent-ra-sync`, that pulls agents from a (private) ANS RA's public event feed and writes the existing `tl-events/` fixture shape, so the unchanged hydrator + prober ingest and score them.

**Architecture:** `agent-ra-sync` is a snapshot-shaped batch producer (mirrors `internal/snapshot` / `cmd/agent-snapshot`). It (1) drains the RA feed `GET /v1/agents/events` via a new `internal/raclient`, folding lifecycle events into a current agent set; (2) enriches each agent with sealed baselines + authoritative `firstSeen` from the Transparency Log via the reused `internal/tlclient`; (3) writes `fixtures/ra-sync/tl-events/<ansId>.yaml` in the existing `tlevent.Event` shape. The hydrator (agents) and prober (live/drift observations) run unchanged. No change to `github.com/godaddy/ans`.

**Tech Stack:** Go 1.26, stdlib `net/http`, `gopkg.in/yaml.v3`, `log/slog`. Reuses `internal/tlclient`, `internal/tlevent`. No new third-party dependencies.

**Design spec:** `docs/superpowers/specs/2026-07-16-ans-ra-trust-index-import-design.md`.

## Global Constraints

- Module path: `github.com/agentnameservice/agent-trust-discovery`. Go directive `1.26`.
- No new third-party dependencies — stdlib + `gopkg.in/yaml.v3` only (already in `go.mod`).
- Output fixtures MUST be valid `tlevent.Event` YAML (pass `tlevent.ParseEvent`); the hydrator and prober are consumed **unchanged**.
- RA feed contract (fixed, from ANS `main`): `GET /v1/agents/events`, params `limit` (1–200, default 100) and `lastLogId` (opaque cursor); response `{ "items": EventItem[], "lastLogId": string }`; `eventType` ∈ `AGENT_REGISTERED | AGENT_RENEWED | AGENT_REVOKED | AGENT_DEPRECATED`; anonymous (no auth header).
- Status map: `AGENT_REGISTERED`/`AGENT_RENEWED` → `ACTIVE`, `AGENT_REVOKED` → `REVOKED`, `AGENT_DEPRECATED` → `DEPRECATED`. These are valid `domain.Status` values.
- `firstSeen` is sourced from the TL badge (authoritative, retention-independent); fall back to the earliest `AGENT_REGISTERED` `createdAt` from the fold only when the badge is unavailable.
- Out of scope for this plan (deferred per spec §7.2, §11, §12): the `emitObservations` path (`versionstability`, `dnssecurity.dnssec`), the durable-catalog/persisted-cursor evolution, and the ARD URN. v1 is a **stateless** producer; observations continue to come from the prober.
- All HTTP calls use a bounded body read and a context deadline. Tests are table-driven, run with `-race`, target ≥80% coverage.

---

## File Structure

- `internal/raclient/client.go` — feed client: wire types (`EventPage`, `EventItem`, `Endpoint`, `Function`), `eventType` constants, `Client`, `New`, `FetchEvents`. One external HTTP boundary; bounded read.
- `internal/raclient/client_test.go` — `httptest`-backed tests.
- `internal/rasync/fold.go` — `foldedAgent`, `FeedFetcher` interface, `statusForEventType`, `drainAndFold`.
- `internal/rasync/fold_test.go` — table-driven fold tests.
- `internal/rasync/rasync.go` — `Config`, `Summary`, `TLFetcher` interface, `toEvent` (merge), `Run`, and the fixture writer (`writeFixture`, `prepareOutDir`, `safeFileName`).
- `internal/rasync/rasync_test.go` — `Run` + `toEvent` tests with fakes.
- `cmd/agent-ra-sync/main.go` — thin CLI wiring (flags, config-file merge, lifecycle).
- `cmd/agent-ra-sync/main_test.go` — config-load test.
- `config/ra-sync.yaml` — default config.
- `config/hydrator.ra-sync.yaml`, `config/prober.ra-sync.yaml` — demo wiring pointing at `fixtures/ra-sync/tl-events`.
- `scripts/demo/run-demo-ra.sh` — demo pipeline script.
- `Makefile` — add `demo-ra` target.

---

## Task 1: `internal/raclient` — RA event-feed client

**Files:**
- Create: `internal/raclient/client.go`
- Test: `internal/raclient/client_test.go`

**Interfaces:**
- Consumes: nothing (leaf package; stdlib only).
- Produces:
  - `type Function struct { ID, Name string; Tags []string }`
  - `type Endpoint struct { AgentURL, MetaDataURL, DocumentationURL, Protocol string; Functions []Function; Transports []string }`
  - `type EventItem struct { LogID, EventType, CreatedAt, ExpiresAt, AgentID, AnsName, AgentHost, AgentDisplayName, AgentDescription, Version, ProviderID string; Endpoints []Endpoint }`
  - `type EventPage struct { Items []EventItem; LastLogID string }`
  - `func New(httpClient *http.Client) *Client`
  - `func (c *Client) FetchEvents(ctx context.Context, baseURL, afterLogID string, limit int) (EventPage, error)`
  - consts `EventTypeAgentRegistered = "AGENT_REGISTERED"`, `EventTypeAgentRenewed = "AGENT_RENEWED"`, `EventTypeAgentRevoked = "AGENT_REVOKED"`, `EventTypeAgentDeprecated = "AGENT_DEPRECATED"`

- [ ] **Step 1: Write the failing test**

Create `internal/raclient/client_test.go`:

```go
package raclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFetchEvents_ParsesPageAndSendsParams(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/agents/events" {
			t.Errorf("path = %q, want /v1/agents/events", r.URL.Path)
		}
		gotQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"items": [
				{"logId":"L1","eventType":"AGENT_REGISTERED","createdAt":"2026-07-01T00:00:00Z",
				 "agentId":"a1","ansName":"ans://v1.0.0.x.example.com","agentHost":"x.example.com",
				 "version":"v1.0.0","agentDisplayName":"X","agentDescription":"desc",
				 "endpoints":[{"agentUrl":"https://x.example.com","protocol":"A2A","transports":["HTTP"]}]}
			],
			"lastLogId": "L1"
		}`))
	}))
	defer srv.Close()

	page, err := New(srv.Client()).FetchEvents(context.Background(), srv.URL, "L0", 50)
	if err != nil {
		t.Fatalf("FetchEvents: %v", err)
	}
	if gotQuery != "lastLogId=L0&limit=50" {
		t.Errorf("query = %q, want lastLogId=L0&limit=50", gotQuery)
	}
	if len(page.Items) != 1 || page.Items[0].AgentID != "a1" || page.LastLogID != "L1" {
		t.Fatalf("unexpected page: %+v", page)
	}
	if page.Items[0].Endpoints[0].Protocol != "A2A" || page.Items[0].Endpoints[0].Transports[0] != "HTTP" {
		t.Errorf("endpoint not parsed: %+v", page.Items[0].Endpoints)
	}
}

func TestFetchEvents_Non200IsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	if _, err := New(srv.Client()).FetchEvents(context.Background(), srv.URL, "", 100); err == nil {
		t.Fatal("expected error on 503, got nil")
	}
}

func TestFetchEvents_OmitsCursorWhenEmpty(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		_, _ = w.Write([]byte(`{"items":[],"lastLogId":""}`))
	}))
	defer srv.Close()
	if _, err := New(srv.Client()).FetchEvents(context.Background(), srv.URL, "", 100); err != nil {
		t.Fatalf("FetchEvents: %v", err)
	}
	if gotQuery != "limit=100" {
		t.Errorf("query = %q, want limit=100 (no lastLogId)", gotQuery)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/raclient/ -run TestFetchEvents -v`
Expected: FAIL — `undefined: New` (package has no implementation yet).

- [ ] **Step 3: Write the implementation**

Create `internal/raclient/client.go`:

```go
// Package raclient is a read-only HTTP client for the ANS RA public agent
// events feed, GET /v1/agents/events. It returns one page of lifecycle events;
// callers page by passing the previous response's LastLogID as afterLogID until
// the cursor stops advancing. The feed is anonymous — no auth header is sent.
package raclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// Event type tokens served by the feed's `eventType` field.
const (
	EventTypeAgentRegistered = "AGENT_REGISTERED"
	EventTypeAgentRenewed    = "AGENT_RENEWED"
	EventTypeAgentRevoked    = "AGENT_REVOKED"
	EventTypeAgentDeprecated = "AGENT_DEPRECATED"
)

// maxResponseBodyBytes caps a successful feed response decoded into memory,
// mirroring tlclient's bounded-read discipline at every external boundary.
const maxResponseBodyBytes = 32 << 20 // 32 MiB

// ErrResponseTooLarge is returned when the feed response exceeds the cap.
var ErrResponseTooLarge = errors.New("raclient: response body exceeds size cap")

// Function mirrors the feed's AgentFunction.
type Function struct {
	ID   string   `json:"id"`
	Name string   `json:"name"`
	Tags []string `json:"tags,omitempty"`
}

// Endpoint mirrors the feed's AgentEndpoint (note wire spelling metaDataUrl).
type Endpoint struct {
	AgentURL         string     `json:"agentUrl"`
	MetaDataURL      string     `json:"metaDataUrl,omitempty"`
	DocumentationURL string     `json:"documentationUrl,omitempty"`
	Protocol         string     `json:"protocol"`
	Functions        []Function `json:"functions,omitempty"`
	Transports       []string   `json:"transports,omitempty"`
}

// EventItem is one lifecycle event on the wire (mirrors the RA EventItem).
type EventItem struct {
	LogID            string     `json:"logId"`
	EventType        string     `json:"eventType"`
	CreatedAt        string     `json:"createdAt"`
	ExpiresAt        string     `json:"expiresAt,omitempty"`
	AgentID          string     `json:"agentId"`
	AnsName          string     `json:"ansName"`
	AgentHost        string     `json:"agentHost"`
	AgentDisplayName string     `json:"agentDisplayName,omitempty"`
	AgentDescription string     `json:"agentDescription,omitempty"`
	Version          string     `json:"version"`
	ProviderID       string     `json:"providerId,omitempty"`
	Endpoints        []Endpoint `json:"endpoints,omitempty"`
}

// EventPage is one page of the feed. LastLogID is the cursor for the next page;
// empty means the tail.
type EventPage struct {
	Items     []EventItem `json:"items"`
	LastLogID string      `json:"lastLogId"`
}

// Client is a minimal HTTP wrapper.
type Client struct {
	httpClient *http.Client
}

// New returns a Client. A nil httpClient uses http.DefaultClient.
func New(httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &Client{httpClient: httpClient}
}

// FetchEvents issues GET {baseURL}/v1/agents/events?limit=..&lastLogId=.. and
// decodes one page. afterLogID is omitted from the query when empty (page from
// the oldest retained row).
func (c *Client) FetchEvents(ctx context.Context, baseURL, afterLogID string, limit int) (EventPage, error) {
	u, err := buildURL(baseURL, afterLogID, limit)
	if err != nil {
		return EventPage{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return EventPage{}, fmt.Errorf("raclient: build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return EventPage{}, fmt.Errorf("raclient: get %s: %w", u, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return EventPage{}, fmt.Errorf("raclient: get %s returned %d: %s",
			u, resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodyBytes+1))
	if err != nil {
		return EventPage{}, fmt.Errorf("raclient: read response: %w", err)
	}
	if int64(len(raw)) > maxResponseBodyBytes {
		return EventPage{}, ErrResponseTooLarge
	}
	var page EventPage
	if err := json.Unmarshal(raw, &page); err != nil {
		return EventPage{}, fmt.Errorf("raclient: decode response: %w", err)
	}
	return page, nil
}

func buildURL(baseURL, afterLogID string, limit int) (string, error) {
	base, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("raclient: parse baseURL: %w", err)
	}
	base.Path = strings.TrimRight(base.Path, "/") + "/v1/agents/events"
	q := url.Values{}
	q.Set("limit", strconv.Itoa(limit))
	if afterLogID != "" {
		q.Set("lastLogId", afterLogID)
	}
	base.RawQuery = q.Encode()
	return base.String(), nil
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/raclient/ -race -v`
Expected: PASS (all three tests).

- [ ] **Step 5: Commit**

```bash
git add internal/raclient/
git commit -m "feat(raclient): RA agent-events feed client"
```

---

## Task 2: `internal/rasync` — fold feed events into a current agent set

**Files:**
- Create: `internal/rasync/fold.go`
- Test: `internal/rasync/fold_test.go`

**Interfaces:**
- Consumes: `raclient.EventPage`, `raclient.EventItem`, `raclient.Endpoint`, `raclient.EventType*` constants (Task 1).
- Produces:
  - `type FeedFetcher interface { FetchEvents(ctx context.Context, baseURL, afterLogID string, limit int) (raclient.EventPage, error) }`
  - `type foldedAgent struct { AgentID, AnsName, Host, Version, DisplayName, Description, Status, FirstSeenFallback, LastUpdated string; Endpoints []raclient.Endpoint }`
  - `func statusForEventType(eventType string) string` (returns `"ACTIVE"`/`"REVOKED"`/`"DEPRECATED"`, or `""` for unknown)
  - `func drainAndFold(ctx context.Context, feed FeedFetcher, baseURL string, pageSize int) (map[string]foldedAgent, error)` (keyed by `AgentID`)

- [ ] **Step 1: Write the failing test**

Create `internal/rasync/fold_test.go`:

```go
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

func (f *fakeFeed) FetchEvents(_ context.Context, _ , _ string, _ int) (raclient.EventPage, error) {
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
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/rasync/ -run 'TestStatusForEventType|TestDrainAndFold' -v`
Expected: FAIL — `undefined: statusForEventType`, `undefined: drainAndFold`.

- [ ] **Step 3: Write the implementation**

Create `internal/rasync/fold.go`:

```go
// Package rasync is the agent-ra-sync producer core: drain the RA event feed,
// fold lifecycle events into a current agent set, enrich with TL baselines, and
// write the tl-events/ fixture YAML the hydrator and prober consume unchanged.
package rasync

import (
	"context"
	"fmt"

	"github.com/agentnameservice/agent-trust-discovery/internal/raclient"
)

// FeedFetcher is the subset of raclient.Client the producer needs; satisfied by
// *raclient.Client and test doubles.
type FeedFetcher interface {
	FetchEvents(ctx context.Context, baseURL, afterLogID string, limit int) (raclient.EventPage, error)
}

// foldedAgent is the current-state projection of one agent across its feed
// events. Keyed by AgentID in the fold result.
type foldedAgent struct {
	AgentID           string
	AnsName           string
	Host              string
	Version           string
	DisplayName       string
	Description       string
	Status            string // domain status string, from the latest event
	FirstSeenFallback string // earliest AGENT_REGISTERED createdAt (used only if the TL badge is unavailable)
	LastUpdated       string // latest event createdAt
	Endpoints         []raclient.Endpoint
}

// statusForEventType maps a feed eventType to a domain lifecycle status. An
// unrecognized eventType returns "" so the caller can skip it (fail-soft,
// mirroring the finder's unknown-eventType handling).
func statusForEventType(eventType string) string {
	switch eventType {
	case raclient.EventTypeAgentRegistered, raclient.EventTypeAgentRenewed:
		return "ACTIVE"
	case raclient.EventTypeAgentRevoked:
		return "REVOKED"
	case raclient.EventTypeAgentDeprecated:
		return "DEPRECATED"
	default:
		return ""
	}
}

// drainAndFold pages the feed from the oldest retained row to the tail, folding
// events into a current agent set keyed by AgentID. The feed is ordered by
// ascending log id, so the last event seen for an agent is the newest and wins.
// Paging stops at an empty page or when the returned cursor does not advance.
func drainAndFold(ctx context.Context, feed FeedFetcher, baseURL string, pageSize int) (map[string]foldedAgent, error) {
	agents := make(map[string]foldedAgent)
	cursor := ""
	for {
		page, err := feed.FetchEvents(ctx, baseURL, cursor, pageSize)
		if err != nil {
			return nil, fmt.Errorf("rasync: fetch events (cursor=%q): %w", cursor, err)
		}
		for i := range page.Items {
			applyEvent(agents, page.Items[i])
		}
		if page.LastLogID == "" || page.LastLogID == cursor || len(page.Items) == 0 {
			return agents, nil
		}
		cursor = page.LastLogID
	}
}

// applyEvent folds one event into the agent set. Unknown eventTypes are skipped.
func applyEvent(agents map[string]foldedAgent, it raclient.EventItem) {
	status := statusForEventType(it.EventType)
	if status == "" || it.AgentID == "" {
		return
	}
	fa := agents[it.AgentID] // zero value on first sight

	// Latest event wins for the mutable fields.
	fa.AgentID = it.AgentID
	fa.AnsName = it.AnsName
	fa.Host = it.AgentHost
	fa.Version = it.Version
	fa.DisplayName = it.AgentDisplayName
	fa.Description = it.AgentDescription
	fa.Status = status
	fa.LastUpdated = it.CreatedAt
	fa.Endpoints = it.Endpoints

	// firstSeen fallback = earliest AGENT_REGISTERED createdAt (feed is ascending,
	// so the first one seen is the earliest).
	if it.EventType == raclient.EventTypeAgentRegistered && fa.FirstSeenFallback == "" {
		fa.FirstSeenFallback = it.CreatedAt
	}

	agents[it.AgentID] = fa
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/rasync/ -race -run 'TestStatusForEventType|TestDrainAndFold' -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/rasync/fold.go internal/rasync/fold_test.go
git commit -m "feat(rasync): fold RA feed events into a current agent set"
```

---

## Task 3: `internal/rasync` — merge with TL baselines, run, write fixtures

**Files:**
- Modify: `internal/rasync/rasync.go` (create in this task)
- Test: `internal/rasync/rasync_test.go`

**Interfaces:**
- Consumes: `foldedAgent`, `FeedFetcher`, `drainAndFold` (Task 2); `tlevent.Event`, `tlevent.Agent`, `tlevent.Endpoint` (`internal/tlevent`); `raclient.Endpoint` (Task 1).
- Produces:
  - `type TLFetcher interface { Fetch(ctx context.Context, baseURL, ansID string) (tlevent.Event, error) }`
  - `type Config struct { RABaseURL, TLBaseURL, OutDir string; PageSize int }`
  - `type Summary struct { AgentsCaptured, TLFetchErrors int }`
  - `func toEvent(fa foldedAgent, badge tlevent.Event, tlOK bool) tlevent.Event`
  - `func Run(ctx context.Context, feed FeedFetcher, tl TLFetcher, cfg Config, logger *slog.Logger) (Summary, error)`

- [ ] **Step 1: Write the failing test**

Create `internal/rasync/rasync_test.go`:

```go
package rasync

import (
	"context"
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
				Agent: tlevent.Agent{Host: "x", Version: "v1.0.0", Name: "X"},
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

func TestRun_RefusesEmptyFeed(t *testing.T) {
	feed := &fakeFeed{pages: []raclient.EventPage{{Items: nil, LastLogID: ""}}}
	dir := t.TempDir()
	if _, err := Run(context.Background(), feed, fakeTL{}, Config{RABaseURL: "http://ra", TLBaseURL: "http://tl", OutDir: dir, PageSize: 100}, nil); err == nil {
		t.Fatal("expected error refusing to write an empty fixture set")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/rasync/ -run 'TestToEvent|TestRun' -v`
Expected: FAIL — `undefined: toEvent`, `undefined: Run`, `undefined: Config`.

- [ ] **Step 3: Write the implementation**

Create `internal/rasync/rasync.go`:

```go
package rasync

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/agentnameservice/agent-trust-discovery/internal/raclient"
	"github.com/agentnameservice/agent-trust-discovery/internal/tlevent"
)

// TLFetcher is the subset of tlclient.Client used by Run; satisfied by
// *tlclient.Client and test doubles.
type TLFetcher interface {
	Fetch(ctx context.Context, baseURL, ansID string) (tlevent.Event, error)
}

// Config configures one Run.
type Config struct {
	RABaseURL string // RA event-feed base URL
	TLBaseURL string // Transparency Log base URL
	OutDir    string // fixture root; tl-events/ is created beneath it
	PageSize  int    // feed page size (1..200); 0 → 100
}

// Summary reports what a run captured.
type Summary struct {
	AgentsCaptured int
	TLFetchErrors  int // agents the feed surfaced but the TL badge failed for (feed-only fixture written)
}

const defaultPageSize = 100

// Run drains the feed, folds to a current agent set, enriches each with TL
// baselines, and writes the tl-events/ fixtures the hydrator/prober consume.
// The tl-events/ dir is wiped and rewritten each run. A TL badge miss degrades
// that agent to a feed-only fixture (empty attestations), never aborts the run.
func Run(ctx context.Context, feed FeedFetcher, tl TLFetcher, cfg Config, logger *slog.Logger) (Summary, error) {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(os.Stdout, nil))
	}
	pageSize := cfg.PageSize
	if pageSize <= 0 {
		pageSize = defaultPageSize
	}

	agents, err := drainAndFold(ctx, feed, cfg.RABaseURL, pageSize)
	if err != nil {
		return Summary{}, err
	}
	logger.InfoContext(ctx, "rasync: fold complete", "agents", len(agents))

	// Refuse to wipe the previous fixture set to nothing: an empty feed (or a
	// window in which everything aged out) would otherwise look to the hydrator
	// like "zero agents" and silently drop all trust data.
	if len(agents) == 0 {
		return Summary{}, fmt.Errorf("rasync: feed returned no agents in the retention window; refusing to produce an empty fixture set")
	}

	outDir := filepath.Join(cfg.OutDir, "tl-events")
	if err := prepareOutDir(outDir); err != nil {
		return Summary{}, err
	}

	summary := Summary{}
	for id, fa := range agents {
		badge, ferr := tl.Fetch(ctx, cfg.TLBaseURL, id)
		tlOK := ferr == nil
		if !tlOK {
			logger.WarnContext(ctx, "rasync: tl badge fetch failed; writing feed-only fixture",
				"agentId", id, "error", ferr.Error())
			summary.TLFetchErrors++
		}
		ev := toEvent(fa, badge, tlOK)
		if verr := ev.Validate(); verr != nil {
			logger.WarnContext(ctx, "rasync: projected event failed validation; skipping",
				"agentId", id, "error", verr.Error())
			continue
		}
		if werr := writeFixture(outDir, ev); werr != nil {
			return summary, fmt.Errorf("rasync: write %s: %w", ev.ANSID, werr)
		}
		summary.AgentsCaptured++
	}

	logger.InfoContext(ctx, "rasync: capture complete",
		"agentsCaptured", summary.AgentsCaptured, "tlFetchErrors", summary.TLFetchErrors, "outDir", outDir)

	if summary.AgentsCaptured == 0 {
		return summary, fmt.Errorf("rasync: %d folded agents but 0 written; refusing to produce empty snapshot", len(agents))
	}
	return summary, nil
}

// toEvent merges a folded feed agent with its TL badge into the fixture Event.
// When tlOK the badge is authoritative for firstSeen + attestations + host/
// version/name; the feed supplies description + endpoints. When !tlOK the fold
// supplies everything and attestations are empty (prober emits non-matching
// drift, exactly as for any agent without a captured baseline).
func toEvent(fa foldedAgent, badge tlevent.Event, tlOK bool) tlevent.Event {
	name := fa.DisplayName
	if name == "" {
		name = fa.Host // import DTO requires a non-empty display name
	}
	protocols, transports := protocolsAndTransports(fa.Endpoints)

	ev := tlevent.Event{
		ANSID:       fa.AgentID,
		Status:      fa.Status,
		ProviderID:  "", // OSS RA never emits providerId
		LastUpdated: fa.LastUpdated,
		Agent: tlevent.Agent{
			Host:        fa.Host,
			Version:     fa.Version,
			Name:        name,
			Description: fa.Description,
			Protocols:   protocols,
			Transports:  transports,
			Endpoints:   projectEndpoints(fa.Endpoints),
		},
	}
	if tlOK {
		ev.FirstSeen = badge.FirstSeen
		ev.Attestations = badge.Attestations
		if badge.Agent.Host != "" {
			ev.Agent.Host = badge.Agent.Host
		}
		if badge.Agent.Version != "" {
			ev.Agent.Version = badge.Agent.Version
		}
	}
	if ev.FirstSeen == "" {
		ev.FirstSeen = fa.FirstSeenFallback
	}
	if ev.LastUpdated == "" {
		ev.LastUpdated = ev.FirstSeen
	}
	return ev
}

// protocolsAndTransports flattens feed endpoints into deduped protocol /
// transport sets (first-seen order, deterministic).
func protocolsAndTransports(eps []raclient.Endpoint) ([]string, []string) {
	protoSeen, transSeen := map[string]bool{}, map[string]bool{}
	var protocols, transports []string
	for _, e := range eps {
		if e.Protocol != "" && !protoSeen[e.Protocol] {
			protoSeen[e.Protocol] = true
			protocols = append(protocols, e.Protocol)
		}
		for _, t := range e.Transports {
			if t != "" && !transSeen[t] {
				transSeen[t] = true
				transports = append(transports, t)
			}
		}
	}
	return protocols, transports
}

// projectEndpoints renders feed endpoints into the fixture's endpoints[] shape,
// one entry per transport so each protocol+transport tuple is explicit.
func projectEndpoints(eps []raclient.Endpoint) []tlevent.Endpoint {
	var out []tlevent.Endpoint
	for _, e := range eps {
		if len(e.Transports) == 0 {
			if e.Protocol == "" && e.AgentURL == "" {
				continue
			}
			out = append(out, tlevent.Endpoint{Protocol: e.Protocol, URL: e.AgentURL})
			continue
		}
		for _, t := range e.Transports {
			out = append(out, tlevent.Endpoint{Protocol: e.Protocol, Transport: t, URL: e.AgentURL})
		}
	}
	return out
}

func prepareOutDir(outDir string) error {
	if err := os.MkdirAll(outDir, 0o750); err != nil {
		return fmt.Errorf("rasync: mkdir %s: %w", outDir, err)
	}
	entries, err := os.ReadDir(outDir)
	if err != nil {
		return fmt.Errorf("rasync: read %s: %w", outDir, err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		if err := os.Remove(filepath.Join(outDir, e.Name())); err != nil {
			return fmt.Errorf("rasync: remove %s: %w", e.Name(), err)
		}
	}
	return nil
}

func writeFixture(outDir string, ev tlevent.Event) error {
	b, err := yaml.Marshal(ev)
	if err != nil {
		return fmt.Errorf("marshal yaml: %w", err)
	}
	name := safeFileName(ev.ANSID) + ".yaml"
	if err := os.WriteFile(filepath.Join(outDir, name), b, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", name, err)
	}
	return nil
}

// safeFileName collapses anything that could escape the directory; UUID ansIds
// are already safe.
func safeFileName(s string) string {
	if s == "" {
		return "unnamed"
	}
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			return r
		}
		return '_'
	}, s)
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/rasync/ -race -v`
Expected: PASS (fold + merge + Run tests).

- [ ] **Step 5: Commit**

```bash
git add internal/rasync/rasync.go internal/rasync/rasync_test.go
git commit -m "feat(rasync): merge TL baselines and write tl-events fixtures"
```

---

## Task 4: `cmd/agent-ra-sync` binary + `config/ra-sync.yaml`

**Files:**
- Create: `cmd/agent-ra-sync/main.go`
- Create: `config/ra-sync.yaml`
- Test: `cmd/agent-ra-sync/main_test.go`

**Interfaces:**
- Consumes: `rasync.Config`, `rasync.Run` (Task 3); `raclient.New` (Task 1); `tlclient.New` (`internal/tlclient`).
- Produces: `func loadConfig(path string) (rasync.Config, error)` (package `main`).

- [ ] **Step 1: Write the failing test**

Create `cmd/agent-ra-sync/main_test.go`:

```go
package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfig_ParsesYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ra-sync.yaml")
	if err := os.WriteFile(path, []byte("raUrl: http://ra:18080\ntlUrl: http://tl:18081\nout: fixtures/ra-sync\npageSize: 200\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.RABaseURL != "http://ra:18080" || cfg.TLBaseURL != "http://tl:18081" || cfg.OutDir != "fixtures/ra-sync" || cfg.PageSize != 200 {
		t.Errorf("unexpected cfg: %+v", cfg)
	}
}

func TestLoadConfig_MissingFileIsEmptyConfig(t *testing.T) {
	cfg, err := loadConfig(filepath.Join(t.TempDir(), "nope.yaml"))
	if err != nil {
		t.Fatalf("loadConfig missing: %v", err)
	}
	if cfg != (configZero()) {
		t.Errorf("expected zero config for missing file, got %+v", cfg)
	}
}
```

Note: `configZero()` is a tiny test helper defined in the same test file:

```go
import "github.com/agentnameservice/agent-trust-discovery/internal/rasync"

func configZero() rasync.Config { return rasync.Config{} }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./cmd/agent-ra-sync/ -v`
Expected: FAIL — `undefined: loadConfig`.

- [ ] **Step 3: Write the implementation**

Create `cmd/agent-ra-sync/main.go`:

```go
// Command agent-ra-sync captures a fixture snapshot from a (private) ANS RA's
// public event feed (GET /v1/agents/events) and the Transparency Log, writing
// the tl-events/ fixture YAML the existing agent-hydrator-stub and agent-prober
// consume unchanged. All orchestration lives in internal/rasync; this file is
// thin wiring: CLI parsing, config-file merge, and process lifecycle.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/agentnameservice/agent-trust-discovery/internal/raclient"
	"github.com/agentnameservice/agent-trust-discovery/internal/rasync"
	"github.com/agentnameservice/agent-trust-discovery/internal/tlclient"
)

const (
	httpTimeout = 30 * time.Second
	runTimeout  = 5 * time.Minute
)

func main() {
	os.Exit(run(os.Args[1:], os.Stderr))
}

func run(args []string, stderr *os.File) int {
	fs := flag.NewFlagSet("agent-ra-sync", flag.ContinueOnError)
	fs.SetOutput(stderr)

	configPath := fs.String("config", "config/ra-sync.yaml", "path to the ra-sync config YAML")
	raURL := fs.String("ra-url", "", "RA event-feed base URL (override config)")
	tlURL := fs.String("tl-url", "", "Transparency Log base URL (override config)")
	out := fs.String("out", "", "output directory for fixture YAML (override config)")
	pageSize := fs.Int("page-size", 0, "feed page size 1..200 (default 100)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	cfg, err := loadConfig(*configPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if *raURL != "" {
		cfg.RABaseURL = *raURL
	}
	if *tlURL != "" {
		cfg.TLBaseURL = *tlURL
	}
	if *out != "" {
		cfg.OutDir = *out
	}
	if *pageSize > 0 {
		cfg.PageSize = *pageSize
	}
	if cfg.RABaseURL == "" || cfg.TLBaseURL == "" || cfg.OutDir == "" {
		fmt.Fprintln(stderr, "agent-ra-sync: --ra-url, --tl-url, and --out are required (via config or flag)")
		return 1
	}

	logger := slog.New(slog.NewJSONHandler(stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	httpClient := &http.Client{Timeout: httpTimeout}
	ctx, cancel := context.WithTimeout(context.Background(), runTimeout)
	defer cancel()

	if _, err := rasync.Run(ctx, raclient.New(httpClient), tlclient.New(httpClient), cfg, logger); err != nil {
		logger.ErrorContext(ctx, "rasync: run failed", "error", err)
		return 1
	}
	return 0
}

// configFile is the on-disk schema for config/ra-sync.yaml. CLI flags override.
type configFile struct {
	RAURL    string `yaml:"raUrl"`
	TLURL    string `yaml:"tlUrl"`
	Out      string `yaml:"out"`
	PageSize int    `yaml:"pageSize"`
}

func loadConfig(path string) (rasync.Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return rasync.Config{}, nil // config optional when all flags are set
		}
		return rasync.Config{}, fmt.Errorf("agent-ra-sync: read config %s: %w", path, err)
	}
	var cf configFile
	if err := yaml.Unmarshal(b, &cf); err != nil {
		return rasync.Config{}, fmt.Errorf("agent-ra-sync: parse config %s: %w", path, err)
	}
	return rasync.Config{RABaseURL: cf.RAURL, TLBaseURL: cf.TLURL, OutDir: cf.Out, PageSize: cf.PageSize}, nil
}
```

- [ ] **Step 4: Create the default config**

Create `config/ra-sync.yaml`:

```yaml
# agent-ra-sync config. Points at a (private) ANS RA's public event feed and its
# Transparency Log. CLI flags (--ra-url/--tl-url/--out/--page-size) override.
#
# The feed is anonymous; no credentials are configured or sent.
raUrl:    http://localhost:18080   # ans-ra: GET /v1/agents/events
tlUrl:    http://localhost:18081   # ans-tl: GET /v1/agents/{ansId}
out:      fixtures/ra-sync
pageSize: 100                       # 1..200
```

- [ ] **Step 5: Run the tests to verify they pass, and build the binary**

Run: `go test ./cmd/agent-ra-sync/ -race -v && go build ./cmd/agent-ra-sync`
Expected: PASS, and the binary compiles.

- [ ] **Step 6: Commit**

```bash
git add cmd/agent-ra-sync/ config/ra-sync.yaml
git commit -m "feat(agent-ra-sync): binary + config wiring the RA feed producer"
```

---

## Task 5: Demo wiring — `demo-ra` pipeline

**Files:**
- Create: `config/hydrator.ra-sync.yaml`
- Create: `config/prober.ra-sync.yaml`
- Create: `scripts/demo/run-demo-ra.sh`
- Modify: `Makefile` (add the `demo-ra` target)

**Interfaces:**
- Consumes: the `agent-ra-sync` binary (Task 4); existing `agent-trust-discovery`, `agent-hydrator-stub`, `agent-prober` binaries; existing `config/demo-live.runtime.yaml`, `scripts/demo/walkthrough-live.sh`.
- Produces: `make demo-ra`.

**Note:** `demo-ra` requires a reachable ANS RA feed + TL (e.g. a locally running `ans-ra`/`ans-tl`, or a deployment URL via `RA_URL`/`TL_URL`). Unlike `make demo`, it is not part of `make check` and is not run in CI; it is an operator/dev convenience mirroring `make demo-live`.

- [ ] **Step 1: Create the hydrator config for the ra-sync fixtures**

Create `config/hydrator.ra-sync.yaml`:

```yaml
# agent-hydrator-stub config for the ra-sync demo. Reads fixtures captured by
# agent-ra-sync. real mode → imports agents only; agent-prober supplies live
# observations (identical topology to hydrator.snapshot.yaml, different dir).
mode: real
target:
  url: http://localhost:8080
  adminKey: ""
source:
  tlEventsDir:     fixtures/ra-sync/tl-events   # written by agent-ra-sync
  observationsDir: fixtures/observations         # unused in real mode
provenance:
  aimId: did:web:ra-sync-demo-aim.local
```

- [ ] **Step 2: Create the prober config for the ra-sync fixtures**

Create `config/prober.ra-sync.yaml`:

```yaml
# agent-prober config for the ra-sync demo. Same binary/code as always — only
# tlEventsDir points at the ra-sync capture.
target:
  url: http://localhost:8080
  adminKey: ""
source:
  tlEventsDir: fixtures/ra-sync/tl-events
probe:
  cadence: 0
  timeout: 10s
provenance:
  aimId: did:web:ra-sync-demo-prober.local
```

- [ ] **Step 3: Create the demo script**

Create `scripts/demo/run-demo-ra.sh`:

```bash
#!/usr/bin/env bash
# run-demo-ra.sh — ra-sync variant of run-demo-live.sh. Captures a fixture set
# from a (private) ANS RA event feed + Transparency Log via agent-ra-sync, then
# runs the unchanged hydrator/prober pipeline against those fixtures.
#
# Requires a reachable RA + TL. Override with RA_URL / TL_URL:
#   RA_URL=http://localhost:18080 TL_URL=http://localhost:18081 make demo-ra
set -euo pipefail

PORT="${PORT:-8080}"
BIN="${BIN:-./bin}"
DB=/tmp/agent-trust-discovery-ra-demo.db
SERVER_LOG=/tmp/agent-trust-discovery-ra-demo.log
OUT="${OUT:-fixtures/ra-sync}"
RA_URL="${RA_URL:-http://localhost:18080}"
TL_URL="${TL_URL:-http://localhost:18081}"

rm -f "$DB"

echo "▶ capturing from RA feed $RA_URL (TL $TL_URL) via agent-ra-sync..."
"$BIN/agent-ra-sync" --ra-url "$RA_URL" --tl-url "$TL_URL" --out "$OUT"

echo "▶ booting agent-trust-discovery on :$PORT (config/demo-live.runtime.yaml, no auth)…"
echo "  (server logs -> $SERVER_LOG)"
"$BIN/agent-trust-discovery" -config config/demo-live.runtime.yaml >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!
cleanup() { kill "$SERVER_PID" 2>/dev/null || true; wait "$SERVER_PID" 2>/dev/null || true; }
trap cleanup EXIT

ready=""
for _ in $(seq 1 50); do
	if curl -fsS "http://localhost:$PORT/health" >/dev/null 2>&1; then ready=1; break; fi
	sleep 0.1
done
if [ -z "$ready" ]; then echo "✗ agent-trust-discovery did not become ready on :$PORT" >&2; exit 1; fi

echo "▶ running agent-hydrator-stub (real mode) against agent-trust-discovery…"
"$BIN/agent-hydrator-stub" -config config/hydrator.ra-sync.yaml

echo "▶ running agent-prober (live DNS/TLS) against the captured hosts…"
"$BIN/agent-prober" -config config/prober.ra-sync.yaml

echo "▶ running the live walkthrough…"
BASE="http://localhost:$PORT" bash scripts/demo/walkthrough-live.sh
```

Then make it executable:

```bash
chmod +x scripts/demo/run-demo-ra.sh
```

- [ ] **Step 4: Add the Makefile target**

In `Makefile`, immediately after the `demo-live:` target's recipe (after its `@bash scripts/demo/run-demo-live.sh` line), add:

```makefile
# ra-sync demo: capture from a (private) ANS RA event feed via agent-ra-sync,
# then run the unchanged hydrator/prober pipeline. Requires a reachable RA + TL
# (RA_URL / TL_URL). Not part of `make check`.
demo-ra:
	@echo "Building ra-sync demo binaries into $(GOBIN)..."
	@go build $(GOFLAGS) -o $(GOBIN)/agent-trust-discovery ./cmd/agent-trust-discovery
	@go build $(GOFLAGS) -o $(GOBIN)/agent-ra-sync ./cmd/agent-ra-sync
	@go build $(GOFLAGS) -o $(GOBIN)/agent-hydrator-stub ./cmd/agent-hydrator-stub
	@go build $(GOFLAGS) -o $(GOBIN)/agent-prober ./cmd/agent-prober
	@bash scripts/demo/run-demo-ra.sh
```

Also add `demo-ra` to the `.PHONY` list on line 2 (append it to the existing `cover-domain demo demo-live` entry so it reads `... demo demo-live demo-ra`).

- [ ] **Step 5: Verify build wiring (no live RA needed)**

Run: `go build ./... && grep -n "demo-ra" Makefile && test -x scripts/demo/run-demo-ra.sh && echo OK`
Expected: builds clean; grep shows the `.PHONY` entry and the target; script is executable; prints `OK`.

- [ ] **Step 6: Commit**

```bash
git add config/hydrator.ra-sync.yaml config/prober.ra-sync.yaml scripts/demo/run-demo-ra.sh Makefile
git commit -m "feat(demo): demo-ra pipeline wiring agent-ra-sync into hydrator/prober"
```

---

## Final verification

- [ ] **Full test + vet + build**

Run: `go build ./... && go vet ./... && go test ./... -race -count=1`
Expected: all pass.

- [ ] **Coverage of the new packages ≥ 80%**

Run: `go test ./internal/raclient/ ./internal/rasync/ ./cmd/agent-ra-sync/ -cover`
Expected: each ≥ 80%. If short, add table cases (e.g. `toEvent` with multiple endpoints/transports, unknown eventType skipped by the fold, oversized feed body).

---

## Self-review notes (traceability to the spec)

- Spec §4/§5 (feed → fold → TL-enrich → fixtures; hydrator/prober unchanged) → Tasks 1–3.
- Spec §6 (RA unchanged; consume `GET /v1/agents/events` + reuse `tlclient`) → no ANS change; Tasks 1 & 3.
- Spec §7 / §7.1 (producer components; feed→`tlevent.Event` mapping; `firstSeen` from TL badge) → Task 3 `toEvent`.
- Spec §7.2 `emitObservations` (versionstability, dnssec) → **deferred** (Global Constraints); not built.
- Spec §8 (stateless drain, wipe-and-rewrite, cursor stop, refuse-empty, fold safety) → Tasks 2 & 3.
- Spec §9 (config + `make demo-ra`) → Tasks 4 & 5.
- Spec §10 (raclient/fold/fixtures/e2e tests, `-race`, 80%) → tests in every task + Final verification.
- Spec §12 items 1 (stateless + TL-badge firstSeen), 2 (re-implement fold), 4 (TL badge norm), 5 (no ARD URN) → reflected; item 3 (versionstability) intentionally deferred with the rest of §7.2.
