package sqlitestore_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/agentnameservice/agent-trust-discovery/internal/adapter/sqlitestore"
	"github.com/agentnameservice/agent-trust-discovery/internal/domain"
	"github.com/agentnameservice/agent-trust-discovery/internal/port"
)

func seed(t *testing.T, db *sqlitestore.DB, agents ...domain.Agent) {
	t.Helper()
	for _, a := range agents {
		if err := db.UpsertAgent(context.Background(), a); err != nil {
			t.Fatalf("seed %s: %v", a.ID, err)
		}
	}
}

func idsOf(p port.SearchPage) []string {
	out := make([]string, len(p.Items))
	for i, a := range p.Items {
		out[i] = string(a.ID)
	}
	return out
}

func assertIDSet(t *testing.T, p port.SearchPage, want ...string) {
	t.Helper()
	got := idsOf(p)
	gs := append([]string(nil), got...)
	ws := append([]string(nil), want...)
	sort.Strings(gs)
	sort.Strings(ws)
	if len(gs) != len(ws) {
		t.Fatalf("result ids = %v, want %v", got, want)
	}
	for i := range gs {
		if gs[i] != ws[i] {
			t.Fatalf("result ids = %v, want %v", got, want)
		}
	}
}

func mk(id, display, dns, status string, protocols, transports, tags, caps []string) domain.Agent {
	return domain.Agent{
		ID: domain.AgentID(id), DNSName: dns, DisplayName: display,
		Description: "agent " + id, ProviderID: "godaddy", Status: domain.Status(status),
		Protocols: protocols, Transports: transports, Tags: tags, Capabilities: caps,
		FirstSeen:   time.Date(2025, 12, 1, 0, 0, 0, 0, time.UTC),
		LastUpdated: time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC),
	}
}

func threeAgents() []domain.Agent {
	a := mk("agent-a", "Alpha", "ans://v1.0.0.booking.example.com", "ACTIVE",
		[]string{"A2A"}, []string{"HTTP"}, []string{"travel"}, []string{"search-hotels"})
	b := mk("agent-b", "Bravo", "ans://v1.0.0.mail.example.com", "REVOKED",
		[]string{"MCP"}, []string{"SSE"}, []string{"email"}, []string{"send-mail"})
	b.ProviderID = "acme"
	c := mk("agent-c", "Charlie", "ans://v1.0.0.pay.example.com", "ACTIVE",
		[]string{"A2A", "MCP"}, []string{"HTTP"}, []string{"travel", "finance"}, []string{"search-hotels", "pay"})
	return []domain.Agent{a, b, c}
}

func TestSearchTextMatch(t *testing.T) {
	db := newStore(t)
	seed(t, db, threeAgents()...)
	got, err := db.Search(context.Background(), port.SearchQuery{Text: "Alpha"})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	assertIDSet(t, got, "agent-a")
}

func TestSearchMatchAllWhenNoText(t *testing.T) {
	db := newStore(t)
	seed(t, db, threeAgents()...)
	got, err := db.Search(context.Background(), port.SearchQuery{})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	assertIDSet(t, got, "agent-a", "agent-b", "agent-c")
	// No text → deterministic order by display_name.
	if want := []string{"agent-a", "agent-b", "agent-c"}; !sameStrings(idsOf(got), want) {
		t.Errorf("order = %v, want %v", idsOf(got), want)
	}
}

func TestSearchFilters(t *testing.T) {
	db := newStore(t)
	seed(t, db, threeAgents()...)
	ctx := context.Background()
	cases := []struct {
		name string
		q    port.SearchQuery
		want []string
	}{
		{"status ACTIVE", port.SearchQuery{Statuses: []domain.Status{domain.StatusActive}}, []string{"agent-a", "agent-c"}},
		{"provider acme", port.SearchQuery{ProviderIDs: []string{"acme"}}, []string{"agent-b"}},
		{"protocol MCP", port.SearchQuery{Protocols: []string{"MCP"}}, []string{"agent-b", "agent-c"}},
		{"transport SSE", port.SearchQuery{Transports: []string{"SSE"}}, []string{"agent-b"}},
		{"tag travel", port.SearchQuery{Tags: []string{"travel"}}, []string{"agent-a", "agent-c"}},
		{"capability pay", port.SearchQuery{Capabilities: []string{"pay"}}, []string{"agent-c"}},
		{"agentDomain mail", port.SearchQuery{AgentDomains: []string{"mail.example.com"}}, []string{"agent-b"}},
		{"status+tag", port.SearchQuery{Statuses: []domain.Status{domain.StatusActive}, Tags: []string{"travel"}}, []string{"agent-a", "agent-c"}},
		{"none match", port.SearchQuery{Tags: []string{"nonexistent"}}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := db.Search(ctx, tc.q)
			if err != nil {
				t.Fatalf("Search: %v", err)
			}
			assertIDSet(t, got, tc.want...)
		})
	}
}

// The agentDomains filter uses LIKE %v%. Without escaping, ?agentDomains=%
// would match every row (LIKE '%%%' is "any string"). The clause must set
// ESCAPE and escape %, _, and \ so caller-supplied wildcards are literal.
func TestSearchAgentDomainWildcardsAreLiteral(t *testing.T) {
	db := newStore(t)
	seed(t, db, threeAgents()...)
	got, err := db.Search(context.Background(), port.SearchQuery{AgentDomains: []string{"%"}})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(got.Items) != 0 {
		t.Fatalf("expected zero matches for literal '%%' filter; got %v", idsOf(got))
	}
	// Underscore is also a LIKE wildcard — must be treated as literal.
	got, err = db.Search(context.Background(), port.SearchQuery{AgentDomains: []string{"_"}})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(got.Items) != 0 {
		t.Fatalf("expected zero matches for literal '_' filter; got %v", idsOf(got))
	}
}

func TestSearchPaginationAndTotal(t *testing.T) {
	db := newStore(t)
	ctx := context.Background()
	var agents []domain.Agent
	for i := 1; i <= 5; i++ {
		id := fmt.Sprintf("agent-%02d", i)
		agents = append(agents, mk(id, fmt.Sprintf("P%02d", i), "ans://v1.0.0."+id+".example.com",
			"ACTIVE", []string{"A2A"}, []string{"HTTP"}, []string{"t"}, []string{"c"}))
	}
	seed(t, db, agents...)

	p1, err := db.Search(ctx, port.SearchQuery{PageSize: 2, TotalRequired: true})
	if err != nil {
		t.Fatalf("page1: %v", err)
	}
	if len(p1.Items) != 2 || p1.PrevToken != "" || p1.NextToken == "" {
		t.Fatalf("page1 = %v prev=%q next=%q", idsOf(p1), p1.PrevToken, p1.NextToken)
	}
	if p1.TotalItems != 5 || p1.TotalPages != 3 {
		t.Fatalf("totals = %d/%d, want 5/3", p1.TotalItems, p1.TotalPages)
	}

	p2, err := db.Search(ctx, port.SearchQuery{PageSize: 2, PageToken: p1.NextToken})
	if err != nil {
		t.Fatalf("page2: %v", err)
	}
	if len(p2.Items) != 2 || p2.PrevToken == "" || p2.NextToken == "" {
		t.Fatalf("page2 = %v prev=%q next=%q", idsOf(p2), p2.PrevToken, p2.NextToken)
	}

	p3, err := db.Search(ctx, port.SearchQuery{PageSize: 2, PageToken: p2.NextToken})
	if err != nil {
		t.Fatalf("page3: %v", err)
	}
	if len(p3.Items) != 1 || p3.NextToken != "" || p3.PrevToken == "" {
		t.Fatalf("page3 = %v prev=%q next=%q", idsOf(p3), p3.PrevToken, p3.NextToken)
	}
	// Pages must not overlap and must cover all five.
	all := append(append(idsOf(p1), idsOf(p2)...), idsOf(p3)...)
	assertIDSet(t, port.SearchPage{Items: pageOf(all)}, "agent-01", "agent-02", "agent-03", "agent-04", "agent-05")
}

func pageOf(ids []string) []domain.Agent {
	out := make([]domain.Agent, len(ids))
	for i, id := range ids {
		out[i] = domain.Agent{ID: domain.AgentID(id)}
	}
	return out
}

func TestSearchExplicitPage(t *testing.T) {
	db := newStore(t)
	ctx := context.Background()
	var agents []domain.Agent
	for i := 1; i <= 5; i++ {
		id := fmt.Sprintf("agent-%02d", i)
		agents = append(agents, mk(id, fmt.Sprintf("P%02d", i), "ans://v1.0.0."+id+".example.com",
			"ACTIVE", nil, nil, nil, nil))
	}
	seed(t, db, agents...)

	got, err := db.Search(ctx, port.SearchQuery{Page: 2, PageSize: 2})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if want := []string{"agent-03", "agent-04"}; !sameStrings(idsOf(got), want) {
		t.Fatalf("page 2 = %v, want %v", idsOf(got), want)
	}
	if got.PrevToken == "" || got.NextToken == "" {
		t.Fatal("expected prev+next tokens on a middle page")
	}
}

func TestSearchClampsPageSize(t *testing.T) {
	db := newStore(t)
	ctx := context.Background()
	agents := make([]domain.Agent, 0, 101)
	for i := range 101 {
		id := fmt.Sprintf("agent-%03d", i)
		agents = append(agents, mk(id, id, "ans://v1.0.0."+id+".example.com",
			"ACTIVE", nil, nil, nil, nil))
	}
	seed(t, db, agents...)
	got, err := db.Search(ctx, port.SearchQuery{PageSize: 1000})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(got.Items) != 100 {
		t.Fatalf("clamped page size = %d, want 100", len(got.Items))
	}
	if got.NextToken == "" {
		t.Fatal("expected NextToken when more than 100 rows exist")
	}
}

func TestSearchBadTokensFallBackToPageOne(t *testing.T) {
	db := newStore(t)
	seed(t, db, threeAgents()...)
	ctx := context.Background()
	bad := []string{
		"!!!not-base64!!!",
		base64.RawURLEncoding.EncodeToString([]byte("q:2")),   // wrong prefix
		base64.RawURLEncoding.EncodeToString([]byte("p:abc")), // non-numeric
		base64.RawURLEncoding.EncodeToString([]byte("p:0")),   // < 1
	}
	for _, tok := range bad {
		got, err := db.Search(ctx, port.SearchQuery{PageToken: tok})
		if err != nil {
			t.Fatalf("Search(%q): %v", tok, err)
		}
		// Falls back to page 1 → all three returned.
		assertIDSet(t, got, "agent-a", "agent-b", "agent-c")
	}
}
