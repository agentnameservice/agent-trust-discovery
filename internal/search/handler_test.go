package search_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/agentnameservice/agent-trust-discovery/internal/adapter/sqlitestore"
	"github.com/agentnameservice/agent-trust-discovery/internal/domain"
	"github.com/agentnameservice/agent-trust-discovery/internal/scoring/engine"
	"github.com/agentnameservice/agent-trust-discovery/internal/scoring/registry"
	"github.com/agentnameservice/agent-trust-discovery/internal/search"
	"github.com/agentnameservice/agent-trust-discovery/internal/web"
)

func newHandler(t *testing.T) (*search.Handler, *sqlitestore.DB) {
	t.Helper()
	svc, store := newService(t)
	return search.NewHandler(svc), store
}

func doReq(hf http.HandlerFunc, method, target, body string) *httptest.ResponseRecorder {
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, target, nil)
	} else {
		r = httptest.NewRequest(method, target, strings.NewReader(body))
	}
	rec := httptest.NewRecorder()
	hf(rec, r)
	return rec
}

func doDetail(h *search.Handler, id, profile string) *httptest.ResponseRecorder {
	target := "/v1/ans/registered-agents/" + id
	if profile != "" {
		target += "?profile=" + profile
	}
	r := httptest.NewRequest(http.MethodGet, target, nil)
	r.SetPathValue("agentId", id)
	rec := httptest.NewRecorder()
	h.Detail(rec, r)
	return rec
}

type resultsView struct {
	Items []map[string]any `json:"items"`
	Links []struct {
		Rel    string `json:"rel"`
		Method string `json:"method"`
		Href   string `json:"href"`
	} `json:"links"`
	TotalItems *int `json:"totalItems"`
	TotalPages *int `json:"totalPages"`
}

func decodeResults(t *testing.T, rec *httptest.ResponseRecorder) resultsView {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var v resultsView
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode results: %v; body=%s", err, rec.Body.String())
	}
	return v
}

func linkRel(v resultsView, rel string) (string, bool) {
	for _, l := range v.Links {
		if l.Rel == rel {
			return l.Href, true
		}
	}
	return "", false
}

func assertProblem(t *testing.T, rec *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if rec.Code != status {
		t.Errorf("status = %d, want %d; body=%s", rec.Code, status, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
		t.Errorf("Content-Type = %q, want application/problem+json", ct)
	}
	var p web.Problem
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatalf("body not problem JSON: %v", err)
	}
	if p.Code != code {
		t.Errorf("code = %q, want %q", p.Code, code)
	}
}

func TestHealth(t *testing.T) {
	h, _ := newHandler(t)
	rec := doReq(h.Health, http.MethodGet, "/health", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if rec.Body.String() != "ok" {
		t.Errorf("body = %q, want ok", rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("Content-Type = %q, want text/plain", ct)
	}
}

func TestSearchByQuery_ReturnsItemsAndSelfLink(t *testing.T) {
	h, store := newHandler(t)
	seedAgent(t, store, "a1", fixedNow())
	seedAgent(t, store, "a2", fixedNow())

	v := decodeResults(t, doReq(h.SearchByQuery, http.MethodGet, "/v1/ans/registered-agents", ""))
	if len(v.Items) != 2 {
		t.Errorf("items = %d, want 2", len(v.Items))
	}
	href, ok := linkRel(v, "self")
	if !ok {
		t.Fatal("missing self link")
	}
	if !strings.HasPrefix(href, "/v1/ans/registered-agents") {
		t.Errorf("self href = %q", href)
	}
}

func TestSearchByQuery_StatusFilter(t *testing.T) {
	h, store := newHandler(t)
	seedAgent(t, store, "active1", fixedNow())
	// A revoked agent the filter must exclude.
	revoked := domain.Agent{ID: "revoked1", DNSName: "ans://revoked1", DisplayName: "R", Status: domain.StatusRevoked, FirstSeen: fixedNow(), LastUpdated: fixedNow()}
	if err := store.UpsertAgent(context.Background(), revoked); err != nil {
		t.Fatalf("seed revoked: %v", err)
	}

	v := decodeResults(t, doReq(h.SearchByQuery, http.MethodGet, "/v1/ans/registered-agents?statuses=REVOKED", ""))
	if len(v.Items) != 1 {
		t.Fatalf("items = %d, want 1", len(v.Items))
	}
	if v.Items[0]["agentId"] != "revoked1" {
		t.Errorf("item = %v, want revoked1", v.Items[0]["agentId"])
	}
}

func TestSearchByQuery_BadParams(t *testing.T) {
	// The split follows design §5.2: 400 for syntactic failures the request
	// couldn't even parse into a well-formed shape, 422 for semantic ones
	// (enum mismatches, per-filter caps).
	cases := []struct {
		name       string
		target     string
		wantStatus int
		wantCode   string
	}{
		{"non-int pageSize", "/v1/ans/registered-agents?pageSize=abc", http.StatusBadRequest, search.CodeInvalidRequest},
		{"non-int page", "/v1/ans/registered-agents?page=xyz", http.StatusBadRequest, search.CodeInvalidRequest},
		{"non-bool totalRequired", "/v1/ans/registered-agents?totalRequired=maybe", http.StatusBadRequest, search.CodeInvalidRequest},
		{"invalid status enum", "/v1/ans/registered-agents?statuses=BOGUS", http.StatusUnprocessableEntity, search.CodeInvalidValue},
		{"bad direction enum", "/v1/ans/registered-agents?pageTokenDirection=sideways", http.StatusUnprocessableEntity, search.CodeInvalidValue},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, _ := newHandler(t)
			rec := doReq(h.SearchByQuery, http.MethodGet, tc.target, "")
			assertProblem(t, rec, tc.wantStatus, tc.wantCode)
		})
	}
}

func TestSearchByQuery_PaginationLinksAndTotals(t *testing.T) {
	h, store := newHandler(t)
	for _, id := range []string{"a1", "a2", "a3"} {
		seedAgent(t, store, id, fixedNow())
	}

	// Page 1 of size 1: a next link, no prev, totals reported.
	p1 := decodeResults(t, doReq(h.SearchByQuery, http.MethodGet, "/v1/ans/registered-agents?pageSize=1&page=1&totalRequired=true", ""))
	if len(p1.Items) != 1 {
		t.Fatalf("page1 items = %d, want 1", len(p1.Items))
	}
	if p1.TotalItems == nil || *p1.TotalItems != 3 || p1.TotalPages == nil || *p1.TotalPages != 3 {
		t.Errorf("totals = %v/%v, want 3/3", p1.TotalItems, p1.TotalPages)
	}
	if _, ok := linkRel(p1, "next"); !ok {
		t.Error("page1 missing next link")
	}
	if _, ok := linkRel(p1, "prev"); ok {
		t.Error("page1 should not have a prev link")
	}

	// Page 2: both prev and next.
	p2 := decodeResults(t, doReq(h.SearchByQuery, http.MethodGet, "/v1/ans/registered-agents?pageSize=1&page=2", ""))
	if _, ok := linkRel(p2, "prev"); !ok {
		t.Error("page2 missing prev link")
	}
	next, ok := linkRel(p2, "next")
	if !ok {
		t.Error("page2 missing next link")
	}
	if !strings.Contains(next, "pageToken=") {
		t.Errorf("next href should carry a pageToken: %q", next)
	}
}

func TestSearchByBody_FiltersAndItems(t *testing.T) {
	h, store := newHandler(t)
	seedAgent(t, store, "active1", fixedNow())
	revoked := domain.Agent{ID: "revoked1", DNSName: "ans://revoked1", DisplayName: "R", Status: domain.StatusRevoked, FirstSeen: fixedNow(), LastUpdated: fixedNow()}
	_ = store.UpsertAgent(context.Background(), revoked)

	v := decodeResults(t, doReq(h.SearchByBody, http.MethodPost, "/v1/ans/search-registered-agents", `{"statuses":["ACTIVE"]}`))
	if len(v.Items) != 1 || v.Items[0]["agentId"] != "active1" {
		t.Errorf("items = %v, want [active1]", v.Items)
	}
}

func TestSearchByBody_BadJSON(t *testing.T) {
	h, _ := newHandler(t)
	rec := doReq(h.SearchByBody, http.MethodPost, "/v1/ans/search-registered-agents", `{`)
	assertProblem(t, rec, http.StatusBadRequest, search.CodeInvalidRequest)
}

// A transposed / different body field ("stauses" for "statuses",
// "pageSizes" for "pageSize") used to silently decode to the zero value and
// return unexpected results; DisallowUnknownFields turns it into a 400 the
// caller can fix at authoring time.
//
// Note: pure case typos ("pagesize" for "pageSize") do NOT trip this — Go's
// encoding/json matches struct tags case-insensitively, so a case-only typo
// resolves to the correct field. Only fields that don't match any known one
// at all — different letters, transpositions, unknown names — reach here.
func TestSearchByBody_RejectsUnknownField(t *testing.T) {
	h, _ := newHandler(t)
	rec := doReq(h.SearchByBody, http.MethodPost, "/v1/ans/search-registered-agents", `{"stauses": ["ACTIVE"]}`)
	assertProblem(t, rec, http.StatusBadRequest, search.CodeInvalidRequest)
}

func TestSearchByBody_InvalidStatus(t *testing.T) {
	h, _ := newHandler(t)
	rec := doReq(h.SearchByBody, http.MethodPost, "/v1/ans/search-registered-agents", `{"statuses":["NOPE"]}`)
	assertProblem(t, rec, http.StatusUnprocessableEntity, search.CodeInvalidValue)
}

// A POST body whose filter array exceeds the per-filter cap must be rejected
// with 400 INVALID_REQUEST, so a caller can never compile a SQL statement with
// thousands of placeholders (SQLite's SQLITE_MAX_VARIABLE_NUMBER default: 999).
func TestSearchByBody_RejectsOverlongFilterArray(t *testing.T) {
	h, _ := newHandler(t)
	// 101 tag values — one over the cap.
	tags := make([]string, 0, 101)
	for i := range 101 {
		tags = append(tags, fmt.Sprintf(`"t%d"`, i))
	}
	body := `{"tags":[` + strings.Join(tags, ",") + `]}`
	rec := doReq(h.SearchByBody, http.MethodPost, "/v1/ans/search-registered-agents", body)
	assertProblem(t, rec, http.StatusUnprocessableEntity, search.CodeInvalidValue)
}

func TestDetail_Happy(t *testing.T) {
	h, store := newHandler(t)
	seedAgent(t, store, "a1", fixedNow())
	appendObs(t, store, "a1", "certtype", `{"type":"DV"}`)

	rec := doDetail(h, "a1", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}

	var detail struct {
		AgentID         string         `json:"agentId"`
		TrustEvaluation map[string]any `json:"trustEvaluation"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &detail); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if detail.AgentID != "a1" {
		t.Errorf("agentId = %q", detail.AgentID)
	}
	te := detail.TrustEvaluation
	if te["scoringProfile"] != "default" {
		t.Errorf("scoringProfile = %v, want default", te["scoringProfile"])
	}
	// verificationTier must be present AND null in v1.
	tier, present := te["verificationTier"]
	if !present || tier != nil {
		t.Errorf("verificationTier = %v (present=%v), want null", tier, present)
	}
	// compositeScore must NOT be emitted (spec §2.4).
	if _, ok := te["compositeScore"]; ok {
		t.Error("compositeScore must not be present")
	}
	tv, _ := te["trustVector"].(map[string]any)
	if tv["identity"].(float64) != 40 {
		t.Errorf("identity = %v, want 40 (DV)", tv["identity"])
	}
	dims, _ := te["dimensions"].([]any)
	if len(dims) != len(domain.AllDimensions()) {
		t.Errorf("dimensions = %d, want %d", len(dims), len(domain.AllDimensions()))
	}
}

func TestDetailHandler_NotFound(t *testing.T) {
	h, _ := newHandler(t)
	rec := doDetail(h, "ghost", "")
	assertProblem(t, rec, http.StatusNotFound, search.CodeNotFound)
}

func TestDetailHandler_UnknownProfile(t *testing.T) {
	h, store := newHandler(t)
	seedAgent(t, store, "a1", fixedNow())
	rec := doDetail(h, "a1", "no-such-profile")
	// Unknown profile is a well-formed request naming a resource that doesn't
	// exist — semantic-value failure per design §5.2 → 422.
	assertProblem(t, rec, http.StatusUnprocessableEntity, search.CodeUnknownProfile)
}

func TestSearchByQuery_EchoesFiltersInSelfLink(t *testing.T) {
	h, store := newHandler(t)
	seedAgent(t, store, "a1", fixedNow())

	v := decodeResults(t, doReq(h.SearchByQuery, http.MethodGet, "/v1/ans/registered-agents?query=Agent&providerIds=godaddy", ""))
	href, ok := linkRel(v, "self")
	if !ok {
		t.Fatal("missing self link")
	}
	if !strings.Contains(href, "query=Agent") || !strings.Contains(href, "providerIds=godaddy") {
		t.Errorf("self href should echo the filters: %q", href)
	}
}

func TestSearchByQuery_FollowNextToken(t *testing.T) {
	h, store := newHandler(t)
	for _, id := range []string{"a1", "a2"} {
		seedAgent(t, store, id, fixedNow())
	}
	p1 := decodeResults(t, doReq(h.SearchByQuery, http.MethodGet, "/v1/ans/registered-agents?pageSize=1", ""))
	next, ok := linkRel(p1, "next")
	if !ok {
		t.Fatal("page1 missing next link")
	}

	p2 := decodeResults(t, doReq(h.SearchByQuery, http.MethodGet, next, ""))
	if len(p2.Items) != 1 {
		t.Fatalf("page2 via token items = %d, want 1", len(p2.Items))
	}
	self2, _ := linkRel(p2, "self")
	if !strings.Contains(self2, "pageToken=") {
		t.Errorf("page2 self link should carry the pageToken: %q", self2)
	}
}

func TestDetailHandler_MissingAgentID(t *testing.T) {
	h, _ := newHandler(t)
	// No path value set → handler must reject with 400 rather than look up "".
	r := httptest.NewRequest(http.MethodGet, "/v1/ans/registered-agents/", nil)
	rec := httptest.NewRecorder()
	h.Detail(rec, r)
	assertProblem(t, rec, http.StatusBadRequest, search.CodeInvalidRequest)
}

func TestSearchByQuery_IndexErrorIs500(t *testing.T) {
	eng := engine.New(failingStore{}, registry.New(), engine.DefaultThresholds(), fixedNow)
	h := search.NewHandler(search.New(failingStore{}, failingStore{}, eng, nil))
	rec := doReq(h.SearchByQuery, http.MethodGet, "/v1/ans/registered-agents", "")
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500; body=%s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
		t.Errorf("Content-Type = %q, want application/problem+json", ct)
	}
}

func TestDetail_ProfileReweight(t *testing.T) {
	h, store := newHandler(t)
	seedAgent(t, store, "a1", fixedNow())
	appendObs(t, store, "a1", "certtype", `{"type":"EV"}`)
	appendObs(t, store, "a1", "dnssecurity", `{"dnssec":true,"caa":true}`)

	profileOf := func(rec *httptest.ResponseRecorder) string {
		t.Helper()
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d; body=%s", rec.Code, rec.Body.String())
		}
		var d struct {
			TrustEvaluation struct {
				RecommendedProfile string `json:"recommendedProfile"`
			} `json:"trustEvaluation"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &d)
		return d.TrustEvaluation.RecommendedProfile
	}

	def := profileOf(doDetail(h, "a1", "default"))
	strict := profileOf(doDetail(h, "a1", "identity-strict"))
	if def == strict {
		t.Errorf("expected the profile to change classification; both = %q", def)
	}
}
