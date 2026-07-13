package search

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"

	"github.com/agentnameservice/agent-trust-discovery/internal/domain"
	"github.com/agentnameservice/agent-trust-discovery/internal/port"
	"github.com/agentnameservice/agent-trust-discovery/internal/web"
)

// searchBasePath is the GET search route; pagination links point here so a
// client can follow self/prev/next via cursor tokens regardless of whether the
// original request was the GET or POST search.
const searchBasePath = "/v1/ans/registered-agents"

// Handler is the HTTP adapter for the read API. Methods are plain
// http.HandlerFunc so they test directly with httptest; routing is Phase 7.
type Handler struct {
	svc *Service
}

// NewHandler constructs a Handler over the given service.
func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

// SearchByQuery handles GET /v1/ans/registered-agents.
func (h *Handler) SearchByQuery(w http.ResponseWriter, r *http.Request) {
	q, err := parseSearchQuery(r.URL.Query())
	if err != nil {
		web.WriteProblemCtx(r.Context(), w, err)
		return
	}
	h.runSearch(w, r, q)
}

// SearchByBody handles POST /v1/ans/search-registered-agents. Unknown JSON
// fields are rejected — a misspelled field ("pagesize", "stauses") would
// otherwise silently decode to the zero value and return unexpected results.
func (h *Handler) SearchByBody(w http.ResponseWriter, r *http.Request) {
	var dto searchRequestDTO
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&dto); err != nil {
		web.WriteProblemCtx(r.Context(), w, errInvalidRequest("request body is not valid JSON: "+err.Error()))
		return
	}
	q, err := dto.toQuery()
	if err != nil {
		web.WriteProblemCtx(r.Context(), w, err)
		return
	}
	h.runSearch(w, r, q)
}

func (h *Handler) runSearch(w http.ResponseWriter, r *http.Request, q port.SearchQuery) {
	page, err := h.svc.Search(r.Context(), q)
	if err != nil {
		web.WriteProblemCtx(r.Context(), w, err)
		return
	}
	items := make([]registeredAgentDTO, 0, len(page.Items))
	for _, a := range page.Items {
		items = append(items, newRegisteredAgentDTO(a))
	}
	web.WriteJSON(w, http.StatusOK, newSearchResultsDTO(items, buildLinks(q, page), page, q.TotalRequired))
}

// Detail handles GET /v1/ans/registered-agents/{agentId}.
func (h *Handler) Detail(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("agentId")
	if id == "" {
		web.WriteProblemCtx(r.Context(), w, errInvalidRequest("agentId is required"))
		return
	}
	agent, eval, err := h.svc.Detail(r.Context(), domain.AgentID(id), r.URL.Query().Get("profile"))
	if err != nil {
		web.WriteProblemCtx(r.Context(), w, err)
		return
	}
	web.WriteJSON(w, http.StatusOK, agentDetailDTO{
		registeredAgentDTO: newRegisteredAgentDTO(agent),
		TrustEvaluation:    newTrustEvaluationDTO(eval),
	})
}

// Health handles GET /health: an always-open liveness probe (design §5.3).
func (h *Handler) Health(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// buildLinks builds the self/prev/next links (design §5.1). self is always
// present; prev/next appear only when the store returned the corresponding
// cursor token.
func buildLinks(q port.SearchQuery, page port.SearchPage) []linkDTO {
	links := []linkDTO{{Rel: "self", Method: http.MethodGet, Href: hrefFor(q, "")}}
	if page.PrevToken != "" {
		links = append(links, linkDTO{Rel: "prev", Method: http.MethodGet, Href: hrefFor(q, page.PrevToken)})
	}
	if page.NextToken != "" {
		links = append(links, linkDTO{Rel: "next", Method: http.MethodGet, Href: hrefFor(q, page.NextToken)})
	}
	return links
}

// hrefFor renders a navigable URL for the query. An empty pageToken yields the
// self link; a non-empty one replaces the cursor and drops the page number.
func hrefFor(q port.SearchQuery, pageToken string) string {
	v := queryValues(q)
	if pageToken != "" {
		v.Set("pageToken", pageToken)
		v.Del("page")
	}
	enc := v.Encode()
	if enc == "" {
		return searchBasePath
	}
	return searchBasePath + "?" + enc
}

func queryValues(q port.SearchQuery) url.Values {
	v := url.Values{}
	if q.Text != "" {
		v.Set("query", q.Text)
	}
	if q.PageSize > 0 {
		v.Set("pageSize", strconv.Itoa(q.PageSize))
	}
	if q.Page > 0 {
		v.Set("page", strconv.Itoa(q.Page))
	}
	if q.PageToken != "" {
		v.Set("pageToken", q.PageToken)
	}
	if q.TotalRequired {
		v.Set("totalRequired", "true")
	}
	addAll(v, "providerIds", q.ProviderIDs)
	addAll(v, "statuses", statusStrings(q.Statuses))
	addAll(v, "agentDomains", q.AgentDomains)
	addAll(v, "protocols", q.Protocols)
	addAll(v, "transports", q.Transports)
	addAll(v, "tags", q.Tags)
	addAll(v, "capabilities", q.Capabilities)
	return v
}

func addAll(v url.Values, key string, vals []string) {
	for _, s := range vals {
		v.Add(key, s)
	}
}

func statusStrings(ss []domain.Status) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = string(s)
	}
	return out
}
