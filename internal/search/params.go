package search

import (
	"fmt"
	"net/url"
	"strconv"

	"github.com/agentnameservice/agent-trust-discovery/internal/domain"
	"github.com/agentnameservice/agent-trust-discovery/internal/port"
)

// maxFilterEntries caps the length of each repeatable filter array. SQLite's
// SQLITE_MAX_VARIABLE_NUMBER defaults to 999, and the store builds one IN
// placeholder per entry across seven filter fields; 100 apiece keeps us
// comfortably under that ceiling and rejects the pathological POST body long
// before compilation cost matters.
const maxFilterEntries = 100

// parseSearchQuery maps GET query parameters (design §5.1) onto a SearchQuery.
// Repeatable filters use the form/explode convention (?tags=a&tags=b). The
// profile and language params are accepted for production parity but do not
// affect search in v1 (search items carry no per-result scores; no i18n), so
// they are not read here. pageSize/page range is left to the store to clamp.
//
// Failures split by the design §5.2 rule: 400 for syntactic problems the
// request couldn't even parse into a well-formed shape (non-integer, non-
// boolean), 422 for semantic ones (enum mismatch, per-filter cap).
func parseSearchQuery(values url.Values) (port.SearchQuery, error) {
	q := port.SearchQuery{
		Text:               values.Get("query"),
		ProviderIDs:        values["providerIds"],
		AgentDomains:       values["agentDomains"],
		Protocols:          values["protocols"],
		Transports:         values["transports"],
		Tags:               values["tags"],
		Capabilities:       values["capabilities"],
		PageToken:          values.Get("pageToken"),
		PageTokenDirection: values.Get("pageTokenDirection"),
	}

	statuses, err := parseStatuses(values["statuses"])
	if err != nil {
		return port.SearchQuery{}, err
	}
	q.Statuses = statuses

	if q.PageSize, err = parseIntParam(values, "pageSize"); err != nil {
		return port.SearchQuery{}, err
	}
	if q.Page, err = parseIntParam(values, "page"); err != nil {
		return port.SearchQuery{}, err
	}
	if q.TotalRequired, err = parseBoolParam(values, "totalRequired"); err != nil {
		return port.SearchQuery{}, err
	}
	if err := validateDirection(q.PageTokenDirection); err != nil {
		return port.SearchQuery{}, err
	}
	if err := validateFilterCounts(q); err != nil {
		return port.SearchQuery{}, err
	}
	return q, nil
}

// validateFilterCounts enforces the per-filter length cap so a pathological
// request cannot compile into a SQL statement with thousands of placeholders.
func validateFilterCounts(q port.SearchQuery) error {
	filters := [...]struct {
		name  string
		count int
	}{
		{"providerIds", len(q.ProviderIDs)},
		{"statuses", len(q.Statuses)},
		{"agentDomains", len(q.AgentDomains)},
		{"protocols", len(q.Protocols)},
		{"transports", len(q.Transports)},
		{"tags", len(q.Tags)},
		{"capabilities", len(q.Capabilities)},
	}
	for _, f := range filters {
		if f.count > maxFilterEntries {
			return errInvalidValue(fmt.Sprintf(
				"%s has %d entries; the per-filter limit is %d", f.name, f.count, maxFilterEntries))
		}
	}
	return nil
}

// searchRequestDTO is the POST JSON body (spec SearchRequest). It carries the
// same filters as the GET route plus page-number pagination; pageToken/
// direction are GET-only in the spec.
type searchRequestDTO struct {
	Query         string   `json:"query"`
	PageSize      int      `json:"pageSize"`
	Page          int      `json:"page"`
	TotalRequired bool     `json:"totalRequired"`
	ProviderIDs   []string `json:"providerIds"`
	Statuses      []string `json:"statuses"`
	AgentDomains  []string `json:"agentDomains"`
	Protocols     []string `json:"protocols"`
	Transports    []string `json:"transports"`
	Tags          []string `json:"tags"`
	Capabilities  []string `json:"capabilities"`
}

func (d searchRequestDTO) toQuery() (port.SearchQuery, error) {
	statuses, err := parseStatuses(d.Statuses)
	if err != nil {
		return port.SearchQuery{}, err
	}
	q := port.SearchQuery{
		Text:          d.Query,
		PageSize:      d.PageSize,
		Page:          d.Page,
		TotalRequired: d.TotalRequired,
		ProviderIDs:   d.ProviderIDs,
		Statuses:      statuses,
		AgentDomains:  d.AgentDomains,
		Protocols:     d.Protocols,
		Transports:    d.Transports,
		Tags:          d.Tags,
		Capabilities:  d.Capabilities,
	}
	if err := validateFilterCounts(q); err != nil {
		return port.SearchQuery{}, err
	}
	return q, nil
}

func parseStatuses(raw []string) ([]domain.Status, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	out := make([]domain.Status, 0, len(raw))
	for _, s := range raw {
		st := domain.Status(s)
		if !st.Valid() {
			return nil, errInvalidValue(fmt.Sprintf(
				"status %q is not one of ACTIVE|WARNING|DEPRECATED|EXPIRED|REVOKED", s))
		}
		out = append(out, st)
	}
	return out, nil
}

// parseIntParam returns 0 (meaning "store default") when the key is absent, and
// a 400 when it is present but not an integer.
func parseIntParam(values url.Values, key string) (int, error) {
	raw := values.Get(key)
	if raw == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, errInvalidRequest(fmt.Sprintf("%s %q is not an integer", key, raw))
	}
	return n, nil
}

func parseBoolParam(values url.Values, key string) (bool, error) {
	raw := values.Get(key)
	if raw == "" {
		return false, nil
	}
	b, err := strconv.ParseBool(raw)
	if err != nil {
		return false, errInvalidRequest(fmt.Sprintf("%s %q is not a boolean", key, raw))
	}
	return b, nil
}

func validateDirection(dir string) error {
	switch dir {
	case "", "forward", "backward":
		return nil
	default:
		return errInvalidValue(fmt.Sprintf("pageTokenDirection %q must be forward or backward", dir))
	}
}
