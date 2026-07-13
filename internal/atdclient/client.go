// Package atdclient is a thin read-only HTTP client for the public agent-trust-discovery
// API at GET /v1/ans/registered-agents (operation listRegisteredAgents). It is
// used by cmd/agent-snapshot to capture a fixture snapshot from prod; production
// agent-trust-discovery itself never imports this package.
//
// The wire shape (Agent, SearchResults, Link) mirrors the spec at
// https://developer.godaddy.com/doc/endpoint/ans and is field-compatible with
// the RI's internal registeredAgentDTO. Pagination is opaque-token based: each
// SearchResults envelope carries a `links[].rel=="next"` URL whose pageToken
// query parameter feeds the subsequent request.
package atdclient

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

// Agent mirrors the prod agent-trust-discovery Search API response. The on-the-wire
// field names differ from the local RI's registeredAgentDTO — the prod
// response uses ansName/agentHost/agentDisplayName/agentDescription/agentVersion
// and a nested lifecycle.status, with no top-level firstSeen/lastUpdated
// (it carries indexedAt + expiresAt instead). The snapshot merge step in
// internal/snapshot does the field-name translation back to the RI's
// fixture YAML shape; this struct only needs to decode what's on the wire.
type Agent struct {
	AgentID          string         `json:"agentId"`
	ProviderID       string         `json:"providerId,omitempty"`
	ANSName          string         `json:"ansName,omitempty"`
	AgentHost        string         `json:"agentHost,omitempty"`
	AgentDisplayName string         `json:"agentDisplayName,omitempty"`
	AgentDescription string         `json:"agentDescription,omitempty"`
	AgentVersion     string         `json:"agentVersion,omitempty"`
	IndexedAt        string         `json:"indexedAt,omitempty"`
	ExpiresAt        string         `json:"expiresAt,omitempty"`
	Lifecycle        AgentLifecycle `json:"lifecycle,omitempty"`
	Endpoints        []Endpoint     `json:"endpoints,omitempty"`
}

// AgentLifecycle carries the status enum. Prod nests it under a "lifecycle"
// object instead of returning a top-level "status" field.
type AgentLifecycle struct {
	Status string `json:"status"`
}

// Endpoint is one advertised agent endpoint as returned by the Search API.
// Protocol / transports are pulled out and folded into the RI fixture's
// agent.protocols / agent.transports during the snapshot merge.
type Endpoint struct {
	AgentURL    string   `json:"agentUrl,omitempty"`
	MetaDataURL string   `json:"metaDataUrl,omitempty"`
	Protocol    string   `json:"protocol,omitempty"`
	Transports  []string `json:"transports,omitempty"`
}

// SearchOpts mirrors the listRegisteredAgents query parameters. Empty string,
// nil slice, and zero int are all treated as "omit"; the only enforced
// invariant is KeywordExtraction=true requires a non-empty Query (the API
// returns 422 otherwise — we fail fast client-side).
type SearchOpts struct {
	Query             string
	KeywordExtraction bool
	KeywordAlgorithm  string
	ProviderIDs       []string
	AgentDomains      []string
	Protocols         []string
	Transports        []string
	Tags              []string
	Capabilities      []string
	Profile           string
	PageSize          int
	Limit             int
}

// ErrKeywordExtractionRequiresQuery is returned by SearchAgents when
// KeywordExtraction is set without a Query (matches the API's 422 contract).
var ErrKeywordExtractionRequiresQuery = errors.New("atdclient: keywordExtraction requires a non-empty query")

// Client-side hardening bounds. These bracket the blast radius of a
// misbehaving or compromised upstream: pagination cannot spin forever, a
// server-supplied next link cannot redirect us to another host, and a single
// page cannot consume unbounded memory.
const (
	// maxPagesWalk caps the total number of paginated GETs in one SearchAgents
	// call. Well beyond any realistic prod page count, but bounded.
	maxPagesWalk = 1000
	// maxResponseBodyBytes caps the size of one page response body decoded
	// into memory.
	maxResponseBodyBytes = 32 << 20 // 32 MiB
)

// ErrPaginationLimitExceeded is returned when a walk would follow more than
// maxPagesWalk next-links (guards against a looping upstream).
var ErrPaginationLimitExceeded = errors.New("atdclient: pagination page limit exceeded")

// ErrNextHrefHostMismatch is returned when a server-supplied next link points
// to a host other than the configured baseURL (guards against redirection).
var ErrNextHrefHostMismatch = errors.New("atdclient: next href host does not match baseURL")

// ErrResponseTooLarge is returned when a page body exceeds maxResponseBodyBytes.
var ErrResponseTooLarge = errors.New("atdclient: response body exceeds size cap")

// link is one entry of SearchResults.links[].
type link struct {
	Rel    string `json:"rel"`
	Method string `json:"method"`
	Href   string `json:"href"`
}

// searchResults is the response envelope.
type searchResults struct {
	Items []Agent `json:"items"`
	Links []link  `json:"links"`
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

// SearchAgents walks the listRegisteredAgents endpoint, following pageToken
// links until Limit agents have been collected (or pagination ends). baseURL is
// the API root (e.g. https://api.godaddy.com); the path is appended internally.
//
// Limit ≤ 0 means no cap (fetch all pages). PageSize ≤ 0 defaults to the API's
// own default (20). The result slice is never longer than Limit (when > 0).
func (c *Client) SearchAgents(ctx context.Context, baseURL string, opts SearchOpts) ([]Agent, error) {
	if opts.KeywordExtraction && strings.TrimSpace(opts.Query) == "" {
		return nil, ErrKeywordExtractionRequiresQuery
	}

	first, err := buildURL(baseURL, opts)
	if err != nil {
		return nil, err
	}
	// Pin the (scheme,host) from the base URL so a server-supplied "next" link
	// cannot redirect us to another origin. buildURL already parsed baseURL
	// once; parsing again here keeps the pin local to the walk.
	basePin, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("atdclient: parse baseURL: %w", err)
	}

	collected := make([]Agent, 0)
	next := first
	for pages := 0; next != ""; pages++ {
		if pages >= maxPagesWalk {
			return nil, ErrPaginationLimitExceeded
		}
		if err := assertSameOrigin(next, basePin); err != nil {
			return nil, err
		}
		page, err := c.fetch(ctx, next)
		if err != nil {
			return nil, err
		}
		for _, a := range page.Items {
			collected = append(collected, a)
			if opts.Limit > 0 && len(collected) >= opts.Limit {
				return collected, nil
			}
		}
		next = nextHref(page.Links, next)
	}
	return collected, nil
}

// assertSameOrigin verifies u shares scheme+host with the configured baseURL.
// Case-insensitive host match, since URL hosts are case-insensitive per RFC 3986.
func assertSameOrigin(u string, base *url.URL) error {
	nu, err := url.Parse(u)
	if err != nil {
		return fmt.Errorf("atdclient: parse next href: %w", err)
	}
	if !strings.EqualFold(nu.Scheme, base.Scheme) || !strings.EqualFold(nu.Host, base.Host) {
		return fmt.Errorf("%w: next=%s base=%s", ErrNextHrefHostMismatch, nu.Host, base.Host)
	}
	return nil
}

func (c *Client) fetch(ctx context.Context, u string) (searchResults, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return searchResults{}, fmt.Errorf("atdclient: build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return searchResults{}, fmt.Errorf("atdclient: get %s: %w", u, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return searchResults{}, fmt.Errorf("atdclient: get %s returned %d: %s",
			u, resp.StatusCode, strings.TrimSpace(string(msg)))
	}

	// Read at most maxResponseBodyBytes+1 so we can detect overflow after the
	// fact and reject rather than silently truncating.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodyBytes+1))
	if err != nil {
		return searchResults{}, fmt.Errorf("atdclient: read response: %w", err)
	}
	if int64(len(body)) > maxResponseBodyBytes {
		return searchResults{}, ErrResponseTooLarge
	}
	var sr searchResults
	if err := json.Unmarshal(body, &sr); err != nil {
		return searchResults{}, fmt.Errorf("atdclient: decode response: %w", err)
	}
	return sr, nil
}

// buildURL renders SearchOpts into the first-page request URL. Repeated array
// values are sent as multiple ?k=v pairs (collectionFormat: multi).
func buildURL(baseURL string, opts SearchOpts) (string, error) {
	base, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("atdclient: parse baseURL: %w", err)
	}
	base.Path = strings.TrimRight(base.Path, "/") + "/v1/ans/registered-agents"

	q := url.Values{}
	if opts.Query != "" {
		q.Set("query", opts.Query)
	}
	if opts.KeywordExtraction {
		q.Set("keywordExtraction", "true")
	}
	if opts.KeywordAlgorithm != "" {
		q.Set("keywordAlgorithm", opts.KeywordAlgorithm)
	}
	for _, v := range opts.ProviderIDs {
		q.Add("providerIds", v)
	}
	for _, v := range opts.AgentDomains {
		q.Add("agentDomains", v)
	}
	for _, v := range opts.Protocols {
		q.Add("protocols", v)
	}
	for _, v := range opts.Transports {
		q.Add("transports", v)
	}
	for _, v := range opts.Tags {
		q.Add("tags", v)
	}
	for _, v := range opts.Capabilities {
		q.Add("capabilities", v)
	}
	if opts.Profile != "" {
		q.Set("profile", opts.Profile)
	}
	if opts.PageSize > 0 {
		q.Set("pageSize", strconv.Itoa(opts.PageSize))
	}
	base.RawQuery = q.Encode()
	return base.String(), nil
}

// nextHref returns the absolute URL of the "next" link, or "" when pagination
// is exhausted. The cur URL is used to resolve relative hrefs.
func nextHref(links []link, cur string) string {
	for _, l := range links {
		if l.Rel != "next" {
			continue
		}
		if l.Href == "" {
			return ""
		}
		nu, err := url.Parse(l.Href)
		if err != nil {
			return ""
		}
		if nu.IsAbs() {
			return nu.String()
		}
		if cu, err := url.Parse(cur); err == nil {
			return cu.ResolveReference(nu).String()
		}
		return l.Href
	}
	return ""
}
