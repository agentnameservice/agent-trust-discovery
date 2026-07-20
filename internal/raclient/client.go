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
