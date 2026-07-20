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
