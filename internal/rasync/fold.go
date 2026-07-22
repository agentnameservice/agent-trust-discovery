// Package rasync is the agent-ra-sync producer core: drain the RA event feed,
// fold lifecycle events into a current agent set, enrich with TL baselines, and
// write the tl-events/ fixture YAML the hydrator and prober consume unchanged.
package rasync

import (
	"context"
	"fmt"

	"github.com/agentnameservice/agent-trust-discovery/internal/raclient"
)

// maxFeedPages caps how many pages drainAndFold will fetch in one run. It is a
// safety valve against a buggy or adversarial feed whose cursor advances
// forever: at the default page size of 100 this still allows ~1M events, well
// beyond any realistic capture, so a legitimate drain never hits it.
const maxFeedPages = 10_000

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
// Paging stops at an empty page or when the returned cursor does not advance,
// and is bounded by maxFeedPages so a feed whose cursor advances forever aborts
// with an error rather than draining unboundedly.
func drainAndFold(ctx context.Context, feed FeedFetcher, baseURL string, pageSize int) (map[string]foldedAgent, error) {
	agents := make(map[string]foldedAgent)
	cursor := ""
	for pages := 0; pages < maxFeedPages; pages++ {
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
	return nil, fmt.Errorf("rasync: feed did not terminate after %d pages (pageSize=%d); aborting unbounded drain", maxFeedPages, pageSize)
}

// applyEvent folds one event into the agent set. Unknown eventTypes are skipped.
func applyEvent(agents map[string]foldedAgent, it raclient.EventItem) {
	status := statusForEventType(it.EventType)
	if status == "" || it.AgentID == "" {
		return
	}
	fa := agents[it.AgentID] // zero value on first sight

	// The AgentID and the lifecycle status/timestamp always reflect the latest
	// event (the whole point of a revoke/deprecate event is its status). The
	// descriptive metadata fields are overwritten only when the event actually
	// carries a value, so a sparse status-change event (e.g. an AGENT_REVOKED
	// that omits the agent block) updates status without blanking the
	// host/version/name/description/endpoints an earlier event established.
	fa.AgentID = it.AgentID
	fa.Status = status
	if it.CreatedAt != "" {
		fa.LastUpdated = it.CreatedAt
	}
	if it.AnsName != "" {
		fa.AnsName = it.AnsName
	}
	if it.AgentHost != "" {
		fa.Host = it.AgentHost
	}
	if it.Version != "" {
		fa.Version = it.Version
	}
	if it.AgentDisplayName != "" {
		fa.DisplayName = it.AgentDisplayName
	}
	if it.AgentDescription != "" {
		fa.Description = it.AgentDescription
	}
	if len(it.Endpoints) > 0 {
		fa.Endpoints = it.Endpoints
	}

	// firstSeen fallback = earliest AGENT_REGISTERED createdAt (feed is ascending,
	// so the first one seen is the earliest).
	if it.EventType == raclient.EventTypeAgentRegistered && fa.FirstSeenFallback == "" && it.CreatedAt != "" {
		fa.FirstSeenFallback = it.CreatedAt
	}

	agents[it.AgentID] = fa
}
