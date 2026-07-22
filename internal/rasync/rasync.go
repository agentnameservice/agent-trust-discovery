package rasync

import (
	"context"
	"errors"
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
	AgentsCaptured  int
	TLFetchErrors   int // agents the feed surfaced but the TL badge failed for (feed-only fixture written)
	ValidationDrops int // folded agents whose projected event failed validation and were dropped (not written)
}

const (
	defaultPageSize = 100
	maxPageSize     = 200
)

// normalizePageSize clamps a configured feed page size into the RA feed's valid
// 1..200 range: a non-positive value falls back to the default, and anything
// above the maximum is capped so the feed never receives an out-of-range limit
// (which would surface as a 4xx rather than a predictable capture).
func normalizePageSize(n int) int {
	switch {
	case n <= 0:
		return defaultPageSize
	case n > maxPageSize:
		return maxPageSize
	default:
		return n
	}
}

// Run drains the feed, folds to a current agent set, enriches each with TL
// baselines, and writes the tl-events/ fixtures the hydrator/prober consume.
// Each run removes the existing *.yaml fixtures in tl-events/ and rewrites them
// (any non-.yaml files are left untouched). A TL badge miss degrades that agent
// to a feed-only fixture (empty attestations), never aborts the run.
func Run(ctx context.Context, feed FeedFetcher, tl TLFetcher, cfg Config, logger *slog.Logger) (Summary, error) {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(os.Stdout, nil))
	}
	pageSize := normalizePageSize(cfg.PageSize)

	agents, err := drainAndFold(ctx, feed, cfg.RABaseURL, pageSize)
	if err != nil {
		return Summary{}, err
	}
	logger.InfoContext(ctx, "rasync: fold complete", "agents", len(agents))

	// Refuse to wipe the previous fixture set to nothing: an empty feed (or a
	// window in which everything aged out) would otherwise look to the hydrator
	// like "zero agents" and silently drop all trust data.
	if len(agents) == 0 {
		return Summary{}, errors.New("rasync: feed returned no agents in the retention window; refusing to produce an empty fixture set")
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
			summary.ValidationDrops++
			continue
		}
		if werr := writeFixture(outDir, ev); werr != nil {
			return summary, fmt.Errorf("rasync: write %s: %w", ev.ANSID, werr)
		}
		summary.AgentsCaptured++
	}

	logger.InfoContext(ctx, "rasync: capture complete",
		"agentsCaptured", summary.AgentsCaptured, "tlFetchErrors", summary.TLFetchErrors,
		"validationDrops", summary.ValidationDrops, "outDir", outDir)

	if summary.AgentsCaptured == 0 {
		return summary, fmt.Errorf("rasync: %d folded agents but 0 written; refusing to produce empty snapshot", len(agents))
	}
	return summary, nil
}

// toEvent merges a folded feed agent with its TL badge into the fixture Event.
// When tlOK the badge is authoritative for firstSeen + attestations + host/
// version; the feed supplies name + description + endpoints. When !tlOK the fold
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
