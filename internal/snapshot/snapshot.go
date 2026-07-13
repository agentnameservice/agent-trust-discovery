// Package snapshot implements the live-pipeline capture step (plan §3): a
// search-driven walk of the public Search API merged with the prod
// Transparency Log, written to disk in the existing TL-event fixture YAML
// shape. The hydrator and prober consume the output unchanged.
package snapshot

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/agentnameservice/agent-trust-discovery/internal/atdclient"
	"github.com/agentnameservice/agent-trust-discovery/internal/tlevent"
)

// AgentSearcher is the subset of atdclient used by Run; satisfied by
// *atdclient.Client and any test double.
type AgentSearcher interface {
	SearchAgents(ctx context.Context, baseURL string, opts atdclient.SearchOpts) ([]atdclient.Agent, error)
}

// TLFetcher is the subset of tlclient used by Run; satisfied by *tlclient.Client.
type TLFetcher interface {
	Fetch(ctx context.Context, baseURL, ansID string) (tlevent.Event, error)
}

// Config configures one Run.
type Config struct {
	SearchBaseURL string
	TLBaseURL     string
	OutDir        string // fixture root; tl-events/ subdir is created beneath it
	SearchOpts    atdclient.SearchOpts
}

// Summary reports what a run captured.
type Summary struct {
	AgentsCaptured int
	TLFetchErrors  int // # of agents Search returned but TL failed for; logged not surfaced
}

// Run captures one snapshot: Search → TL → merge → write fixture YAML files.
// The output tl-events/ directory is wiped and rewritten on every run so the
// snapshot is clean. Agents whose TL fetch fails are logged and skipped (the
// next run will retry); the run still returns successfully so the bound stays
// visible in the summary.
func Run(ctx context.Context, search AgentSearcher, tl TLFetcher, cfg Config, logger *slog.Logger) (Summary, error) {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(os.Stdout, nil))
	}

	agents, err := search.SearchAgents(ctx, cfg.SearchBaseURL, cfg.SearchOpts)
	if err != nil {
		return Summary{}, fmt.Errorf("snapshot: search agents: %w", err)
	}
	logger.InfoContext(ctx, "snapshot: search complete", "agents", len(agents),
		"limit", cfg.SearchOpts.Limit)

	outDir := filepath.Join(cfg.OutDir, "tl-events")
	if err := prepareOutDir(outDir); err != nil {
		return Summary{}, err
	}

	summary := Summary{}
	for _, a := range agents {
		ev, ferr := tl.Fetch(ctx, cfg.TLBaseURL, a.AgentID)
		if ferr != nil {
			logger.WarnContext(ctx, "snapshot: tl fetch failed",
				"agentId", a.AgentID, "error", ferr.Error())
			summary.TLFetchErrors++
			continue
		}
		merged := merge(a, ev)
		// Validate the merged event before writing so a malformed fixture is
		// surfaced here (with the agentId) rather than silently written and
		// discovered later at hydrator load. Bad merge → skip that agent and
		// let the run continue for the rest of the population.
		if verr := merged.Validate(); verr != nil {
			logger.WarnContext(ctx, "snapshot: merged event failed validation",
				"agentId", a.AgentID, "error", verr.Error())
			summary.TLFetchErrors++
			continue
		}
		if err := writeFixture(outDir, merged); err != nil {
			return summary, fmt.Errorf("snapshot: write %s: %w", merged.ANSID, err)
		}
		summary.AgentsCaptured++
	}

	logger.InfoContext(ctx, "snapshot: capture complete",
		"agentsCaptured", summary.AgentsCaptured,
		"tlFetchErrors", summary.TLFetchErrors,
		"outDir", outDir)

	// prepareOutDir wiped the previous snapshot before the loop, so a total
	// TL outage would otherwise leave callers with an empty directory and a
	// nil error — the hydrator would then interpret that as "zero agents
	// registered" and silently wipe all trust data. Refuse the empty result
	// so the operator sees the failure and the previous fixture is (from the
	// operator's perspective) retryable.
	if len(agents) > 0 && summary.AgentsCaptured == 0 {
		return summary, fmt.Errorf("snapshot: all %d TL fetches failed; refusing to produce empty snapshot", summary.TLFetchErrors)
	}
	return summary, nil
}

// merge combines a Search registry record (a) with the TL-fetched event (ev),
// producing the single tlevent.Event the existing fixture YAML serializes.
//
// Provenance per field:
//   - ANSID, sealed attestations, agent.host/version/name → TL (authoritative).
//   - status, firstSeen (issuedAt), lastUpdated (timestamp) → TL.
//   - providerId → TL if present, else Search.
//   - description, endpoints → Search (TL doesn't carry them).
//   - protocols, transports → derived from Search endpoints[] (deduped).
//
// Search's prod response has no top-level tags/capabilities arrays — those
// fields stay empty on the snapshot.
func merge(a atdclient.Agent, ev tlevent.Event) tlevent.Event {
	ev.ProviderID = pickNonEmpty(ev.ProviderID, a.ProviderID)
	if ev.Status == "" {
		ev.Status = a.Lifecycle.Status
	}
	ev.Agent.Description = a.AgentDescription

	protocols, transports := protocolsAndTransports(a.Endpoints)
	ev.Agent.Protocols = protocols
	ev.Agent.Transports = transports
	ev.Agent.Endpoints = projectEndpoints(a.Endpoints)
	return ev
}

func pickNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// protocolsAndTransports flattens Search endpoints[] into the
// agent.protocols / agent.transports sets the RI fixture YAML carries.
// Order is preserved (first-seen wins) so snapshots are deterministic.
func protocolsAndTransports(eps []atdclient.Endpoint) ([]string, []string) {
	protoSeen := map[string]bool{}
	transSeen := map[string]bool{}
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

// projectEndpoints renders Search endpoints[] into the fixture's
// agent.endpoints[] shape. Each Search endpoint expands to one fixture
// endpoint per transport, so the typed protocol+transport tuple matches
// the curated fixtures.
func projectEndpoints(eps []atdclient.Endpoint) []tlevent.Endpoint {
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

// prepareOutDir wipes any existing tl-events/ contents under outDir and
// recreates the dir. Non-YAML files are left alone so a sibling README or
// .gitkeep survives across snapshots.
func prepareOutDir(outDir string) error {
	if err := os.MkdirAll(outDir, 0o750); err != nil {
		return fmt.Errorf("snapshot: mkdir %s: %w", outDir, err)
	}
	entries, err := os.ReadDir(outDir)
	if err != nil {
		return fmt.Errorf("snapshot: read %s: %w", outDir, err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		if err := os.Remove(filepath.Join(outDir, e.Name())); err != nil {
			return fmt.Errorf("snapshot: remove %s: %w", e.Name(), err)
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

// safeFileName makes an ansId safe to use as a filename — UUIDs already are
// safe, but the API contract just says "string", so we collapse anything that
// could escape the directory.
func safeFileName(s string) string {
	if s == "" {
		return "unnamed"
	}
	repl := func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '-', r == '_', r == '.':
			return r
		}
		return '_'
	}
	return strings.Map(repl, s)
}
