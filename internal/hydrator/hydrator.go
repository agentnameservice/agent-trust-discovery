package hydrator

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/agentnameservice/agent-trust-discovery/internal/tlevent"
)

// Config configures the hydrator's target and provenance tag (design §6.3).
type Config struct {
	BaseURL  string // agent-trust-discovery base URL, e.g. http://localhost:8080
	AdminKey string // sent as Authorization: Bearer <key> when non-empty
	AIMID    string // tagged on every emitted observation's provenance
}

// Hydrator projects TL events + fixtures into agent-trust-discovery imports.
type Hydrator struct {
	cfg    Config
	client *http.Client
}

// New builds a Hydrator. A nil client uses http.DefaultClient.
func New(cfg Config, client *http.Client) *Hydrator {
	if client == nil {
		client = http.DefaultClient
	}
	return &Hydrator{cfg: cfg, client: client}
}

// Summary reports what a run imported.
type Summary struct {
	AgentsImported       int
	ObservationsImported int
}

// Run executes a single pass (design §6.3). It always imports agents first
// (§6.5 rule 1). In mock mode it then computes and imports observations; in
// real mode it stops after agents (agent-prober supplies live observations). A
// non-200 import is surfaced as an error, never silently retried (§6.5 rule 2).
func (h *Hydrator) Run(ctx context.Context, events []tlevent.Event, obsFiles []ObservationFile, mock bool) (Summary, error) {
	agents := make([]agentWire, 0, len(events))
	baselines := make(map[string]tlevent.Attestations, len(events))
	for _, e := range events {
		agents = append(agents, projectAgent(e))
		baselines[e.ANSID] = e.Attestations
	}
	if err := h.post(ctx, "/v1/internal/agents/import", agentImportRequest{Agents: agents}); err != nil {
		return Summary{}, fmt.Errorf("hydrator: import agents: %w", err)
	}
	summary := Summary{AgentsImported: len(agents)}
	if !mock {
		return summary, nil
	}

	var prov *provenanceWire
	if h.cfg.AIMID != "" {
		prov = &provenanceWire{AIMID: h.cfg.AIMID}
	}
	observations := make([]observationWire, 0)
	for _, f := range obsFiles {
		att := baselines[f.AgentID] // zero value (empty baselines) for an unknown agent → "not sealed"
		for _, entry := range f.Observations {
			w, err := projectObservation(f.AgentID, entry, att, prov)
			if err != nil {
				return summary, fmt.Errorf("hydrator: project %s/%s: %w", f.AgentID, entry.SignalID, err)
			}
			observations = append(observations, w)
		}
	}
	if len(observations) > 0 {
		if err := h.post(ctx, "/v1/internal/observations/import", observationImportRequest{Observations: observations}); err != nil {
			return summary, fmt.Errorf("hydrator: import observations: %w", err)
		}
	}
	summary.ObservationsImported = len(observations)
	return summary, nil
}

func (h *Hydrator) post(ctx context.Context, path string, body any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.cfg.BaseURL+path, bytes.NewReader(b))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if h.cfg.AdminKey != "" {
		req.Header.Set("Authorization", "Bearer "+h.cfg.AdminKey)
	}

	resp, err := h.client.Do(req)
	if err != nil {
		return fmt.Errorf("post %s: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("post %s returned %d: %s", path, resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	return nil
}
