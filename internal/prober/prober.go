package prober

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/agentnameservice/agent-trust-discovery/internal/tlevent"
)

const observedAtPlaceholder = "2026-06-25T00:00:00Z" // stamped by the caller in real runs; fixed here for determinism

// CertResult is what a live TLS handshake yields: the leaf certificate's
// SHA256 fingerprint and its validation tier (DV/OV/EV/none).
type CertResult struct {
	Fingerprint string
	Type        string
}

// Probe abstracts the live network operations so the projection logic is
// testable with a mock. The real implementation (net.Resolver + crypto/tls)
// lives in cmd/agent-prober. Every method returns a non-nil error when the target
// is unreachable; the prober turns that into a score-0 observation, never a
// silent skip (design §6.6).
type Probe interface {
	Cert(ctx context.Context, host string) (CertResult, error)
	TXT(ctx context.Context, name string) (string, error)
	CAA(ctx context.Context, host string) (bool, error)
}

// Config configures the prober's target and provenance.
type Config struct {
	BaseURL  string
	AdminKey string
	AIMID    string
	Now      func() string // optional observedAt stamper; nil → a fixed placeholder
	Logger   *slog.Logger  // optional; nil → slog.Default()
}

// Prober produces live observations from TL events.
type Prober struct {
	cfg    Config
	probe  Probe
	client *http.Client
	logger *slog.Logger
}

// New builds a Prober. A nil client uses http.DefaultClient; a nil
// cfg.Logger uses slog.Default().
func New(cfg Config, probe Probe, client *http.Client) *Prober {
	if client == nil {
		client = http.DefaultClient
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Prober{cfg: cfg, probe: probe, client: client, logger: logger}
}

// Summary reports what a pass emitted.
type Summary struct {
	ObservationsEmitted int
}

// RunOnce probes every event's agent once and imports the resulting
// observations. It does not import agents — the hydrator (real mode) owns that;
// the prober only produces observations (design §6.6 topology).
func (p *Prober) RunOnce(ctx context.Context, events []tlevent.Event) (Summary, error) {
	obs := make([]observationWire, 0, len(events)*5) // 5 signals probed per agent
	for _, e := range events {
		obs = append(obs, p.probeAgent(ctx, e)...)
	}
	if len(obs) == 0 {
		return Summary{}, nil
	}
	if err := p.post(ctx, observationImportRequest{Observations: obs}); err != nil {
		return Summary{}, fmt.Errorf("prober: import observations: %w", err)
	}
	return Summary{ObservationsEmitted: len(obs)}, nil
}

func (p *Prober) observedAt() string {
	if p.cfg.Now != nil {
		return p.cfg.Now()
	}
	return observedAtPlaceholder
}

// probeAgent runs the live probes for one event and shapes them into
// observations. Unreachable probes yield score-0-shaped values (empty observed
// / certtype none), never a skip.
func (p *Prober) probeAgent(ctx context.Context, e tlevent.Event) []observationWire {
	var prov *provenanceWire
	if p.cfg.AIMID != "" {
		prov = &provenanceWire{AIMID: p.cfg.AIMID}
	}
	host := e.Agent.Host
	at := p.observedAt()
	mk := func(signalID string, value any) observationWire {
		b, _ := json.Marshal(value)
		return observationWire{AgentID: e.ANSID, SignalID: signalID, ObservedAt: at, Value: b, Provenance: prov}
	}

	out := make([]observationWire, 0, 5)

	// certtype (raw) + certfingerprint.server (drift), from one TLS handshake.
	//
	// certfingerprint.identity (design §4.4 Family B, §6.6 drift-verdict tier)
	// is intentionally NOT emitted here in v1. The signal is registered
	// (signals/drift.go) and the hydrator produces it from fixture pipelines
	// (project.go: driftBaseline), but a *live* observation of the identity
	// cert requires the AIM identity endpoint, which v1 does not have. Rather
	// than emit an observed="" verdict that would flag drift on every pass,
	// this producer leaves certfingerprint.identity to the hydrator/fixture
	// path (design §6.3). v2: the AIM identity endpoint fills this gap.
	cert, certErr := p.probe.Cert(ctx, host)
	certType, observedFP := "none", ""
	if certErr == nil {
		certType, observedFP = cert.Type, cert.Fingerprint
	} else {
		// The failure is still emitted as a score-0 observation (never a
		// silent skip), but log it so "why is this agent's cert signal 0?"
		// is a log grep rather than an openssl s_client (mirrors snapshot.Run).
		p.logger.WarnContext(ctx, "prober: probe failed",
			"agentId", e.ANSID, "host", host, "signal", "certfingerprint.server", "error", certErr)
	}
	out = append(out, mk("certtype", map[string]string{"type": certType}))
	out = append(out, mk("certfingerprint.server", driftValue{
		Expected: e.Attestations.ServerCert.Fingerprint, Observed: observedFP,
		Matched:        certErr == nil && e.Attestations.ServerCert.Fingerprint == observedFP,
		ExpectedSource: "tl_attestation", ObservedSource: "live_tls_handshake",
	}))

	// dnsrecord.ans / dnsrecord.ans-badge (drift), from live TXT lookups.
	out = append(out, p.dnsVerdict(ctx, e, "dnsrecord.ans", "_ans."+host, e.Attestations.DNSRecordsProvisioned.ANS, prov, at))
	out = append(out, p.dnsVerdict(ctx, e, "dnsrecord.ans-badge", "_ans-badge."+host, e.Attestations.DNSRecordsProvisioned.ANSBadge, prov, at))

	// dnssecurity (raw): CAA is probed; DNSSEC validation is deferred (v1 stub).
	caa, caaErr := p.probe.CAA(ctx, host)
	if caaErr != nil {
		p.logger.WarnContext(ctx, "prober: probe failed",
			"agentId", e.ANSID, "host", host, "signal", "dnssecurity", "error", caaErr)
	}
	out = append(out, mk("dnssecurity", map[string]bool{"dnssec": false, "caa": caaErr == nil && caa}))

	return out
}

func (p *Prober) dnsVerdict(ctx context.Context, e tlevent.Event, signalID, name, expected string, prov *provenanceWire, at string) observationWire {
	observed, err := p.probe.TXT(ctx, name)
	if err != nil {
		observed = ""
		p.logger.WarnContext(ctx, "prober: probe failed",
			"agentId", e.ANSID, "host", e.Agent.Host, "signal", signalID, "name", name, "error", err)
	}
	b, _ := json.Marshal(driftValue{
		Expected: expected, Observed: observed,
		Matched:        err == nil && expected == observed,
		ExpectedSource: "tl_attestation", ObservedSource: "live_dns_query",
	})
	return observationWire{AgentID: e.ANSID, SignalID: signalID, ObservedAt: at, Value: b, Provenance: prov}
}

func (p *Prober) post(ctx context.Context, body any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.cfg.BaseURL+"/v1/internal/observations/import", bytes.NewReader(b))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if p.cfg.AdminKey != "" {
		req.Header.Set("Authorization", "Bearer "+p.cfg.AdminKey)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("post observations: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("observations import returned %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	return nil
}
