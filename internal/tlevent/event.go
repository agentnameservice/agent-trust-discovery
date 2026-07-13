// Package tlevent is the hydrator-side schema and parser for simulated
// transparency-log events (design §6.2/§6.3, mirroring DESIGN.md A.3 typed
// fields with a permissive agent block). A TL event carries an agent's
// registration metadata plus its sealed cryptographic baselines; the hydrator
// projects events into agent imports and pairs the baselines against live-side
// observations to compute drift verdicts. agent-trust-discovery never sees a TL event —
// this package is shared only by the hydrator and the prober (§6.6).
package tlevent

import (
	"bytes"
	"errors"
	"fmt"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/agentnameservice/agent-trust-discovery/internal/domain"
)

// Event is one simulated registration event.
type Event struct {
	ANSID        string       `yaml:"ansId"`
	Status       string       `yaml:"status"`
	ProviderID   string       `yaml:"providerId"`
	FirstSeen    string       `yaml:"firstSeen"`   // RFC 3339
	LastUpdated  string       `yaml:"lastUpdated"` // RFC 3339
	Agent        Agent        `yaml:"agent"`
	Attestations Attestations `yaml:"attestations"`
}

// Agent is the registration metadata; host/version/name are the typed A.3
// fields, the rest are the permissive extension (design §6.3).
type Agent struct {
	Host         string     `yaml:"host"`
	Version      string     `yaml:"version"`
	Name         string     `yaml:"name"`
	Description  string     `yaml:"description"`
	Protocols    []string   `yaml:"protocols"`
	Transports   []string   `yaml:"transports"`
	Tags         []string   `yaml:"tags"`
	Capabilities []string   `yaml:"capabilities"`
	Endpoints    []Endpoint `yaml:"endpoints"`
}

// Endpoint is one advertised agent endpoint; its protocol/transport feed the
// agent's searchable protocol/transport sets.
type Endpoint struct {
	Protocol  string `yaml:"protocol"`
	Transport string `yaml:"transport"`
	URL       string `yaml:"url"`
}

// Attestations holds the sealed cryptographic baselines the hydrator pairs
// against live-side observations (design §6.3 step 2b).
type Attestations struct {
	ServerCert            CertAttestation `yaml:"serverCert"`
	IdentityCert          CertAttestation `yaml:"identityCert"`
	DNSRecordsProvisioned DNSRecords      `yaml:"dnsRecordsProvisioned"`
	DNSSECStatus          string          `yaml:"dnssecStatus"`
}

// CertAttestation is a sealed certificate fingerprint baseline.
type CertAttestation struct {
	Fingerprint string `yaml:"fingerprint"`
}

// DNSRecords holds the sealed _ans / _ans-badge TXT record baselines.
type DNSRecords struct {
	ANS      string `yaml:"_ans"`
	ANSBadge string `yaml:"_ans-badge"`
}

// ParseEvent parses and validates one event from YAML bytes. Unknown fields
// are rejected: TL-event fixtures are hand-authored *and* snapshot-written,
// and a typo (`fingerpint` for `fingerprint`) would silently drop the
// baseline and cascade into a spurious drift verdict downstream.
func ParseEvent(b []byte) (Event, error) {
	var e Event
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&e); err != nil {
		return Event{}, fmt.Errorf("tlevent: parse: %w", err)
	}
	if err := e.validate(); err != nil {
		return Event{}, err
	}
	return e, nil
}

// Validate runs the same shape checks ParseEvent applies. Producers that
// build an Event programmatically (cmd/agent-snapshot merges Search + TL into
// one) call this before writing so a malformed fixture is surfaced at capture
// time with the agentId, not silently written and only discovered later when
// agent-hydrator-stub's ParseEvent fails.
func (e Event) Validate() error { return e.validate() }

func (e Event) validate() error {
	if e.ANSID == "" {
		return errors.New("tlevent: ansId is required")
	}
	if e.Agent.Host == "" || e.Agent.Version == "" || e.Agent.Name == "" {
		return fmt.Errorf("tlevent %q: agent.host, agent.version and agent.name are required", e.ANSID)
	}
	if !domain.Status(e.Status).Valid() {
		return fmt.Errorf("tlevent %q: status %q is not a valid lifecycle status", e.ANSID, e.Status)
	}
	if err := requireRFC3339(e.ANSID, "firstSeen", e.FirstSeen); err != nil {
		return err
	}
	return requireRFC3339(e.ANSID, "lastUpdated", e.LastUpdated)
}

func requireRFC3339(ansID, field, raw string) error {
	if raw == "" {
		return fmt.Errorf("tlevent %q: %s is required", ansID, field)
	}
	if _, err := time.Parse(time.RFC3339, raw); err != nil {
		return fmt.Errorf("tlevent %q: %s %q is not an RFC 3339 timestamp", ansID, field, raw)
	}
	return nil
}
