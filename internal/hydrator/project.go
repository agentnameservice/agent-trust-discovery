package hydrator

import (
	"encoding/json"
	"fmt"

	"github.com/agentnameservice/agent-trust-discovery/internal/tlevent"
)

// driftBaseline returns the sealed baseline a drift-verdict signal pairs against
// in a TL event's attestations (design §6.3 step 4a), and whether the signal is
// a drift-verdict signal at all.
func driftBaseline(signalID string, a tlevent.Attestations) (string, bool) {
	switch signalID {
	case "certfingerprint.server":
		return a.ServerCert.Fingerprint, true
	case "certfingerprint.identity":
		return a.IdentityCert.Fingerprint, true
	case "dnsrecord.ans":
		return a.DNSRecordsProvisioned.ANS, true
	case "dnsrecord.ans-badge":
		return a.DNSRecordsProvisioned.ANSBadge, true
	default:
		return "", false
	}
}

// projectAgent maps a TL event to an agent import body (design §6.3 step 2a):
// ansId→agentId, ans://version.host→dnsName, name→displayName, and the
// endpoints' protocols/transports into the searchable sets.
func projectAgent(e tlevent.Event) agentWire {
	return agentWire{
		AgentID:      e.ANSID,
		DNSName:      "ans://" + e.Agent.Version + "." + e.Agent.Host,
		DisplayName:  e.Agent.Name,
		Description:  e.Agent.Description,
		ProviderID:   e.ProviderID,
		Status:       e.Status,
		Protocols:    mergeDedupe(e.Agent.Protocols, endpointField(e.Agent.Endpoints, func(ep tlevent.Endpoint) string { return ep.Protocol })),
		Transports:   mergeDedupe(e.Agent.Transports, endpointField(e.Agent.Endpoints, func(ep tlevent.Endpoint) string { return ep.Transport })),
		Tags:         e.Agent.Tags,
		Capabilities: e.Agent.Capabilities,
		FirstSeen:    e.FirstSeen,
		LastUpdated:  e.LastUpdated,
	}
}

// projectObservation builds one observation import entry. Drift-verdict signals
// pair the event's sealed baseline (expected) with the fixture's live-side value
// (observed) and compute matched; raw signals forward the authored value.
func projectObservation(agentID string, entry ObservationEntry, att tlevent.Attestations, prov *provenanceWire) (observationWire, error) {
	w := observationWire{
		AgentID:    agentID,
		SignalID:   entry.SignalID,
		ObservedAt: entry.ObservedAt,
		Provenance: prov,
	}

	if expected, isDrift := driftBaseline(entry.SignalID, att); isDrift {
		verdict := driftValue{
			Expected:       expected,
			Observed:       entry.Observed,
			Matched:        expected == entry.Observed,
			ExpectedSource: "tl_attestation",
			ObservedSource: "fixture",
		}
		b, err := json.Marshal(verdict)
		if err != nil {
			return observationWire{}, fmt.Errorf("marshal verdict: %w", err)
		}
		w.Value = b
		return w, nil
	}

	b, err := json.Marshal(entry.Value)
	if err != nil {
		return observationWire{}, fmt.Errorf("marshal raw value: %w", err)
	}
	w.Value = b
	return w, nil
}

func endpointField(eps []tlevent.Endpoint, pick func(tlevent.Endpoint) string) []string {
	out := make([]string, 0, len(eps))
	for _, ep := range eps {
		out = append(out, pick(ep))
	}
	return out
}

// mergeDedupe concatenates the slices and removes empty/duplicate values,
// preserving first-seen order. Returns nil when nothing remains (so the wire
// field is omitted).
func mergeDedupe(slices ...[]string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, s := range slices {
		for _, v := range s {
			if v == "" || seen[v] {
				continue
			}
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}
