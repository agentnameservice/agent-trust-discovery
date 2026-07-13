package importsvc

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/agentnameservice/agent-trust-discovery/internal/domain"
)

// Wire shapes for the import endpoints. Field names mirror spec/api-spec-search.yaml
// (RegisteredAgent, Observation, Provenance). Conversion to domain types runs
// the request-level (400-class) checks: required fields, valid status,
// RFC 3339 timestamps, and length/count caps so a hostile or buggy caller
// cannot force us to persist multi-megabyte strings. Semantic checks that
// need the store/registry (the §5.2.1 422-class rules) live in the service.

// Length/count caps at the import DTO boundary. These are generous compared
// to real fixture data (agentId <= 128 chars, description <= 4 KiB) but far
// tighter than "no limit at all". Exceeding any cap → 400 INVALID_REQUEST.
const (
	maxAgentIDLen        = 128
	maxDNSNameLen        = 253 // RFC 1035 domain-name limit
	maxDisplayNameLen    = 256
	maxDescriptionLen    = 4096
	maxProviderIDLen     = 128
	maxStatusLen         = 32 // longest valid enum is DEPRECATED
	maxSignalIDLen       = 128
	maxProvenanceIDLen   = 128
	maxProvenanceURLLen  = 2048
	maxObservationValLen = 65_536 // 64 KiB — plenty for any built-in signal's JSON

	maxStringSliceLen  = 64  // per agent: protocols/transports/tags/capabilities
	maxStringSliceItem = 128 // one entry in the above slices
)

type importAgentsRequest struct {
	Agents []agentDTO `json:"agents"`
}

type agentDTO struct {
	AgentID      string   `json:"agentId"`
	DNSName      string   `json:"dnsName"`
	DisplayName  string   `json:"displayName"`
	Description  string   `json:"description"`
	ProviderID   string   `json:"providerId"`
	Status       string   `json:"status"`
	Protocols    []string `json:"protocols"`
	Transports   []string `json:"transports"`
	Tags         []string `json:"tags"`
	Capabilities []string `json:"capabilities"`
	FirstSeen    string   `json:"firstSeen"`
	LastUpdated  string   `json:"lastUpdated"`
}

type importObservationsRequest struct {
	Observations []observationDTO `json:"observations"`
}

type observationDTO struct {
	AgentID    string          `json:"agentId"`
	SignalID   string          `json:"signalId"`
	ObservedAt string          `json:"observedAt"`
	Value      json.RawMessage `json:"value"`
	Provenance *provenanceDTO  `json:"provenance,omitempty"`
}

type provenanceDTO struct {
	AIMID       string `json:"aimId"`
	EvidenceURL string `json:"evidenceUrl"`
}

// toDomain converts the agent batch, rejecting an empty batch and propagating
// the first row's conversion error (400 INVALID_REQUEST).
func (r importAgentsRequest) toDomain() ([]domain.Agent, error) {
	if len(r.Agents) == 0 {
		return nil, errInvalidRequest("agents: at least one agent is required")
	}
	out := make([]domain.Agent, 0, len(r.Agents))
	for _, a := range r.Agents {
		da, err := a.toDomain()
		if err != nil {
			return nil, err
		}
		out = append(out, da)
	}
	return out, nil
}

func (d agentDTO) toDomain() (domain.Agent, error) {
	if d.AgentID == "" {
		return domain.Agent{}, errInvalidRequest("agent: agentId is required")
	}
	if err := checkStrLen("agentId", d.AgentID, maxAgentIDLen); err != nil {
		return domain.Agent{}, err
	}
	if d.DNSName == "" {
		return domain.Agent{}, errInvalidRequest(fmt.Sprintf("agent %q: dnsName is required", d.AgentID))
	}
	if err := checkStrLen(fmt.Sprintf("agent %q dnsName", d.AgentID), d.DNSName, maxDNSNameLen); err != nil {
		return domain.Agent{}, err
	}
	if d.DisplayName == "" {
		return domain.Agent{}, errInvalidRequest(fmt.Sprintf("agent %q: displayName is required", d.AgentID))
	}
	if err := checkStrLen(fmt.Sprintf("agent %q displayName", d.AgentID), d.DisplayName, maxDisplayNameLen); err != nil {
		return domain.Agent{}, err
	}
	if err := checkStrLen(fmt.Sprintf("agent %q description", d.AgentID), d.Description, maxDescriptionLen); err != nil {
		return domain.Agent{}, err
	}
	if err := checkStrLen(fmt.Sprintf("agent %q providerId", d.AgentID), d.ProviderID, maxProviderIDLen); err != nil {
		return domain.Agent{}, err
	}
	if err := checkStrLen(fmt.Sprintf("agent %q status", d.AgentID), d.Status, maxStatusLen); err != nil {
		return domain.Agent{}, err
	}
	status := domain.Status(d.Status)
	if !status.Valid() {
		return domain.Agent{}, errInvalidRequest(fmt.Sprintf(
			"agent %q: status %q is not one of ACTIVE|WARNING|DEPRECATED|EXPIRED|REVOKED", d.AgentID, d.Status))
	}
	for _, spec := range []struct {
		label string
		vals  []string
	}{
		{"protocols", d.Protocols},
		{"transports", d.Transports},
		{"tags", d.Tags},
		{"capabilities", d.Capabilities},
	} {
		if err := checkStringSlice(fmt.Sprintf("agent %q %s", d.AgentID, spec.label), spec.vals); err != nil {
			return domain.Agent{}, err
		}
	}
	firstSeen, err := parseRFC3339(fmt.Sprintf("agent %q firstSeen", d.AgentID), d.FirstSeen)
	if err != nil {
		return domain.Agent{}, err
	}
	lastUpdated, err := parseRFC3339(fmt.Sprintf("agent %q lastUpdated", d.AgentID), d.LastUpdated)
	if err != nil {
		return domain.Agent{}, err
	}
	return domain.Agent{
		ID:           domain.AgentID(d.AgentID),
		DNSName:      d.DNSName,
		DisplayName:  d.DisplayName,
		Description:  d.Description,
		ProviderID:   d.ProviderID,
		Status:       status,
		Protocols:    d.Protocols,
		Transports:   d.Transports,
		Tags:         d.Tags,
		Capabilities: d.Capabilities,
		FirstSeen:    firstSeen,
		LastUpdated:  lastUpdated,
	}, nil
}

// toDomain converts the observation batch, rejecting an empty batch and
// propagating the first row's conversion error (400 INVALID_REQUEST).
func (r importObservationsRequest) toDomain() ([]domain.SignalObservation, error) {
	if len(r.Observations) == 0 {
		return nil, errInvalidRequest("observations: at least one observation is required")
	}
	out := make([]domain.SignalObservation, 0, len(r.Observations))
	for _, o := range r.Observations {
		do, err := o.toDomain()
		if err != nil {
			return nil, err
		}
		out = append(out, do)
	}
	return out, nil
}

func (d observationDTO) toDomain() (domain.SignalObservation, error) {
	if d.AgentID == "" {
		return domain.SignalObservation{}, errInvalidRequest("observation: agentId is required")
	}
	if err := checkStrLen("observation agentId", d.AgentID, maxAgentIDLen); err != nil {
		return domain.SignalObservation{}, err
	}
	if d.SignalID == "" {
		return domain.SignalObservation{}, errInvalidRequest(fmt.Sprintf("observation on agent %q: signalId is required", d.AgentID))
	}
	if err := checkStrLen(fmt.Sprintf("observation on agent %q signalId", d.AgentID), d.SignalID, maxSignalIDLen); err != nil {
		return domain.SignalObservation{}, err
	}
	if len(d.Value) == 0 || string(d.Value) == "null" {
		return domain.SignalObservation{}, errInvalidRequest(fmt.Sprintf(
			"observation for signal %q on agent %q: value is required", d.SignalID, d.AgentID))
	}
	if len(d.Value) > maxObservationValLen {
		return domain.SignalObservation{}, errInvalidRequest(fmt.Sprintf(
			"observation for signal %q on agent %q: value is %d bytes, max %d",
			d.SignalID, d.AgentID, len(d.Value), maxObservationValLen))
	}
	observedAt, err := parseRFC3339(fmt.Sprintf("observation %q/%q observedAt", d.AgentID, d.SignalID), d.ObservedAt)
	if err != nil {
		return domain.SignalObservation{}, err
	}
	var prov *domain.Provenance
	if d.Provenance != nil {
		if err := checkStrLen("provenance aimId", d.Provenance.AIMID, maxProvenanceIDLen); err != nil {
			return domain.SignalObservation{}, err
		}
		if err := checkStrLen("provenance evidenceUrl", d.Provenance.EvidenceURL, maxProvenanceURLLen); err != nil {
			return domain.SignalObservation{}, err
		}
		prov = &domain.Provenance{AIMID: d.Provenance.AIMID, EvidenceURL: d.Provenance.EvidenceURL}
	}
	return domain.SignalObservation{
		AgentID:    domain.AgentID(d.AgentID),
		SignalID:   domain.SignalID(d.SignalID),
		ObservedAt: observedAt,
		Value:      d.Value,
		Provenance: prov,
	}, nil
}

// checkStrLen enforces max byte length. Uses byte length (not rune count) so
// the caps line up with underlying storage limits. label identifies the field
// in the 400 detail message.
func checkStrLen(label, s string, maxLen int) error {
	if len(s) > maxLen {
		return errInvalidRequest(fmt.Sprintf("%s is %d bytes, max %d", label, len(s), maxLen))
	}
	return nil
}

// checkStringSlice enforces slice count and per-item length caps. Empty
// slices are allowed; nil is treated as empty.
func checkStringSlice(label string, vals []string) error {
	if len(vals) > maxStringSliceLen {
		return errInvalidRequest(fmt.Sprintf("%s has %d entries, max %d", label, len(vals), maxStringSliceLen))
	}
	for i, v := range vals {
		if len(v) > maxStringSliceItem {
			return errInvalidRequest(fmt.Sprintf("%s[%d] is %d bytes, max %d", label, i, len(v), maxStringSliceItem))
		}
	}
	return nil
}

// parseRFC3339 parses a required RFC 3339 timestamp, returning a 400
// INVALID_REQUEST on an empty or malformed value. label identifies the field
// for the caller-facing detail message.
func parseRFC3339(label, raw string) (time.Time, error) {
	if raw == "" {
		return time.Time{}, errInvalidRequest(label + " is required")
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, errInvalidRequest(fmt.Sprintf("%s %q is not an RFC 3339 timestamp", label, raw))
	}
	return t, nil
}
