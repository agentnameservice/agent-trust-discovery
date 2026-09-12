package importsvc

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestAgentDTOToDomain_LengthCaps exercises every length/count cap on the
// agent DTO — one input just over each limit must be rejected with a 400
// INVALID_REQUEST, never silently truncated or persisted.
func TestAgentDTOToDomain_LengthCaps(t *testing.T) {
	valid := agentDTO{
		AgentID: "a1", DNSName: "a1.example.com", DisplayName: "A1",
		Status:      "ACTIVE",
		FirstSeen:   "2026-06-04T08:00:00Z",
		LastUpdated: "2026-06-04T08:00:00Z",
	}

	cases := []struct {
		name     string
		mutate   func(*agentDTO)
		wantSubs string // substring expected in the returned error
	}{
		{"agentId over cap", func(d *agentDTO) { d.AgentID = strings.Repeat("x", maxAgentIDLen+1) }, "agentId"},
		{"dnsName over cap", func(d *agentDTO) { d.DNSName = strings.Repeat("x", maxDNSNameLen+1) }, "dnsName"},
		{"displayName over cap", func(d *agentDTO) { d.DisplayName = strings.Repeat("x", maxDisplayNameLen+1) }, "displayName"},
		{"description over cap", func(d *agentDTO) { d.Description = strings.Repeat("x", maxDescriptionLen+1) }, "description"},
		{"providerId over cap", func(d *agentDTO) { d.ProviderID = strings.Repeat("x", maxProviderIDLen+1) }, "providerId"},
		{"status over cap", func(d *agentDTO) { d.Status = strings.Repeat("x", maxStatusLen+1) }, "status"},
		{"protocols count over cap", func(d *agentDTO) {
			d.Protocols = make([]string, maxStringSliceLen+1)
		}, "protocols"},
		{"protocols item over cap", func(d *agentDTO) {
			d.Protocols = []string{strings.Repeat("x", maxStringSliceItem+1)}
		}, "protocols"},
		{"tags item over cap", func(d *agentDTO) {
			d.Tags = []string{strings.Repeat("x", maxStringSliceItem+1)}
		}, "tags"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := valid
			tc.mutate(&d)
			_, err := d.toDomain()
			if err == nil {
				t.Fatalf("toDomain: want error mentioning %q, got nil", tc.wantSubs)
			}
			if !strings.Contains(err.Error(), tc.wantSubs) {
				t.Errorf("error = %q, want substring %q", err.Error(), tc.wantSubs)
			}
		})
	}
}

// TestObservationDTOToDomain_LengthCaps covers the observation-side caps.
func TestObservationDTOToDomain_LengthCaps(t *testing.T) {
	valid := observationDTO{
		AgentID: "a1", SignalID: "certtype",
		ObservedAt: "2026-06-04T08:00:00Z",
		Value:      json.RawMessage(`{"type":"DV"}`),
	}

	cases := []struct {
		name     string
		mutate   func(*observationDTO)
		wantSubs string
	}{
		{"agentId over cap", func(d *observationDTO) { d.AgentID = strings.Repeat("x", maxAgentIDLen+1) }, "agentId"},
		{"signalId over cap", func(d *observationDTO) { d.SignalID = strings.Repeat("x", maxSignalIDLen+1) }, "signalId"},
		{"value over cap", func(d *observationDTO) {
			// Craft a JSON object with a huge padding string; the total
			// length must exceed maxObservationValLen bytes.
			pad := strings.Repeat("x", maxObservationValLen)
			d.Value = json.RawMessage(`{"type":"DV","pad":"` + pad + `"}`)
		}, "value"},
		{"provenance aimId over cap", func(d *observationDTO) {
			d.Provenance = &provenanceDTO{AIMID: strings.Repeat("x", maxProvenanceIDLen+1)}
		}, "aimId"},
		{"provenance evidenceUrl over cap", func(d *observationDTO) {
			d.Provenance = &provenanceDTO{EvidenceURL: strings.Repeat("x", maxProvenanceURLLen+1)}
		}, "evidenceUrl"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := valid
			tc.mutate(&d)
			_, err := d.toDomain()
			if err == nil {
				t.Fatalf("toDomain: want error mentioning %q, got nil", tc.wantSubs)
			}
			if !strings.Contains(err.Error(), tc.wantSubs) {
				t.Errorf("error = %q, want substring %q", err.Error(), tc.wantSubs)
			}
		})
	}
}

// TestObservationDTOToDomain_EvidenceURLScheme pins #18's URL validation: a
// non-empty provenance.evidenceUrl must be an absolute http(s) URL so a
// javascript:/file:/bare-string value can't reach a relying party that renders
// it as a link. Empty stays allowed (evidenceUrl is optional).
func TestObservationDTOToDomain_EvidenceURLScheme(t *testing.T) {
	base := observationDTO{
		AgentID: "a1", SignalID: "certtype",
		ObservedAt: "2026-06-04T08:00:00Z",
		Value:      json.RawMessage(`{"type":"DV"}`),
	}

	for _, raw := range []string{
		"javascript:alert(1)",
		"file:///etc/passwd",
		"not a url at all",
		"/relative/path",
		"http:///no-host",
		"ftp://example.com/x",
	} {
		t.Run("reject "+raw, func(t *testing.T) {
			d := base
			d.Provenance = &provenanceDTO{EvidenceURL: raw}
			_, err := d.toDomain()
			if err == nil || !strings.Contains(err.Error(), "evidenceUrl") {
				t.Fatalf("evidenceUrl %q: want evidenceUrl error, got %v", raw, err)
			}
		})
	}

	for _, raw := range []string{
		"",
		"http://example.com",
		"https://aim.example.com/findings/42",
	} {
		t.Run("accept "+raw, func(t *testing.T) {
			d := base
			d.Provenance = &provenanceDTO{AIMID: "did:web:aim.example.com", EvidenceURL: raw}
			if _, err := d.toDomain(); err != nil {
				t.Fatalf("evidenceUrl %q: want ok, got %v", raw, err)
			}
		})
	}
}
