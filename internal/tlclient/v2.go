package tlclient

import (
	"time"

	"github.com/agentnameservice/agent-trust-discovery/internal/tlevent"
)

// Internal wire structs for the V2 (reference ans-tl) TL response. Fields
// shared byte-for-byte with V1 — ansId, issuedAt, timestamp, agent.{host,
// version,name}, the response-root status — reuse the V1 types (tlEventAgent)
// directly; only attestations differs in shape.
type tlResponseV2 struct {
	Payload tlPayloadV2 `json:"payload"`
	Status  string      `json:"status"`
}

type tlPayloadV2 struct {
	Producer tlProducerV2 `json:"producer"`
}

type tlProducerV2 struct {
	Event tlEventV2 `json:"event"`
}

type tlEventV2 struct {
	ANSID        string           `json:"ansId"`
	IssuedAt     string           `json:"issuedAt"`
	Timestamp    string           `json:"timestamp"`
	Agent        tlEventAgent     `json:"agent"`
	Attestations tlAttestationsV2 `json:"attestations"`
}

// tlAttestationsV2 is the reference ans-tl attestations shape: plural cert
// arrays (each entry carrying notAfter) and an array-shaped DNS record list
// instead of V1's singleton objects / fqdn-keyed map.
type tlAttestationsV2 struct {
	ServerCerts           []tlCertV2      `json:"serverCerts"`
	IdentityCerts         []tlCertV2      `json:"identityCerts"`
	DNSRecordsProvisioned []tlDNSRecordV2 `json:"dnsRecordsProvisioned"`
	DNSSECStatus          string          `json:"dnssecStatus"`
}

type tlCertV2 struct {
	Fingerprint string `json:"fingerprint"`
	NotAfter    string `json:"notAfter"`
}

type tlDNSRecordV2 struct {
	Name string `json:"name"`
	Data string `json:"data"`
}

// mapEventV2 projects the reference ans-tl's V2 event payload onto the RI's
// tlevent.Event — the same target shape mapEvent produces for V1, so
// everything downstream of tlclient is schema-agnostic. Mirrors mapEvent's
// host-keyed DNS resolution exactly, just building the map from the array
// first; picks one primary fingerprint per cert slot via
// primaryCertFingerprint.
func mapEventV2(in tlEventV2, topLevelStatus string) tlevent.Event {
	host := in.Agent.Host
	ansKey := "_ans." + host
	badgeKey := "_ans-badge." + host

	dns := make(map[string]string, len(in.Attestations.DNSRecordsProvisioned))
	for _, rec := range in.Attestations.DNSRecordsProvisioned {
		dns[rec.Name] = rec.Data
	}

	return tlevent.Event{
		ANSID:       in.ANSID,
		Status:      topLevelStatus,
		FirstSeen:   normalizeRFC3339(in.IssuedAt),
		LastUpdated: normalizeRFC3339(in.Timestamp),
		Agent: tlevent.Agent{
			Host:    host,
			Version: in.Agent.Version,
			Name:    in.Agent.Name,
		},
		Attestations: tlevent.Attestations{
			ServerCert:   tlevent.CertAttestation{Fingerprint: primaryCertFingerprint(in.Attestations.ServerCerts)},
			IdentityCert: tlevent.CertAttestation{Fingerprint: primaryCertFingerprint(in.Attestations.IdentityCerts)},
			DNSRecordsProvisioned: tlevent.DNSRecords{
				ANS:      dns[ansKey],
				ANSBadge: dns[badgeKey],
			},
			DNSSECStatus: in.Attestations.DNSSECStatus,
		},
	}
}

// primaryCertFingerprint picks the fingerprint of the cert entry with the
// newest notAfter (RFC 3339) from a V2 cert array — the "primary" fingerprint
// mapEventV2 maps into the RI's single-cert field (see the package doc's
// cert-set limitation). On a tie for the newest notAfter, or when no entry's
// notAfter parses, it falls back to the first array entry so the result is
// still deterministic. An empty array yields an empty fingerprint.
//
// Full set-membership drift matching across the array remains tlclient's
// documented deferred follow-up; this only selects one primary per slot.
func primaryCertFingerprint(certs []tlCertV2) string {
	if len(certs) == 0 {
		return ""
	}

	bestIdx := 0
	var bestTime time.Time
	bestValid := false
	tie := false

	for i, c := range certs {
		t, err := time.Parse(time.RFC3339, c.NotAfter)
		if err != nil {
			continue
		}
		switch {
		case !bestValid || t.After(bestTime):
			bestIdx, bestTime, bestValid, tie = i, t, true, false
		case t.Equal(bestTime):
			tie = true
		}
	}

	if !bestValid || tie {
		bestIdx = 0
	}
	return certs[bestIdx].Fingerprint
}
