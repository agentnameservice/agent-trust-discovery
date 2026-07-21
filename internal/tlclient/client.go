// Package tlclient is a thin read-only HTTP client for the public
// Transparency Log endpoint GET /v1/agents/{ansId}. It maps the TL response
// into the RI's tlevent.Event shape so cmd/agent-snapshot can persist the
// sealed baseline as fixture YAML the existing hydrator/prober consume
// unchanged.
//
// It decodes both TL badge schemas seen in practice, selected by the
// response's top-level "schemaVersion" discriminator:
//   - "V1" (prod GoDaddy TL): singleton serverCert/identityCert objects,
//     dnsRecordsProvisioned as a map[fqdn]value.
//   - "V2" (the reference ans-tl): plural serverCerts/identityCerts arrays
//     (each entry carrying notAfter), dnsRecordsProvisioned as an array of
//     {data,name,type}.
//
// An empty or unrecognized schemaVersion (e.g. a future V3) falls back to
// the V1 shape; see v2.go for the V2 decode path.
//
// Cert-set limitation: both schemas can carry more than one cert per slot
// (prod's validServerCerts[], the reference's serverCerts[]/identityCerts[]);
// we map only the primary fingerprint into the single RI field (V1: the
// lone object; V2: the entry with the newest notAfter), so drift compares
// against the primary only. Full set-membership matching is a deliberate
// follow-up (plan §2 / design §9).
package tlclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/agentnameservice/agent-trust-discovery/internal/tlevent"
)

// maxResponseBodyBytes caps the successful TL response body decoded into
// memory. The TL endpoint is internal, but this is still an external HTTP
// boundary; bounding the read here mirrors atdclient so every capture-path
// client is deliberately bounded at each external read point.
const maxResponseBodyBytes = 32 << 20 // 32 MiB

// ErrResponseTooLarge is returned when the TL response body exceeds
// maxResponseBodyBytes.
var ErrResponseTooLarge = errors.New("tlclient: response body exceeds size cap")

// Client is a minimal HTTP wrapper.
type Client struct {
	httpClient *http.Client
}

// New returns a Client. A nil httpClient uses http.DefaultClient.
func New(httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &Client{httpClient: httpClient}
}

// Internal wire structs for the V1 (prod) TL response. Only the fields we
// map are declared; everything else is ignored.
//
// Notable shape detail: `status` lives at the response root (not inside
// payload.producer.event); the agent's effective registration timestamps are
// `issuedAt` and `timestamp` on the event (not firstSeen/lastUpdated).
type tlResponse struct {
	Payload       tlPayload `json:"payload"`
	Status        string    `json:"status"`
	SchemaVersion string    `json:"schemaVersion"`
}

type tlPayload struct {
	Producer tlProducer `json:"producer"`
}

type tlProducer struct {
	Event tlEvent `json:"event"`
}

type tlEvent struct {
	ANSID        string         `json:"ansId"`
	IssuedAt     string         `json:"issuedAt"`
	Timestamp    string         `json:"timestamp"`
	Agent        tlEventAgent   `json:"agent"`
	Attestations tlAttestations `json:"attestations"`
}

type tlEventAgent struct {
	Host    string `json:"host"`
	Version string `json:"version"`
	Name    string `json:"name"`
}

type tlAttestations struct {
	ServerCert            tlCert            `json:"serverCert"`
	IdentityCert          tlCert            `json:"identityCert"`
	DNSRecordsProvisioned map[string]string `json:"dnsRecordsProvisioned"`
	DNSSECStatus          string            `json:"dnssecStatus"`
}

type tlCert struct {
	Fingerprint string `json:"fingerprint"`
}

// Fetch issues GET /v1/agents/{ansId} against baseURL and maps the result into
// a tlevent.Event. The returned event is suitable for serializing back to the
// RI's fixture YAML shape (the hydrator/prober consume it directly).
//
// DNS records are FQDN-keyed in prod ("_ans.<host>" / "_ans-badge.<host>"). We
// resolve them by the agent's host and rewrite the keys to the bare "_ans" /
// "_ans-badge" the RI fixture convention uses.
func (c *Client) Fetch(ctx context.Context, baseURL, ansID string) (tlevent.Event, error) {
	if strings.TrimSpace(ansID) == "" {
		return tlevent.Event{}, errors.New("tlclient: ansId is required")
	}

	u, err := buildURL(baseURL, ansID)
	if err != nil {
		return tlevent.Event{}, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return tlevent.Event{}, fmt.Errorf("tlclient: build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return tlevent.Event{}, fmt.Errorf("tlclient: get %s: %w", u, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return tlevent.Event{}, fmt.Errorf("tlclient: get %s returned %d: %s",
			u, resp.StatusCode, strings.TrimSpace(string(msg)))
	}

	// Read at most maxResponseBodyBytes+1 so we can detect overflow after the
	// fact and reject rather than silently truncating (same bounded-read
	// pattern as atdclient).
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodyBytes+1))
	if err != nil {
		return tlevent.Event{}, fmt.Errorf("tlclient: read response: %w", err)
	}
	if int64(len(raw)) > maxResponseBodyBytes {
		return tlevent.Event{}, ErrResponseTooLarge
	}
	// The two schemas are incompatible at the Go type level (V1's attestations
	// are singleton objects, V2's are arrays), so we can't decode both with
	// one struct. Probe the top-level schemaVersion discriminator first — a
	// minimal, always-succeeding decode — and only then unmarshal raw into
	// the matching full struct.
	var schema struct {
		SchemaVersion string `json:"schemaVersion"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		return tlevent.Event{}, fmt.Errorf("tlclient: decode response: %w", err)
	}

	if schema.SchemaVersion == "V2" {
		var body tlResponseV2
		if err := json.Unmarshal(raw, &body); err != nil {
			return tlevent.Event{}, fmt.Errorf("tlclient: decode response: %w", err)
		}
		return mapEventV2(body.Payload.Producer.Event, body.Status), nil
	}

	// "V1", empty, or any unrecognized schemaVersion (a future V3 is out of
	// scope) fall back to the V1 shape, unchanged.
	var body tlResponse
	if err := json.Unmarshal(raw, &body); err != nil {
		return tlevent.Event{}, fmt.Errorf("tlclient: decode response: %w", err)
	}
	return mapEvent(body.Payload.Producer.Event, body.Status), nil
}

func buildURL(baseURL, ansID string) (string, error) {
	base, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("tlclient: parse baseURL: %w", err)
	}
	base.Path = strings.TrimRight(base.Path, "/") + "/v1/agents/" + url.PathEscape(ansID)
	return base.String(), nil
}

// mapEvent projects the prod TL event payload onto the RI's tlevent.Event.
// Top-level status comes from the response root (not inside the event); the
// event's issuedAt / timestamp feed firstSeen / lastUpdated respectively.
// FQDN-keyed DNS records are resolved by the agent host; missing keys become
// empty strings (the prober treats those as a drift "Observed==” vs expected"
// — i.e. visible in scoring, never a silent skip).
func mapEvent(in tlEvent, topLevelStatus string) tlevent.Event {
	host := in.Agent.Host
	ansKey := "_ans." + host
	badgeKey := "_ans-badge." + host

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
			ServerCert:   tlevent.CertAttestation{Fingerprint: in.Attestations.ServerCert.Fingerprint},
			IdentityCert: tlevent.CertAttestation{Fingerprint: in.Attestations.IdentityCert.Fingerprint},
			DNSRecordsProvisioned: tlevent.DNSRecords{
				ANS:      in.Attestations.DNSRecordsProvisioned[ansKey],
				ANSBadge: in.Attestations.DNSRecordsProvisioned[badgeKey],
			},
			DNSSECStatus: in.Attestations.DNSSECStatus,
		},
	}
}

// normalizeRFC3339 trims sub-second precision the tlevent validator's
// time.RFC3339 parse can't handle, e.g. "2026-03-23T19:32:40.047508Z" →
// "2026-03-23T19:32:40Z". Empty input is returned unchanged so a missing
// timestamp surfaces as the validator's "is required" error rather than a
// misleading "not a valid timestamp" error.
//
// The hand-rolled walk is intentional over a time.Parse/Format round-trip —
// it preserves the original timezone offset instead of coercing to UTC, and
// leaves malformed input alone so the downstream validator reports the real
// cause.
func normalizeRFC3339(s string) string {
	if s == "" {
		return ""
	}
	dot := strings.IndexByte(s, '.')
	if dot < 0 {
		return s
	}
	// Find the end of the fractional component (everything up to the
	// timezone designator Z / + / -).
	end := len(s)
	for i := dot + 1; i < len(s); i++ {
		c := s[i]
		if c == 'Z' || c == '+' || c == '-' {
			end = i
			break
		}
	}
	return s[:dot] + s[end:]
}
