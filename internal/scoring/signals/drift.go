package signals

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/agentnameservice/agent-trust-discovery/internal/domain"
	"github.com/agentnameservice/agent-trust-discovery/internal/port"
)

// DriftSignalIDs returns the canonical set of drift-verdict signal IDs
// (design §4.4 Family B). Every producer that shapes a drift observation
// keys off this list: the hydrator (project.go's driftBaseline resolver),
// the prober (probeAgent's emit set — minus documented v1 gaps), and the
// scoring layer registration below. Adding a drift signal is an edit HERE
// plus a matching case in the producers; the invariant tests
// (drift_registry_test.go, project_internal_test.go, prober_test.go) trap
// producers that don't cover it.
//
// A fresh slice is returned each call so callers cannot mutate shared state
// (immutability convention, mirroring domain.AllDimensions).
func DriftSignalIDs() []domain.SignalID {
	return []domain.SignalID{
		"certfingerprint.server",
		"certfingerprint.identity",
		"dnsrecord.ans",
		"dnsrecord.ans-badge",
	}
}

// DriftSignal implements the drift-verdict convention (design §3.1 #8, §4.4
// Family B): the hydrator pairs a sealed baseline with a live value, computes
// matched, and POSTs a verdict. Evaluate is essentially binary: matched→100,
// mismatch→0 + a drift risk code, missing baseline→0 "not sealed". The four
// built-in drift signals differ only in ID, human subject, risk code, and an
// optional value-format check.
type DriftSignal struct {
	id            domain.SignalID
	subject       string
	riskCode      string
	validateValue func(expected, observed string) error
}

func (d DriftSignal) ID() domain.SignalID       { return d.id }
func (DriftSignal) Dimension() domain.Dimension { return domain.DimensionIntegrity }
func (DriftSignal) Derived() bool               { return false }

type driftValue struct {
	Expected       string `json:"expected"`
	Observed       string `json:"observed"`
	Matched        bool   `json:"matched"`
	ExpectedSource string `json:"expectedSource,omitempty"`
	ObservedSource string `json:"observedSource,omitempty"`
}

func decodeDrift(value json.RawMessage) (driftValue, error) {
	var v driftValue
	if err := json.Unmarshal(value, &v); err != nil {
		return driftValue{}, fmt.Errorf("invalid value: %w", err)
	}
	return v, nil
}

// Validate checks the verdict shape and, for fingerprint signals, the
// SHA256:<64 hex> format of any non-empty side. It also cross-checks that
// the producer-reported `matched` bool actually reflects
// `expected == observed` — a mis-reporting producer that sends matched:true
// for divergent values is caught here rather than silently relayed into a
// perfect drift score.
func (d DriftSignal) Validate(value json.RawMessage) error {
	v, err := decodeDrift(value)
	if err != nil {
		return fmt.Errorf("%s: %w", d.id, err)
	}
	if d.validateValue != nil {
		if err := d.validateValue(v.Expected, v.Observed); err != nil {
			return fmt.Errorf("%s: %w", d.id, err)
		}
	}
	// If both sides are populated (i.e. a full baseline+observation verdict),
	// `matched` must equal string equality. An empty expected means "not
	// sealed"; an empty observed means "not observed" — in either case the
	// producer's matched flag is only meaningful when both sides are present.
	if v.Expected != "" && v.Observed != "" && v.Matched != (v.Expected == v.Observed) {
		return fmt.Errorf("%s: matched=%t contradicts expected=%q vs observed=%q",
			d.id, v.Matched, v.Expected, v.Observed)
	}
	return nil
}

// Evaluate turns the verdict into a score + attestation tier + risk code.
func (d DriftSignal) Evaluate(_ context.Context, _ domain.Agent, obs *domain.SignalObservation) (port.SignalResult, error) {
	if obs == nil {
		return port.SignalResult{Raw: 0, Explanation: "no observation", Attestation: domain.AttestationUnattested}, nil
	}
	v, err := decodeDrift(obs.Value)
	if err != nil {
		return port.SignalResult{}, fmt.Errorf("%s: %w", d.id, err)
	}
	att := attestationFor(v.ExpectedSource)

	switch {
	case v.Expected == "":
		return port.SignalResult{Raw: 0, Explanation: d.subject + ": not sealed", Attestation: att}, nil
	case v.Matched:
		return port.SignalResult{Raw: 100, Explanation: d.subject + " matches sealed value", Attestation: att}, nil
	default:
		return port.SignalResult{
			Raw:         0,
			Explanation: fmt.Sprintf("%s drift: sealed=%s observed=%s", d.subject, v.Expected, v.Observed),
			Attestation: att,
			RiskCodes:   []string{d.riskCode},
		}, nil
	}
}

// CertFingerprintServer compares the served TLS cert fingerprint against the
// sealed baseline.
func CertFingerprintServer() DriftSignal {
	return DriftSignal{id: "certfingerprint.server", subject: "serverCert fingerprint", riskCode: RiskServerCertFPDrift, validateValue: fingerprintPair}
}

// CertFingerprintIdentity compares the identity cert fingerprint against the
// sealed baseline.
func CertFingerprintIdentity() DriftSignal {
	return DriftSignal{id: "certfingerprint.identity", subject: "identityCert fingerprint", riskCode: RiskIdentityCertFPDrift, validateValue: fingerprintPair}
}

// DNSRecordANS compares the live _ans TXT record against the sealed baseline.
func DNSRecordANS() DriftSignal {
	return DriftSignal{id: "dnsrecord.ans", subject: "_ans TXT", riskCode: RiskDNSANSDrift}
}

// DNSRecordANSBadge compares the live _ans-badge TXT record against the sealed baseline.
func DNSRecordANSBadge() DriftSignal {
	return DriftSignal{id: "dnsrecord.ans-badge", subject: "_ans-badge TXT", riskCode: RiskDNSANSBadgeDrift}
}

func fingerprintPair(expected, observed string) error {
	for _, s := range []string{expected, observed} {
		if s == "" {
			continue // empty side (not sealed / not observed) is allowed
		}
		if !validFingerprint(s) {
			return fmt.Errorf("fingerprint %q must be SHA256:<64 hex>", s)
		}
	}
	return nil
}

func validFingerprint(s string) bool {
	const prefix = "SHA256:"
	if !strings.HasPrefix(s, prefix) {
		return false
	}
	hexPart := s[len(prefix):]
	if len(hexPart) != 64 {
		return false
	}
	for _, c := range hexPart {
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}
