package signals_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/agentnameservice/agent-trust-discovery/internal/domain"
	"github.com/agentnameservice/agent-trust-discovery/internal/scoring/signals"
)

type driftCase struct {
	sig      signals.DriftSignal
	id       domain.SignalID
	risk     string
	isFinger bool
}

func driftCases() []driftCase {
	return []driftCase{
		{signals.CertFingerprintServer(), "certfingerprint.server", signals.RiskServerCertFPDrift, true},
		{signals.CertFingerprintIdentity(), "certfingerprint.identity", signals.RiskIdentityCertFPDrift, true},
		{signals.DNSRecordANS(), "dnsrecord.ans", signals.RiskDNSANSDrift, false},
		{signals.DNSRecordANSBadge(), "dnsrecord.ans-badge", signals.RiskDNSANSBadgeDrift, false},
	}
}

func TestDriftMetaAndVerdicts(t *testing.T) {
	for _, dc := range driftCases() {
		t.Run(string(dc.id), func(t *testing.T) {
			if dc.sig.ID() != dc.id || dc.sig.Dimension() != domain.DimensionIntegrity || dc.sig.Derived() {
				t.Fatalf("meta wrong: id=%s dim=%s derived=%v", dc.sig.ID(), dc.sig.Dimension(), dc.sig.Derived())
			}

			// matched → 100, tl_attested, no risk.
			matched := fmt.Sprintf(`{"expected":%q,"observed":%q,"matched":true,"expectedSource":"tl_attestation"}`, validFP, validFP)
			res, err := dc.sig.Evaluate(context.Background(), domain.Agent{}, obsOf(matched))
			if err != nil {
				t.Fatalf("matched Evaluate: %v", err)
			}
			if res.Raw != 100 || res.Attestation != domain.AttestationTLAttested || len(res.RiskCodes) != 0 {
				t.Errorf("matched: %+v", res)
			}

			// mismatch → 0 + this signal's risk code.
			mism := fmt.Sprintf(`{"expected":%q,"observed":"SHA256:%s","matched":false,"expectedSource":"tl_attestation"}`, validFP, strings.Repeat("d", 64))
			res, err = dc.sig.Evaluate(context.Background(), domain.Agent{}, obsOf(mism))
			if err != nil {
				t.Fatalf("mismatch Evaluate: %v", err)
			}
			if res.Raw != 0 || !sameStrings(res.RiskCodes, []string{dc.risk}) {
				t.Errorf("mismatch: raw=%d risks=%v want 0 + %s", res.Raw, res.RiskCodes, dc.risk)
			}

			// missing sealed baseline → 0, "not sealed", no risk.
			res, err = dc.sig.Evaluate(context.Background(), domain.Agent{}, obsOf(`{"expected":"","observed":"x","matched":false}`))
			if err != nil {
				t.Fatalf("not-sealed Evaluate: %v", err)
			}
			if res.Raw != 0 || len(res.RiskCodes) != 0 || !strings.Contains(res.Explanation, "not sealed") {
				t.Errorf("not sealed: %+v", res)
			}

			// nil observation → 0, no risk.
			res, err = dc.sig.Evaluate(context.Background(), domain.Agent{}, nil)
			if err != nil || res.Raw != 0 || len(res.RiskCodes) != 0 {
				t.Errorf("nil obs: res=%+v err=%v", res, err)
			}
		})
	}
}

func TestDriftAttestationTiers(t *testing.T) {
	s := signals.DNSRecordANS()
	cases := map[string]domain.Attestation{
		`"tl_attestation"`:  domain.AttestationTLAttested,
		`"trust_card_hash"`: domain.AttestationCardAttested,
		`"fixture"`:         domain.AttestationUnattested,
	}
	for src, want := range cases {
		v := fmt.Sprintf(`{"expected":"x","observed":"x","matched":true,"expectedSource":%s}`, src)
		res, err := s.Evaluate(context.Background(), domain.Agent{}, obsOf(v))
		if err != nil {
			t.Fatalf("Evaluate(%s): %v", src, err)
		}
		if res.Attestation != want {
			t.Errorf("expectedSource %s → %v, want %v", src, res.Attestation, want)
		}
	}
	// absent expectedSource → unattested.
	res, err := s.Evaluate(context.Background(), domain.Agent{}, obsOf(`{"expected":"x","observed":"x","matched":true}`))
	if err != nil || res.Attestation != domain.AttestationUnattested {
		t.Errorf("absent source: att=%v err=%v", res.Attestation, err)
	}
}

func TestDriftEvaluateMalformed(t *testing.T) {
	if _, err := signals.DNSRecordANS().Evaluate(context.Background(), domain.Agent{}, obsOf(`not-json`)); err == nil {
		t.Error("malformed value: want error")
	}
}

func TestDriftValidate(t *testing.T) {
	// Fingerprint signals enforce the SHA256 format; DNS signals accept any string.
	server := signals.CertFingerprintServer()
	if err := server.Validate(json.RawMessage(fmt.Sprintf(`{"expected":%q,"observed":%q,"matched":true}`, validFP, validFP))); err != nil {
		t.Errorf("Validate good fingerprint: %v", err)
	}
	if err := server.Validate(json.RawMessage(`{"expected":"deadbeef","observed":"deadbeef","matched":true}`)); err == nil {
		t.Error("Validate short/no-prefix fingerprint: want error")
	}
	// Right length + prefix but a non-hex character.
	nonHex := "SHA256:" + strings.Repeat("a", 63) + "z"
	if err := server.Validate(json.RawMessage(fmt.Sprintf(`{"expected":%q,"observed":%q,"matched":true}`, nonHex, validFP))); err == nil {
		t.Error("Validate non-hex fingerprint: want error")
	}
	// Empty sides are allowed (not sealed / not observed).
	if err := server.Validate(json.RawMessage(`{"expected":"","observed":"","matched":false}`)); err != nil {
		t.Errorf("Validate empty sides: %v", err)
	}

	dns := signals.DNSRecordANS()
	if err := dns.Validate(json.RawMessage(`{"expected":"v=ans1; url=x","observed":"v=ans1; url=x","matched":true}`)); err != nil {
		t.Errorf("Validate dns txt: %v", err)
	}
	if err := dns.Validate(json.RawMessage(`not-json`)); err == nil {
		t.Error("Validate malformed: want error")
	}
}

// TestDriftValidate_MatchedContradictsSides asserts that a producer claiming
// matched:true for divergent expected/observed values is rejected at import
// time, not silently relayed into a perfect drift score. Also guards the
// symmetric case (matched:false when the two sides are equal).
func TestDriftValidate_MatchedContradictsSides(t *testing.T) {
	dns := signals.DNSRecordANS()

	// matched=true but sides differ → reject.
	err := dns.Validate(json.RawMessage(`{"expected":"a","observed":"b","matched":true}`))
	if err == nil || !strings.Contains(err.Error(), "matched=true") {
		t.Errorf("matched=true with differing sides: want error mentioning matched=true, got %v", err)
	}

	// matched=false but sides equal → also a contradiction.
	err = dns.Validate(json.RawMessage(`{"expected":"a","observed":"a","matched":false}`))
	if err == nil || !strings.Contains(err.Error(), "matched=false") {
		t.Errorf("matched=false with equal sides: want error mentioning matched=false, got %v", err)
	}

	// Consistent cases still pass.
	if err := dns.Validate(json.RawMessage(`{"expected":"a","observed":"a","matched":true}`)); err != nil {
		t.Errorf("consistent matched=true: %v", err)
	}
	if err := dns.Validate(json.RawMessage(`{"expected":"a","observed":"b","matched":false}`)); err != nil {
		t.Errorf("consistent matched=false: %v", err)
	}

	// Empty sides bypass the cross-check (not-sealed / not-observed cases).
	if err := dns.Validate(json.RawMessage(`{"expected":"","observed":"a","matched":true}`)); err != nil {
		t.Errorf("empty expected: %v", err)
	}
	if err := dns.Validate(json.RawMessage(`{"expected":"a","observed":"","matched":false}`)); err != nil {
		t.Errorf("empty observed: %v", err)
	}
}
