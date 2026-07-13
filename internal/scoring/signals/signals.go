// Package signals holds the eight built-in trust signals (design §4.4): four
// raw-observation signals (certtype, dnssecurity, agentage, versionstability)
// and four drift-verdict signals (certfingerprint.server/.identity,
// dnsrecord.ans/.ans-badge). Each implements port.Signal, owning its own value
// schema (§5.2.1) and the risk codes + attestation tier it reports (§4.1). They
// double as worked examples for out-of-tree custom signals.
package signals

import (
	"time"

	"github.com/agentnameservice/agent-trust-discovery/internal/domain"
	"github.com/agentnameservice/agent-trust-discovery/internal/port"
)

// Risk codes the built-ins emit (design §4.7), named {DIMENSION}_{SIGNAL}_{CONDITION}.
const (
	RiskDNSSECBroken        = "INTEGRITY_DNSSEC_BROKEN"
	RiskAgentNew            = "INTEGRITY_AGENT_NEW"
	RiskVersionChurnHigh    = "INTEGRITY_VERSION_CHURN_HIGH"
	RiskServerCertFPDrift   = "INTEGRITY_SERVER_CERT_FINGERPRINT_DRIFT"
	RiskIdentityCertFPDrift = "INTEGRITY_IDENTITY_CERT_FINGERPRINT_DRIFT"
	RiskDNSANSDrift         = "INTEGRITY_DNS_ANS_DRIFT"
	RiskDNSANSBadgeDrift    = "INTEGRITY_DNS_ANS_BADGE_DRIFT"
	RiskCertDVOnly          = "IDENTITY_CERT_DV_ONLY"
	RiskCertMissing         = "IDENTITY_CERT_MISSING"
)

// Expected-source labels for the drift-verdict convention (design §3.1 #8).
const (
	sourceTLAttestation = "tl_attestation"
	sourceTrustCardHash = "trust_card_hash"
)

// attestationFor maps a verdict's expectedSource to the evidence tier the signal
// reports; unknown/empty → unattested.
func attestationFor(expectedSource string) domain.Attestation {
	switch expectedSource {
	case sourceTLAttestation:
		return domain.AttestationTLAttested
	case sourceTrustCardHash:
		return domain.AttestationCardAttested
	default:
		return domain.AttestationUnattested
	}
}

// BuiltIns returns the eight built-in signals in a stable order. now supplies
// the clock for the derived agentage signal; pass nil to use time.Now.
func BuiltIns(now func() time.Time) []port.Signal {
	return []port.Signal{
		CertType{},
		DNSSECurity{},
		NewAgentAge(now),
		VersionStability{},
		CertFingerprintServer(),
		CertFingerprintIdentity(),
		DNSRecordANS(),
		DNSRecordANSBadge(),
	}
}
