# Provenance signing extension (jws) — spec draft (RFC)

**Status:** Draft / RFC — not for merge until the shape settles and it verifies
against ≥ 2 independent signer implementations.
**Builds on:** #18 (surfaces `provenance` on each `SignalScore`), #16 (the
`subject` bucket on a signal). Discussed on #16 and #18.

## Motivation

Today `Provenance` is `aimId` + `evidenceUrl`, and neither is signed. #18 turns
that provenance from stored-and-inert into something every relying party reads.
The next step is to let a consumer **carry a score and independently check it
hasn't drifted, without re-fetching** — i.e. a signed verdict, not a trusted
fetch. Three properties have to hold, each of which is cheap to state now and
awkward to retrofit later:

1. the verifier can tell the carried score matches what was signed (drift check);
2. verification does not require a network fetch at verify time;
3. a signed scan of one agent cannot be re-attached to a different agent.

## The envelope

The provenance envelope gains an optional `signed` object. Absent ⇒ unchanged
behavior (back-compatible; the score is unsigned, as today).

```jsonc
"provenance": {
  "aimId": "did:web:agentgraph.co",
  "evidenceUrl": "https://agentgraph.co/api/v1/public/scan/…",
  "signed": {
    "jws": "<compact JWS, embedded payload>",   // eyJhbGciOiJFZERTQSIsImtpZCI6…
    "kid": "…",                                   // MUST equal the JWS header kid
    "jwks": "https://agentgraph.co/.well-known/jwks.json"  // rotation/discovery only
  }
}
```

## Design decisions (the three pinned in review)

### 1. Embedded (compact JWS), and state the binding

The JWS is **compact with an embedded payload** — self-contained, so
verification is byte-exact and **no canonicalisation rule is required** (this is
why embedded is chosen over a detached proof: a detached proof forces a frozen
JCS/RFC 8785 field set, and two honest implementations that serialise the same
observation differently fail the signature for no reason).

**Binding rule (normative):** the signed payload carries the **authoritative
scored values**. A verifier **MUST** compare them to the container's fields
(`score`, `dimension`, risk codes) and treat a mismatch as a **verification
failure, not a warning**. That comparison *is* the drift check; left unstated it
is a hole (the relying party would hold the score twice with nothing saying they
must agree).

### 2. `kid` in the envelope — otherwise `jwks` reintroduces the fetch

The JWS protected header **MUST** include a `kid`, and the envelope **MUST**
carry the same `kid`. A verifier pins and caches the verifying key by `kid`; the
`jwks` URL is **rotation/discovery fallback only**, not the verify-time hot path.
A bare well-known JWKS URL alone is still a fetch at verification time and does
not deliver the no-refetch property. Keys rotate rarely; evidence is per-scan —
that asymmetry is where the amortisation comes from.

### 3. The signed payload names its subject and its time

The signed payload **MUST** include:

```jsonc
{
  "sub": "<subject id — the entity the scan is about>",
  "subjectClass": "agent" | "tool" | "org",   // the #16 subject bucket
  "iat": 1789600000,                            // issued-at (seconds)
  "dimension": "safety",
  "score": 0,                                   // authoritative; bound per §1
  "riskCodes": ["SAFETY_…"]
}
```

A verifier **MUST** check that `sub` matches the observation's subject; a
mismatch is a verification failure. Without a signed subject, a valid signed
scan of one agent can be re-attached to another agent's observation and still
verify. Carrying `subjectClass` in the payload also lets the credential state
its own #16 bucket rather than trusting the registration entry to be right.

## Verification algorithm

1. If `provenance.signed` is absent → score is unsigned; stop (unchanged).
2. Parse the compact JWS. Read `kid` from the protected header; it **MUST** equal
   `provenance.signed.kid`.
3. Resolve the key by `kid` from cache; on miss, fetch `jwks` once, select by
   `kid`, cache. (Fetch is discovery/rotation, not the steady-state path.)
4. Verify the JWS signature (baseline `alg`: `EdDSA` / Ed25519). Reject any
   `alg` not in the allowed set; never honor `alg: none`.
5. **Binding:** compare the payload's `score` / `dimension` / `riskCodes` to the
   container fields → mismatch is a failure (§1).
6. **Subject:** compare the payload's `sub` to the observation's subject →
   mismatch is a failure (§3).
7. Optionally enforce a max age on `iat` per the relying party's policy.

Any failure ⇒ the score is treated as **unsigned/untrusted**, not silently
accepted.

## Conformance / interop

A signature format only proves portable when someone who did not write the
signer can verify it. Before this shape locks it **MUST** be verified against at
least two independent implementations — e.g. `did:web:dnsofmoney.com`
(detached `eddsa-jcs-2022` + compact JWS with a `kid`) and @kenneives's signer —
producing the same accept/reject verdicts on a shared corpus of test vectors.

## Non-goals / open

- Detached proofs and canonicalisation (out — embedded avoids both).
- Quorum / multi-signer aggregation (later; v1 is single-signer).
- Revocation of a signed scan (handled by the transparency log + score TTL,
  not the envelope).
