# TrustModel Trust Index Signals — Definitions

Narrow, functional, and defensible definitions for the three signals this package
registers to fill the ANS `agent-trust-discovery` dimensions that are empty in v1
(`solvency`, `behavior`, `safety`; `dimensionWeight 0` in the default profile).

Design rules that make each definition defensible:

1. **Scoped** — every signal states what it does *not* measure, so the dimension
   cannot silently expand.
2. **Functional** — the score is computed from observable, auditable inputs, not
   opinion. No single-judge subjective scoring.
3. **Reproducible** — the score is recomputable from its evidence bundle, so a
   relying party or resolver can audit rather than trust the number.
4. **Evidenced** — every observation carries `provenance{aimId, evidenceUrl}`
   pointing at the record it was derived from.

All signals emit on the existing `port.Signal` contract and set
`Attestation = Unattested` (the score is asserted by the provider; the receipt,
not the signal, is the attestation).

## The generic score container

All three signals share **one** observation container, and `ScoreSignal` is a
generic per-dimension implementation of it. Core hosts a generic `0..100` score
and never re-derives tier or holds a per-dimension opinion — the provider (the
TrustModel hydrator) computes the score and the dimension-scoped risk codes and
hands them across the import boundary. This is deliberate: it keeps the container
reusable by **any** provider (not only TrustModel), and it keeps `solvency` from
re-deriving the cert tier that `certtype` already scores in the `identity`
dimension.

```json
{
  "score": 0,                       // integer 0..100 (required)
  "riskCodes": ["SOLVENCY_..."],    // optional; {DIMENSION}_-prefixed, ^[A-Z0-9_]+$, count-capped
  "explanation": "…"                // optional; surfaced in the API response
}
```

- **Validate** — `score ∈ [0,100]`; each risk code matches `^[A-Z0-9_]+$` and the
  count is capped.
- **Evaluate** — `Raw ← score`; `RiskCodes ← ` the provider's codes (any whose
  `{DIMENSION}_` prefix doesn't match the signal's `Dimension()` are dropped)
  **plus** a normalized `{DIMENSION}_TRUSTMODEL_SCORE_LOW` when `score` is below a
  **configurable** threshold (default `70`). A bare `{"score": N}` still works —
  you then get only the backstop, so nothing regresses for a minimal hydrator.
- No observation → `Raw 0` + `{DIMENSION}_TRUSTMODEL_UNKNOWN`.

---

## 1. `trustmodel.solvency.score` — Operator Accountability

**Dimension:** `solvency`

**Definition.** The degree to which the agent is operated by a verified,
identifiable party that can be held responsible for its actions and exposes a
recourse/revocation path.

**Does NOT measure.** Runtime behavior, output quality, or on-chain settlement
volume — only the *accountability* of the controlling entity. (On-chain
settlement — demonstrated ability to *pay* — is a complementary solvency input;
see issue #9. Both compose into the dimension via this same container.)

**How the score is derived (provider side).** The TrustModel hydrator computes
`score` from the identity-assurance tier of the controlling organization on the
agent's AgentCert plus whether a liable legal entity and a published revocation
path exist — e.g. `EV 100 / OV 75 / DV 40 / unverified 0`. This mapping lives in
the **hydrator**, not in core: core receives a generic `0..100` score so
`solvency` measures the provider's accountability assessment rather than
re-deriving a cert tier already scored under `identity`.

**Provider risk codes.** `SOLVENCY_OPERATOR_UNVERIFIED`, plus the generic
`SOLVENCY_TRUSTMODEL_SCORE_LOW` (below threshold) and `SOLVENCY_TRUSTMODEL_UNKNOWN`
(no observation).

**Evidence.** The X.509 / AgentCert validation record referenced by `evidenceUrl`.

---

## 2. `trustmodel.behavior.score` — Operational Reliability

**Dimension:** `behavior`

**Definition.** The extent to which the agent does what it advertises, correctly
and consistently, under test.

**Does NOT measure.** Subjective helpfulness or tone — only measured task
correctness and stability.

**How the score is derived (provider side).** TrustModel's independent behavior
score: a normalized mean of measured sub-scores — capability/accuracy pass rate,
consistency across repeated runs (reliability), degradation under input
perturbation / adversarial rephrasing (robustness), and output-vs-claim
faithfulness. Evaluated at temperature 0 with multi-judge scoring and judge
fingerprinting (no single-judge scoring).

**Provider risk codes.** e.g. `BEHAVIOR_ACCURACY_LOW`, `BEHAVIOR_INCONSISTENT`,
plus the generic `BEHAVIOR_TRUSTMODEL_SCORE_LOW` / `BEHAVIOR_TRUSTMODEL_UNKNOWN`.

**Evidence.** Evaluation run IDs + report referenced by `evidenceUrl`.

---

## 3. `trustmodel.safety.score` — Harm Resistance

**Dimension:** `safety`

**Definition.** The agent's resistance to producing unsafe, non-compliant, or
privacy-violating output under normal and adversarial input.

**Does NOT measure.** Content style — only violation rates. It scores the
*agent's own* behavior; the static safety of the tools / MCP servers it connects
to is a complementary supply-chain input (see AgentAvow, issue #12) that composes
into `safety` through this same container.

**How the score is derived (provider side).** TrustModel's independent safety
score: a composite of `100 − normalized violation rate` across safety-violation
categories (harmful/toxic), PII / data-leakage rate, prompt-injection / jailbreak
resistance from red-team probes, and applicable regulatory checks. Failures are
counted as signal.

**Provider risk codes.** e.g. `SAFETY_PROMPT_INJECTION`, `SAFETY_PII_LEAK`, plus
the generic `SAFETY_TRUSTMODEL_SCORE_LOW` / `SAFETY_TRUSTMODEL_UNKNOWN`.

**Evidence.** Red-team probe + evaluation results referenced by `evidenceUrl`.

---

## Versioning

These are **v0** reference definitions. Signal IDs (`vendor.dimension.name`) and
the generic score container are stable within a major version; the low-score
threshold is a per-signal config value (default `70`), and the provider-side
score derivations may be tuned in minor revisions and are documented here rather
than hard-coded. Any provider can implement the same container against these
definitions and hydrate a dimension without core holding an opinion.
