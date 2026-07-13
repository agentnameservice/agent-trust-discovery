# agent-trust-discovery — Trust Index Reference Implementation

`agent-trust-discovery` is an open-source Go reference implementation of the ANS
**Search / Trust Index API**. It indexes registered AI agents and answers one
question for each of them — *"why does this agent score what it does?"* — by
computing a per-agent **Trust Vector** across the five dimensions defined by the
Trust Index specification (`integrity`, `identity`, `solvency`, `behavior`,
`safety`), each scored as an integer `0–100`, and serving
production-compatible search and detail endpoints.

It is the discovery-and-trust side companion to the
[Agent Name Service (ANS)](https://github.com/agentnameservice/ans): where
`ans` **registers and cryptographically verifies** agents by name (a
Registration Authority + an append-only transparency log), `agent-trust-discovery`
**indexes those agents and scores their trustworthiness** for consumers who are
deciding whether — and how far — to trust an agent they discovered.

Pedagogy is the top goal. Every signal contributes an integer score, an active
weight, and a human-readable explanation, all surfaced in the public API
response, so the scoring is never a black box.

> **Reference implementation, not production.** The eight built-in signals and
> their score curves are deliberately simplified for clarity. `agent-trust-discovery` is
> independent of any specific Agent Identity Management (AIM) stack — it ingests
> observations through a documented HTTP import contract, not through coupling
> to a particular upstream.

## Binaries

| Binary | Port | Role |
| --- | --- | --- |
| `agent-trust-discovery` | 8080 | The HTTP server — read API, admin import API, SQLite + FTS5 storage, scoring engine, signal registry, scoring-profile model |
| `agent-hydrator-stub` | — | The worked-example **hydrator** (Bootstrap archetype): reads fixtures, computes drift verdicts locally, and POSTs observations to `agent-trust-discovery`. Powers `make demo` |
| `agent-snapshot` | — | Live-pipeline capture step: pulls the production GoDaddy Search API and Transparency Log, writes fixture YAML the hydrator/prober consume unchanged. Powers `make demo-live` |
| `agent-prober` | — | Optional real-signal producer (AIM archetype): keeps the sealed baseline from the fixture but produces the live side from **real DNS queries and TLS handshakes**. Off by default; exercised by `make demo-live` |

`agent-trust-discovery` is the only binary that holds state; the other two are evidence
**producers** that sit on the far side of an HTTP trust boundary and write to it.

## Quickstart (offline, deterministic)

```bash
# Prereqs: Go 1.26+, bash, curl, python3
git clone https://github.com/agentnameservice/agent-trust-discovery
cd agent-trust-discovery
make demo
```

`make demo` builds `agent-trust-discovery` + `agent-hydrator-stub`, boots the server on
`:8080` (no auth, fresh `/tmp` SQLite db), hydrates it from `fixtures/` via the
stub hydrator, then runs an eight-stop curl walkthrough. It does **no live
network probes** — every value compared comes from a fixture, so the demo is
fully offline and renders the same population every time.

The walkthrough (`scripts/demo/walkthrough.sh`) demonstrates:

1. **List** all registered agents.
2. **Search** with filters (`query=booking&statuses=ACTIVE`).
3. **Detail** — the full `trustEvaluation` breakdown for one agent.
4. **Mutate a raw observation** (`certtype` DV→EV) and re-score: `identity`
   climbs 40→100, the `IDENTITY_CERT_DV_ONLY` risk factor disappears, and the
   `recommendedProfile` is promoted.
5. **Cert-fingerprint drift** — a one-hex-digit edit produces a verdict mismatch
   and an `INTEGRITY_SERVER_CERT_FINGERPRINT_DRIFT` risk factor.
6. **DNS `_ans` drift** on a pre-rigged agent.
7. **Profile comparison** — the same agent under `?profile=default` vs
   `?profile=identity-strict`, showing how the active scoring profile re-shapes
   the `recommendedProfile`.
8. **Summary table** — one row per agent (status, the five Trust Vector
   integers, `recommendedProfile`, risk count).

## Live demo (`make demo-live` — real prod data, real DNS + TLS probes)

`make demo` is fully offline against curated fixtures. **`make demo-live`**
captures a fresh snapshot from production — the public GoDaddy ANS **Search
API** (`GET /v1/ans/registered-agents`) and **Transparency Log**
(`GET /v1/agents/{ansId}`) — and runs the same hydrator → prober → walkthrough
pipeline against it. The prober's `expected` baseline comes from the
TL-sealed attestations; its `observed` side comes from real DNS TXT lookups
and TLS handshakes against the captured agents' actual hosts.

```bash
make demo-live                  # default: capture 5 agents, run the eight-stop walkthrough
LIMIT=20 make demo-live         # capture up to 20 agents
QUERY=booking make demo-live    # filter the capture by free-text query
```

Under the hood (`scripts/demo/run-demo-live.sh`):

1. **Capture.** `agent-snapshot` walks the public Search API with the
   query/limit you supplied, then for each result fetches the Transparency
   Log entry and writes the merged record to
   `fixtures/snapshot/tl-events/<ansId>.yaml` in the same shape the curated
   fixtures use. Both endpoints are unauthenticated GETs; the rate limit is
   100 req/60s, well above the default `--limit 5` walk.
2. **Boot.** `agent-trust-discovery` starts on `:8080` with
   `config/demo-live.runtime.yaml` (no-auth overlay, separate DB at
   `/tmp/agent-trust-discovery-live-demo.db` so it never collides with `make demo`).
3. **Hydrate.** `agent-hydrator-stub` runs in `mode: real` against
   `fixtures/snapshot/tl-events/` and imports the captured agents only — the
   prober supplies all observations.
4. **Probe.** `agent-prober` reads the same captured fixtures, keeps the sealed
   baseline from the TL, and produces the `observed` side from real DNS and
   TLS against each agent's real host. Unreachable agents yield score-0
   observations, never silent skips.
5. **Walkthrough.** `scripts/demo/walkthrough-live.sh` runs the same
   eight-stop tour as the offline demo, but every agent ID is resolved from
   the live capture and STOPs 4–6 stamp their synthesized observations with
   `now+1h` so they outrank the prober's just-written values.

`agent-snapshot`'s flag set maps 1:1 to the public Search API:
`--query`, `--provider`, `--domain`, `--protocol`, `--transport`, `--tag`,
`--capability`, `--keyword-extraction`, `--keyword-algorithm`, `--profile`,
`--page-size`, `--limit`. Defaults live in `config/snapshot.yaml`; CLI flags
override. `fixtures/snapshot/` is `.gitignore`d so captured prod data never
gets committed by accident.

> **Cert-set limitation (v1).** The prod TL response carries
> `validServerCerts[]` (a set with `notAfter`); `agent-snapshot` writes only
> the primary `serverCert.fingerprint` into the single RI field, so drift
> compares against the primary only. Full set-membership matching and TL
> signature verification are deliberate follow-ups.

## The trust model

Every agent detail embeds a spec-shaped **Trust Evaluation** (Trust Index spec
Appendix B):

- **Trust Vector** — five integers `0–100`, one per dimension. `integrity` and
  `identity` carry signals in v1; `solvency`, `behavior`, and `safety` are
  present in every response with score `0` until plug-in signals are registered.
- **`recommendedProfile`** — a policy hint assigned by an ordered first-match
  cascade over the profile's *active* dimensions: `UNTRUSTED` → `FIDUCIARY` →
  `TRANSACTIONAL` → `READ_ONLY` (fallback). Thresholds are configurable in
  `config/runtime.yaml`.
- **`riskFactors`** — actionable codes (e.g. `IDENTITY_CERT_DV_ONLY`,
  `INTEGRITY_DNS_ANS_DRIFT`), each owned and emitted by the signal that detects
  the condition.
- **`dimensions[]`** — an RI-specific transparency aid listing every signal's
  raw score, active weight, attestation tier, and explanation.

### How a dimension score is computed

Every dimension score is built in two steps, both surfaced in each
`trustEvaluation` so nothing is a black box:

1. **Each signal maps its observation to a raw score `0–100`** via the fixed
   curve in the table below. A signal with no observation scores `0`.
2. **A dimension's score is the weighted average of its signals' raw scores** —
   `round( Σ(raw × weight) / Σ(weight) )` over signals with a non-zero
   `signalWeight`, or `0` if the dimension has none.

For example, under the `default` profile (all weights `1`) seven integrity
signals scoring `100, 91, 33, 100, 100, 100, 100` average to
`round(624 / 7) = 89`. The demo computes `agent-001`'s `integrity` exactly this
way, and every term's `rawScore` and `explanation` appears in the response.
(`agentage` rises with the fixture agent's age, so the demo's exact total drifts
over time — it isn't pinned to `89`.)

> `dimensionWeights` do **not** enter this arithmetic — they are an on/off gate
> that only selects which dimensions drive the `recommendedProfile` cascade
> (below).

### Built-in signals

Eight illustrative signals in two families — **raw observations** and **drift
verdicts**. A drift-verdict signal scores a `{expected, observed, matched, …}`
comparison the hydrator already computed, so `agent-trust-discovery` never ingests
transparency-log events itself.

| Signal | Family | Dimension | Raw score `0–100` |
| --- | --- | --- | --- |
| `certtype` | raw | identity | `EV → 100`, `OV → 70`, `DV → 40`, `none`/absent → `0` |
| `dnssecurity` | raw | integrity | DNSSEC + CAA → `100`; exactly one → `50`; neither → `0` |
| `agentage` (derived) | raw | integrity | age ramp `round(100 × days / 180)`, capped at `100` |
| `versionstability` | raw | integrity | `round(100 / (1 + versionChanges30d))` |
| `certfingerprint.server` | drift | integrity | verdict `matched → 100`; mismatch → `0`; unsealed → `0` |
| `certfingerprint.identity` | drift | integrity | verdict `matched → 100`; mismatch → `0`; unsealed → `0` |
| `dnsrecord.ans` | drift | integrity | verdict `matched → 100`; mismatch → `0`; unsealed → `0` |
| `dnsrecord.ans-badge` | drift | integrity | verdict `matched → 100`; mismatch → `0`; unsealed → `0` |

These curves are deliberately simplified for pedagogy (design §4.4); production
Trust Index scoring is richer.

### Scoring profiles

A **scoring profile** (YAML, `config/`) configures the scoring. `signalWeights`
set how signals roll up *within* a dimension; `dimensionWeights` are an on/off
gate selecting which dimensions drive the `recommendedProfile` cascade (in v1
each is `0` or `1` — magnitude is reserved for a future cross-dimension
aggregate). Two profiles ship — `default` and `identity-strict` — and a profile
is chosen per request via the `?profile=` query parameter. This is **distinct**
from `recommendedProfile`, which is the spec's output classification.

## API surface

`spec/api-spec-search.yaml` is the canonical OpenAPI contract.

**Read endpoints** (mirror production verbatim; no auth in v1):

```
GET  /v1/ans/registered-agents             # search via query params
POST /v1/ans/search-registered-agents      # search via JSON body
GET  /v1/ans/registered-agents/{agentId}   # detail (embeds trustEvaluation)
GET  /health                               # liveness; always open
```

**Admin import endpoints** (the only ingress for state; written by hydrators):

```
POST /v1/internal/agents/import            # upsert agents (keyed on agentId)
POST /v1/internal/observations/import      # append signal observations
```

Errors are RFC 7807 `application/problem+json`; clients read the `code` field.

## Architecture

Hexagonal / ports-and-adapters, mirroring the `ans` repo's shape. The domain
model (`internal/domain`) has zero infrastructure dependencies. The defining
boundary is the **producer ↔ Trust-Index split across an HTTP edge**:

```
  Evidence producers (untrusted side)          agent-trust-discovery (the binary)
  ┌─────────────────────────────────┐          ┌──────────────────────────────┐
  │ agent-hydrator-stub  (fixtures)    │  POST    │ import service  ─┐            │
  │ agent-prober         (live DNS/TLS)│ ───────► │ /v1/internal/*   │           │
  │ your own AIM / feed / curl       │          │                  ▼           │
  └─────────────────────────────────┘          │            SQLite + FTS5      │
                                                │                  ▲           │
  read clients ── GET/POST /v1/ans/* ─────────► │ search service ──┤           │
                                                │ scoring engine ──┘           │
                                                │   8 built-in signals + plugins│
                                                └──────────────────────────────┘
```

`agent-trust-discovery` has no opinion on what's on the producer side — it accepts any
observation that passes the per-signal `Validate` schema and stores it.

## Two extension contracts

Both halves of "extend the system" are first-class and documented:

1. **Signal definitions** — implement the `port.Signal` interface (`Derived`,
   `Validate`, `Evaluate`), register it inside `agent-trust-discovery`, and ship a weight
   in a profile. No code generation, no dynamic plug-in loading. See
   [`docs/extending-signals.md`](docs/extending-signals.md).
2. **Signal hydration** — write any process in any language that POSTs to the
   documented import contract; swap in your own evidence source (an AIM bus, a
   threat-intel feed, WHOIS, periodic TLS handshakes) without touching
   `agent-trust-discovery`. The interface *is* the HTTP contract — there is no
   `port.Hydrator`. See
   [`docs/extending-signal-sources.md`](docs/extending-signal-sources.md).

## Configuration

YAML configs live under `config/`:

- `runtime.yaml` — `agent-trust-discovery` server: listen addr, db path, admin-key policy
  (**secure by default**: `admin.requireKey: true`), log level, and the
  `recommendedProfile` classification thresholds.
- `demo.runtime.yaml` — the `make demo` overlay; disables admin auth for a
  frictionless walkthrough (and logs a loud warning when it does).
- `demo-live.runtime.yaml` — `make demo-live` overlay, same shape with a
  separate DB path so it never collides with the offline demo.
- `default-profile.yaml`, `profiles/identity-strict.yaml` — scoring profiles.
- `hydrator.yaml`, `hydrator.snapshot.yaml` — `agent-hydrator-stub`: target URL,
  `mode` (mock/real), source dirs. The `.snapshot.yaml` variant points at
  `fixtures/snapshot/` and runs in `real` mode for `make demo-live`.
- `prober.yaml`, `prober.snapshot.yaml` — `agent-prober`: target URL, TL-events
  dir, probe cadence/timeout. The `.snapshot.yaml` variant points at the
  captured snapshot dir.
- `snapshot.yaml` — `agent-snapshot`: Search/TL base URLs, output dir, and
  default search filters (CLI flags override).

## Development

```bash
make build        # build all packages and commands
make test         # unit tests
make test-cover   # with coverage; enforces the gate (≥90% over internal/)
make test-race    # race detector
make check        # fmt + vet + lint + test-cover (pre-commit gate)
make demo         # the offline end-to-end walkthrough (curated fixtures)
make demo-live    # the live end-to-end walkthrough (real prod capture + probes)
```

Coverage gate: ≥90% across `internal/` with `internal/domain` at 100%; `cmd/*`
is excluded from the denominator (thin wiring, exercised end-to-end). Structured
JSON logging via `log/slog`; every request carries a `requestId`.

## Status

**v1 ships** the full read API (search + detail with the spec-shaped Trust
Evaluation), the admin import API, eight built-in signals across two families,
two scoring profiles, the `recommendedProfile` cascade, the stub hydrator that
powers the offline demo, the optional real-signal prober, and the
`agent-snapshot` live-capture step that realizes the TL-sourced sealed baseline
for `make demo-live`.

**Deferred to v2**: full `validServerCerts[]`
set-membership matching (v1 maps only the primary fingerprint), TL signature
verification on the snapshot, AIM signature verification + quorum,
verification tiers (Bronze/Silver/Gold), the conformant `/v1/trust/evaluate`
endpoint with a W3C Verifiable Credential envelope, score caching, Trust
Manifest / Trust Card ingestion, and production-grade auth adapters.

## License

MIT License — see [`LICENSE`](LICENSE). Matches the
[ANS project](https://github.com/agentnameservice/ans).
