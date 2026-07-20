# Design: Import ANS agents into the Trust Index

**Date:** 2026-07-16 (updated 2026-07-17 for the RA event feed; re-validated 2026-07-21 against merged `main`)
**Status:** Design complete — validated against merged ANS `main`; all §12 open items resolved (2026-07-21). Implementation plan deferred.
**Repos:** `github.com/godaddy/ans` (ANS — RA/TL; GitHub `agentnameservice/ans`), `github.com/agentnameservice/agent-trust-discovery` (Trust Index)

## 0. Validation against merged `main` (2026-07-21)

ANS **PR #46** (`feat/ans-finder` — the event feed + `ans-finder`) and the follow-on
**PR #47** (AI Catalog, FQDN exclusivity, seal-before-success activation) are both **merged
to `main`** (`agentnameservice/ans` @ `daf5ba12`). Re-checked every load-bearing assumption
against `main`:

- **Feed contract unchanged.** `GET /v1/agents/events` — anonymous exact-path; `limit`
  (default 100, max 200) + `lastLogId` cursor; `EventPage{items,lastLogId}`; the
  `FeedEventItem` fields and the `eventType` enum (`AGENT_REGISTERED|RENEWED|REVOKED|
  DEPRECATED`) are exactly what §3.1 documents.
- **Retention unchanged.** `feed.go` still read-filters `created_at_ms >= now − retention`,
  default `720h`/30d, `<=0` coerced to `720h`. §8 and §12-item-1 stand as written.
- **Seal-before-success does NOT break the feed (the one real risk).** #47 activates inline
  — `verify-dns` seals `AGENT_REGISTERED` and bypasses the outbox worker the feed reads
  from. To keep registrations discoverable it added `OutboxStore.RecordSealed`, which
  inserts a **pre-delivered** row (`sent_at_ms` + `log_id` set at insert, inside the
  activation tx). Net: `AGENT_REGISTERED` still surfaces on the feed, atomically with the
  agent going `ACTIVE`; a consumer sees no difference.
- **`createdAt` = the producer's event `timestamp`** (not the outbox row's wall-clock), so
  the §7.1 `firstSeen` = earliest `AGENT_REGISTERED` derivation remains accurate.
- **Reference consumer + fold still present** (`internal/finder/poller`, `.../project`,
  `.../feed`), so §4 / §7's "mirror the finder" guidance holds; still under `internal/`, so
  §12-item-2 (re-implement, use as oracle) stands.

**Verdict: the plan is still valid — no structural change required.** Two additive,
non-blocking notes from #47 are folded into §12 (item 5): the new ARD URN, and the
owner-scoped AI-Catalog endpoints (which are *not* a global-enumeration alternative). All
five §12 items were subsequently **resolved** (2026-07-21) — see §12.

## 1. Problem & goal

The Trust Index (`agent-trust-discovery`) computes a five-dimension Trust Vector over
registered agents, but today it can only ingest through its admin import contract, fed
by fixtures snapshotted from the **public** GoDaddy deployment. There was no path to pull
agents from a **private** ANS deployment into the index — and the RA's `GET /v2/ans/agents`
is owner-scoped, with no global enumeration.

**ANS PR #46** (`feat/ans-finder`) changes the picture: it adds a **public, unauthenticated
agent-lifecycle event feed** to the RA at `GET /v1/agents/events`, plus a new `ans-finder`
discovery service that consumes it. The feed is exactly the global-enumeration surface
this design needs.

**Goal:** import agents from a private ANS deployment into the Trust Index by **consuming
the RA event feed** (no RA change), folding lifecycle events into the agent catalog,
enriching with Transparency-Log baselines, and feeding the existing import/probe/score
pipeline.

**Relationship to `ans-finder`:** PR #46's `ans-finder` is an ARD discovery/search service
that polls the same feed and serves *search*. The Trust Index overlaps on catalog, but its
differentiator is **trust scoring + live prober observations**, which the finder does not
do. This design deliberately consumes the *same* feed the finder consumes and layers
scoring on top; where practical it mirrors the finder's ingestion pattern
(`internal/finder/poller` + `internal/finder/project`).

## 2. Decisions (locked during brainstorming)

| Decision | Choice | Rationale |
|---|---|---|
| Enumeration source | **RA `GET /v1/agents/events` feed** (PR #46) | Public, cursor-paginated, TL-sealed. Already exists. |
| RA change | **None** | The feed is already in PR #46; the earlier plan's new `/v2/admin/agents` admin endpoint is **removed**. |
| Data-flow shape | **Pull** | The Trust-repo producer polls the feed. |
| Deliverable | **Design/plan only** | No code this session. |
| Import content | **Agents + TL-derived baselines** | Feed → agent catalog; TL → sealed attestation baselines. |
| Sync model | **Incremental via cursor** | The feed's `lastLogId` cursor is built-in; no `updatedSince` to invent. |
| Ingestion shape | **Feed → fold → fixtures** | ra-sync writes `tl-events/` fixtures; hydrator + prober run **unchanged**. Keeps TL-fetching in one place. |
| Topology | **Mimic `make demo-live`** | Reuse the proven `enumerate → fixtures → hydrator + prober` seam. |

## 3. Key mechanics (verified in code; drive the design)

### 3.1 The RA event feed (ANS PR #46)

`GET /v1/agents/events` — `internal/ra/handler/v1events.go`, `internal/ra/service/feed.go`,
route wired anonymously in `cmd/ans-ra/main.go` via an **exact-path** exemption
(`WithAnonymousExactPath`; exact so it can't disable auth on the `/v1/agents/{agentId}/…`
wildcard siblings).

- **Auth:** public / unauthenticated.
- **Query params:** `limit` (1–200, default 100; out-of-range → 422), `lastLogId` (opaque
  cursor; rows *after* it), `providerId` (parity only — empty page on the OSS RA).
- **Response** `EventPageResponse`: `{ "items": EventItem[], "lastLogId": "…" }`. `items`
  always an array (never null); `lastLogId` omitted at the tail.
- **`EventItem`:** `logId`, `eventType`, `createdAt`, `expiresAt?`, `agentId`, `ansName`,
  `agentHost`, `agentDisplayName?`, `agentDescription?`, `version`, `providerId?` (never
  emitted by OSS RA), `endpoints[]` (`agentUrl`, `metaDataUrl?`, `documentationUrl?`,
  `protocol`, `transports[]`, `functions[]`). Protocol/transport tokens are the
  hyphenated wire form (`HTTP-API`, `STREAMABLE-HTTP`, `JSON-RPC`).
- **`eventType` enum:** `AGENT_REGISTERED`, `AGENT_RENEWED`, `AGENT_REVOKED`,
  `AGENT_DEPRECATED`.
- **Sealed only:** the feed serves rows gated on `sent_at_ms IS NOT NULL AND log_id IS NOT
  NULL` — an item appearing here is **sealed in the Transparency Log and its receipt is
  resolvable from `logId`** (tamper-evident discovery).
- **Retention window:** an unknown cursor and an aged-out cursor are indistinguishable —
  both restart from the oldest retained row. The feed is a recent-events window, not a
  complete historical dump (see §8 retention caveat).
- **Reference consumer to mirror:** `internal/finder/poller` (durable cursor, single-writer,
  fail-soft — wedges at the cursor on a structural error rather than skipping) and
  `internal/finder/project` (the fold: `AGENT_REGISTERED`/`AGENT_RENEWED` → active catalog
  entry fanned across endpoints; `AGENT_REVOKED`/`AGENT_DEPRECATED` → tombstone; unknown
  eventType → skip-alert, no error).

### 3.2 Scoring is lazy and observation-backed

`internal/scoring/engine/engine.go` `Engine.Evaluate` runs **on every read** (no cache).
For each signal it fetches the **latest** observation for `(agent, signal)` — `nil` if none
— and calls `signal.Evaluate(agent, obs)`; a signal with no observation scores **0** (and
may raise a risk code). **Importing an agent creates no observations.** The two import
endpoints are independent:

- `POST /v1/internal/agents/import` → the **agent record** only.
- `POST /v1/internal/observations/import` → **observation rows** (append-only, idempotent
  on `(agentId, signalId, observedAt)`).

### 3.3 Built-in signals: derived vs observation-backed

`internal/scoring/signals/`:

| Signal | Dimension | `Derived()` | Value schema | Source in this design |
|---|---|---|---|---|
| `agentage` | integrity | **true** | computed from `agent.FirstSeen`, ramps to 100 at 180d; **rejects** imports (422) | The agent record's `firstSeen` — no observation emitted. |
| `certtype` | identity | false | `{"type":"DV\|OV\|EV\|none"}` | Prober (live TLS). |
| `versionstability` | integrity | false | `{"versionChanges30d":N}` | Optional ra-sync-derived (feed version history). |
| `dnssecurity` | integrity | false | `{"dnssec":bool,"caa":bool}` | Prober (`caa` live; `dnssec` v1-stub). |
| `certfingerprint.server` / `.identity` | integrity | false | drift verdict `{expected,observed,matched,…}` | Prober: `expected` from fixture baseline, `observed` live. |
| `dnsrecord.ans` / `.ans-badge` | integrity | false | drift verdict | Prober: `expected` from fixture baseline, `observed` live. |

**Consequences:** (a) getting `firstSeen` right on the agent record is what makes
`agentage` score — so the fold must set `firstSeen` = the earliest `AGENT_REGISTERED`
`createdAt`, not the latest event's time. (b) drift verdicts need **both** a TL baseline
(`expected`) and a live value (`observed`), so they are produced by the **prober**, never
fabricated at import — which is why TL baselines are captured into the fixture the prober
reads, not imported as standalone observations.

### 3.4 The `demo-live` fixture seam

`make demo-live` runs `agent-snapshot` (enumerate prod Search API + capture per-agent TL
events → `fixtures/snapshot/tl-events/<ansId>.yaml`) → boot server → `agent-hydrator-stub`
(imports **agents** from those fixtures) → `agent-prober` (probes each fixture's host,
pairs the fixture's attestation baselines with live values into drift verdicts, POSTs
observations). **Both the hydrator and the prober read the same `tl-events/` directory —
that directory is the worklist and the baseline source.**

## 4. Approach

**`agent-ra-sync` = `agent-snapshot` with the feed as its enumeration front-end.** It polls
`GET /v1/agents/events`, folds the lifecycle events into the current agent set, enriches
each agent with TL baselines via the existing `tlclient`, and writes the identical
`tl-events/<ansId>.yaml` fixture shape. The hydrator and prober then run **completely
unchanged**.

Difference from `agent-snapshot`: the agent list comes from the **event feed** (folded
incremental events) instead of the prod Search API (`atdclient`); everything downstream is
the same.

### 4.1 Superseded alternatives (recorded)

- **New RA `/v2/admin/agents` admin endpoint** (this design's earlier draft): **removed.**
  PR #46's public feed does the same enumeration with *zero* RA change, no admin bearer
  key, a built-in incremental cursor, and TL-sealed items.
- **Enumerate from the TL badge endpoints + RA per-agent detail:** still not viable — the
  TL exposes only per-`agentId` lookups and log metadata (`internal/tl/handler/handler.go`
  `Mount`), no list/leaf endpoint. The event feed realizes the same *tamper-evident
  enumeration* idea, but on the RA and already projected/denormalized (no raw-leaf replay).
- **Feed → direct import (mirror `ans-finder`):** viable and truly incremental, but forces
  the **prober** to change (fetch TL baselines itself + take its worklist from the catalog),
  splitting TL-fetching across two producers. Rejected in favor of feed → fixtures, which
  keeps TL-fetching in one place and leaves the prober untouched. Trade-off recorded here
  in case volume later makes full-snapshot regeneration undesirable.

## 5. Topology

```
                 demo-live (today)                          integrated (this design)
   agent-snapshot ──▶ fixtures/snapshot/tl-events/    agent-ra-sync ──▶ fixtures/ra-sync/tl-events/
     source: prod Search API (atdclient)               source: RA  GET /v1/agents/events  (poll + fold)  [EXISTS, PR #46]
     baselines: prod TL (tlclient)                      baselines: private TL GET /v1/agents/{ansId} (tlclient, reused)
                     │                                                  │
        ┌────────────┴────────────┐                         ┌───────────┴───────────┐
  hydrator (real) → imports agents   prober → live obs    hydrator (real) → agents   prober → live obs
     (UNCHANGED)                      (UNCHANGED)             (UNCHANGED)               (UNCHANGED)
```

The integration reduces to **one new snapshot-shaped producer that polls an
already-existing RA feed**; RA is unchanged, and the existing import/probe/score pipeline
runs unchanged on top.

## 6. RA surface consumed (existing — no RA change)

`GET /v1/agents/events` (§3.1), plus the reused TL `GET /v1/agents/{agentId}` for
baselines. Nothing is added to `github.com/godaddy/ans`.

## 7. Trust Index change (the new producer)

`github.com/agentnameservice/agent-trust-discovery`. Mirrors `internal/snapshot` /
`cmd/agent-snapshot`, with a feed-poller front-end modeled on `internal/finder/poller` +
`internal/finder/project`.

- **`internal/raclient`** — feed client for `GET /v1/agents/events`: cursor pagination via
  `lastLogId`, `limit`, context deadlines, SSRF-safe base-URL handling. Returns typed
  `EventPage`/`EventItem` byte-compatible with the RA swagger.
- **`internal/rasync`** — the producer core:
  1. **Drain** the feed from the start cursor, following `lastLogId` until the tail.
  2. **Fold** events into current agent state (`AGENT_REGISTERED`/`AGENT_RENEWED` → upsert;
     `AGENT_REVOKED` → `REVOKED`; `AGENT_DEPRECATED` → `DEPRECATED`), tracking
     `lastUpdated` = latest event `createdAt`. `firstSeen` is taken from the TL badge in
     step 3 (authoritative, not retention-bound), not from the fold — see §7.1 and §12
     item 1. The fold is **re-implemented** from `internal/finder/project` semantics (not
     importable across modules; §12 item 2).
  3. **Enrich** each folded agent with TL baselines via the reused `internal/tlclient`
     (`GET /v1/agents/{ansId}` → `Attestations`), and take `firstSeen` from the badge's
     registration seal timestamp. For `ACTIVE` agents the badge is **guaranteed** to exist
     (seal-before-success; §12 item 4), so this is the norm. The best-effort
     empty-attestation fallback (the prober then emits non-matching drift verdicts) covers
     only TL-outage or non-`ACTIVE` edge cases and never aborts the agent.
  4. **Assemble** a `tlevent.Event` per agent from the folded catalog fields + TL
     attestations, and **write** `fixtures/ra-sync/tl-events/<ansId>.yaml` using the
     `internal/snapshot` conventions (wipe-and-rewrite the dir, `safeFileName(ansId)`,
     `0o600`).
- **`cmd/agent-ra-sync`** — binary; `-config config/ra-sync.yaml`; single-pass exit code
  reflects the run (mirrors `agent-snapshot`/`agent-prober`).
- **Reused unchanged:** `internal/tlclient`, `internal/tlevent`, `internal/hydrator`,
  `internal/prober`, the server, and both import endpoints.

### 7.1 Field mapping (feed `EventItem` → `tlevent.Event`)

- `agentId` → `ANSID`; `ansName`/`agentHost`/`version` → the event's name/host/version
  (`dnsName` becomes `ans://{version}.{host}` downstream in the hydrator's `projectAgent`).
- `agentDisplayName` → `Name` (the import DTO requires a non-empty `displayName`; when the
  feed omits it, fall back to `agentHost`, matching the finder's no-displayname handling).
- `agentDescription` → `Description`; `endpoints[]` → the event endpoints (protocols /
  transports / functions).
- `firstSeen` ← the **TL badge** registration/seal timestamp (`tlclient`; authoritative and
  independent of the feed retention window), falling back to the earliest `AGENT_REGISTERED`
  `createdAt` seen in the feed when the badge is unavailable. `lastUpdated` = latest event
  `createdAt`. (Resolves the retention-window `firstSeen` skew — §12 item 1.)
- **Status from `eventType`:** latest `AGENT_REGISTERED`/`AGENT_RENEWED` → `ACTIVE`;
  `AGENT_REVOKED` → `REVOKED`; `AGENT_DEPRECATED` → `DEPRECATED`. (`WARNING`/`EXPIRED` are
  Trust-Index-derived / not feed-sourced.)
- `Attestations` ← TL (`tlclient`), not the feed.

### 7.2 Optional ra-sync-derived observations (opt-in)

Faithful to `demo-live` real mode, observations come from the **prober**. As an opt-in
enhancement so agents score before the first probe, ra-sync may also write an
`observations/` fixture set the hydrator imports in its combined/mock mode:
`versionstability` (`versionChanges30d` = count of `AGENT_REGISTERED`/supersession events
for an `agentId` in the trailing 30d; a stable agent → 100; **undercounts under a retention
window shorter than 30d**, biasing optimistic — §12 item 3) and `dnssecurity.dnssec` (from
the TL badge's `dnssecStatus`). `agentage` is never emitted (derived; 422); `certtype` is
left to the prober's live read.

## 8. Sync semantics, error handling, operability

- **Cursor:** the feed is incremental via `lastLogId`.
  - **v1 (stateless — chosen; §12 item 1):** each run drains from the oldest retained row,
    folds in memory to current state, and wipe-and-rewrites the fixture set. Simple, matches
    `agent-snapshot`'s stateless model. `firstSeen` comes from the TL badge (§7.1) so
    `agentage` stays accurate; the **cold-start discovery gap** (agents with no lifecycle
    event inside the retention window are unseen) is **accepted as a documented v1
    limitation**.
  - **incremental-ready evolution (deferred):** persist `lastLogId` + a projected catalog
    (as `ans-finder` does) so state accumulates across runs and survives events aging out of
    the window. Adopt if the deployment's `retention` proves insufficient for a complete
    catalog.
- **Fold safety:** unknown `eventType` → skip that item with an alert, never a crash
  (mirrors `internal/finder/project`); a structural feed error wedges at the cursor rather
  than silently skipping (mirrors the poller).
- **Lifecycle:** `REVOKED`/`DEPRECATED` agents are emitted with the correct status (the
  index shows them, not deletes them). Hard-delete is out of scope.
- **Boundaries:** context timeouts on all HTTP calls; the feed is anonymous (no secret to
  hold) but the TL base URL is validated; the prober's existing `blockInternalAddr` SSRF
  guard continues to protect live probes.
- **Failure:** a page fetch/enrich/write failure is retried with backoff; a run that can't
  complete exits non-zero. The writer wipe-and-rewrites `tl-events/` per run, so a partial
  set is never half-consumed.

### Retention caveat — the feed is a bounded window, not full history

The feed is a **read model over the RA's `outbox_events` table**. That table is **never
pruned** (`internal/adapter/store/sqlite/migrations/006_outbox_log_id.sql`: *"a table that
is never pruned … the aged-out prefix grows for the life of the deployment"*), but the feed
applies a **retention floor on every read** — `internal/adapter/store/sqlite/feed.go`
`ReadFeed` filters `created_at_ms >= now − retention`, defaulting to **30 days** (`720h`;
`internal/config/config.go` coerces a `<=0` value to `720h`, `defaults.go:54`). Retention
is a read filter, **not** deletion.

**There is no caller-side way to page before that floor.** An empty, unknown, or aged-out
`lastLogId` all resolve to the **oldest *retained* row** (`resolveCursor`), never the true
first event, and there is no query parameter to disable or widen the window. The
consequences:

- **`agent-ra-sync` only ever receives the oldest *retained* events — never the oldest
  events.** Any lifecycle event enqueued before `now − retention` is invisible to the feed
  and is **never ingested**, even though it still physically exists in the RA's outbox
  table. Events genuinely older than the retention period simply cannot be pulled through
  this API.
- **Cold-start discovery gap:** an agent whose most recent event predates the window (e.g.
  registered 40 days ago, still `ACTIVE`, not renewed within 30 days) does not appear at
  all — you cannot index an agent you never see.
- **`firstSeen` skew:** even for agents that do appear, folding only in-window events can
  place `firstSeen` at a visible `AGENT_RENEWED` time rather than the original
  `AGENT_REGISTERED` time — corrupting the derived `agentage` signal (§3.3).

The only lever that reaches older events is **operator-side on the RA** (widen `retention`
to a large duration so the floor approaches 0); there is nothing `agent-ra-sync` can do as
a client to see past the window. Trust-side mitigations are in §12 item 1.

## 9. Config & wiring

- **`config/ra-sync.yaml`** (mirrors `config/snapshot.yaml`): `raUrl` (feed base), `tlUrl`,
  `out` (default `fixtures/ra-sync`), `pageSize` (≤200), and an `emitObservations` toggle
  for §7.2.
- **`make demo-ra`** target mirroring `demo-live`:
  `agent-ra-sync → boot server → hydrator (real) → prober → walkthrough`. `make demo` and
  `make demo-live` remain untouched.

## 10. Testing

- **`raclient`:** feed pagination against an `httptest` RA (multi-page drain, tail
  detection, `limit` bounds → 422, aged-out cursor restart); error/timeout paths.
- **`rasync` fold:** table-driven over event sequences — register→active, renew updates +
  preserves `firstSeen`, revoke→REVOKED, deprecate→DEPRECATED, out-of-order/duplicate
  `logId`, unknown eventType → skip. Assert `firstSeen`/`lastUpdated` derivation.
- **`rasync` fixtures:** given a fake feed + fake TL, assert the exact
  `tl-events/<ansId>.yaml` written (status mapping, displayName fallback, best-effort TL
  degradation); optional `observations/` fixtures when `emitObservations` is on.
- **End-to-end:** fake feed + fake TL → `agent-ra-sync` → real hydrator + prober-with-mock
  `Probe` → real import handlers against a temp SQLite store; assert agents + scores land
  and a re-run is idempotent.
- Run with `-race`; target the repo's 80% coverage bar.

## 11. Explicitly out of scope (YAGNI)

- Any change to `github.com/godaddy/ans` (the feed already exists).
- A long-running durable-catalog service (v1 is a stateless batch producer; durable cursor
  is the documented evolution, not v1).
- Live `certfingerprint.identity` observed values (needs the AIM identity endpoint; v2).
- Hard-delete propagation.
- Reconciling / merging with `ans-finder` (separate service; this design only *consumes the
  same feed*).

## 12. Resolved decisions (were open items; resolved 2026-07-21)

1. **Retention / cold-start completeness — RESOLVED: stateless v1 + TL-badge `firstSeen`.**
   The feed serves only events within the RA's retention window (`created_at_ms >= now −
   retention`, default **30 days**; `feed.go` `ReadFeed`), and no API parameter widens it
   (§8). v1 is therefore a **stateless** producer (drain each run, fold in memory,
   wipe-and-rewrite fixtures — matching `agent-snapshot`). `firstSeen` and authoritative
   current fields are sourced from the **TL badge** (`tlclient`), which is independent of the
   retention window, so the derived `agentage` signal stays accurate. The **cold-start
   discovery gap** — agents with no lifecycle event inside the retention window are not seen
   — is **accepted as a documented v1 limitation**. The **durable accumulating catalog +
   persisted cursor** (mirrors `ans-finder`) is the **deferred evolution** (§11), adopted if
   the target deployment's configured `retention` proves insufficient for a complete catalog.

2. **Reusing `internal/finder` code — RESOLVED: re-implement.** `internal/finder/poller`,
   `.../project`, and `.../feed` live under `github.com/godaddy/ans/internal/`, so they are
   **not importable** from `agent-trust-discovery` (separate module; `internal/` visibility).
   The fold is **re-implemented** in `internal/rasync` following the same rules, with the
   finder (and `internal/ard`) as the reference/conformance oracle — `eventType` constants
   and fold semantics pinned by golden-file parity tests (§10).

3. **`versionstability` from the feed — RESOLVED: derive, with a documented caveat.** A
   version bump is a **supersession**: the superseded registration emits `AGENT_DEPRECATED`
   (with `supersededById`) and the new version emits `AGENT_REGISTERED`, both under the same
   immutable `agentId`. `versionChanges30d` is therefore the count of `AGENT_REGISTERED`
   events for an `agentId` in the trailing 30 days — derivable from the fold (a stable agent
   → 0 → score 100). **Caveat:** bounded by feed retention; under a window shorter than 30
   days the count **undercounts**, biasing the score optimistically. Emitted only under the
   `emitObservations` opt-in (§7.2); otherwise left unset (the prober does not produce it).

4. **TL baseline coverage — RESOLVED: guaranteed for `ACTIVE` agents.** #47's
   **seal-before-success** activation is fail-closed: an agent reaches `ACTIVE` only after
   the TL acknowledges its sealed `AGENT_REGISTERED` (otherwise `TL_UNAVAILABLE`, the agent
   stays `PENDING_DNS`). So every `ACTIVE` agent surfaced by the feed has a resolvable TL
   record, and `GET /v1/agents/{agentId}` (`GetBadge`) returns the attestations `tlclient`
   maps (`serverCert` / `identityCert` fingerprints, `dnsRecordsProvisioned`,
   `dnssecStatus`). §7 step-3 enrichment is therefore the **norm**; the best-effort
   empty-attestation fallback covers only TL-outage or non-`ACTIVE` edge cases.

5. **ARD URN identity parity — RESOLVED: not adopted in v1.** The Trust Index keys on
   `agentId` (the import DTO's required id) and `ansName`, as specified; it does **not**
   adopt `internal/ard`'s `urn:air:{host}:agents:{label}` in v1. The owner-scoped AI-Catalog
   endpoints (`GET /v2/ans/agents/{agentId}/catalog-entry`, `/ai-catalog`) are
   per-agent/per-host artifacts, **not** a global-enumeration alternative — the anonymous
   event feed remains the enumeration source. *Revisit if cross-surface correlation with the
   Finder / AI Catalog becomes a product need.*
