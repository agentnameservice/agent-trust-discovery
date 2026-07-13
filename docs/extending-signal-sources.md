# Extending agent-trust-discovery with a custom signal source (hydrator / AIM)

A **hydrator** produces observations and POSTs them to agent-trust-discovery's import
contract. It decides *where evidence comes from* — a TL-event feed plus a live
network probe, a WHOIS lookup, a threat-intel feed, an upstream AIM bus. This is
the *other half* of the extension story from `docs/extending-signals.md`: that
one defines *what a signal means*; this one defines *where its observations come
from*.

`agent-trust-discovery` has no opinion about which hydrator a deployment runs. The bundled
`cmd/agent-hydrator-stub` (the Bootstrap archetype) is one worked example;
`cmd/agent-prober` (optional, design §6.6) is another.

## The interface IS the HTTP contract

There is **no `port.Hydrator` or `port.AIM` interface inside agent-trust-discovery**. A
hydrator integrates by authenticating and POSTing valid JSON to two endpoints
(design §5.2):

```
POST /v1/internal/agents/import          # upsert agents (keyed on agentId)
POST /v1/internal/observations/import    # append observations
```

Write your hydrator in any language, run it on any schedule, swap it out without
rebuilding agent-trust-discovery. Pushing it in-process would force every author to ship a
Go binary linked against agent-trust-discovery internals — exactly the coupling the
producer/TI process split avoids (design §6.1, §6.4).

## Five shape rules (§6.5)

1. **POST agents before their observations.** An observation for an unknown
   `agentId` is rejected with `422 AGENT_NOT_FOUND`.
2. **Honor `INVALID_SIGNAL_VALUE`.** A `422` means the value failed the signal's
   `Validate`. Stop and surface the error (it names the `signalId`, `agentId`,
   and the validation message); do not silently retry.
3. **Treat the import API as authoritative.** The signal's `Validate` is the
   schema — there is no separate registry to consult. If the import accepts it,
   it is valid; if it rejects it, fix the value.
4. **Follow the drift-verdict convention for drift-style signals.** Emit
   `{expected, observed, matched, expectedSource?, observedSource?}` so the
   engine can label the resulting `signalScore` with the right `attestation`
   tier (design §3.1 decision #8). Non-drift signals keep whatever value shape
   their `Validate` enforces.
5. **Identify yourself in `provenance.aimId`** when multiple AIMs run against
   the same agent-trust-discovery. v1 stores it and surfaces it; v2 will use it for quorum
   and signature verification (design §9).

## Attestation tiers

The engine derives a `signalScore.attestation` from a drift verdict's
`expectedSource`:

| `expectedSource` | resulting `attestation` |
|---|---|
| `tl_attestation` | `tl_attested` |
| `trust_card_hash` | `card_attested` (v2) |
| anything else / absent | `unattested` |

Raw (non-drift) observations are `unattested` — they carry no sealed baseline.

## The standard AIM loop

When a real production AIM replaces the stub, only *where the baseline and the
live value come from* changes; everything downstream is identical:

```
loop:
  events = read_tl_events_since(cursor)              # the AIM's own subscription
  for each event in events:
      sealed = parse event.attestations              # the sealed baselines
      live   = my_local_check(event.agent.host)      # DNS query, TLS handshake, …
      for each (signal_id, expected, observed) in compare(sealed, live):
          POST /v1/internal/observations/import {
            agentId:    event.ansId,
            signalId:   signal_id,
            observedAt: now(),
            value:      { expected, observed, matched: (expected == observed),
                          expectedSource: "tl_attestation",
                          observedSource: "live_dns_query" },  // or "live_tls_handshake"
            provenance: { aimId: my_id, evidenceUrl: ... }
          }
  cursor = max(events.timestamps)
  sleep(cadence)
```

Compared to `cmd/agent-hydrator-stub`, only `read_tl_events_since` and
`my_local_check` change — the stub reads both sides from fixtures; a real AIM
reads `expected` from a TL feed and `observed` from a live probe. The value
shape, the observation endpoint, and the provenance block are identical. That
sameness *is* the extension contract.

## A minimal hydrator, end to end

The bundled stub (`internal/hydrator`) is the reference. Its essence:

1. Read your evidence source (the stub reads `fixtures/tl-events/*.yaml`).
2. Project each agent and `POST /v1/internal/agents/import` **first**.
3. For each observation, build the value (raw, or a drift verdict pairing a
   sealed baseline against a live value) and `POST
   /v1/internal/observations/import`.
4. On any non-`200`, stop and surface the body (rule 2).

Authentication is a static admin key when `admin.requireKey` is true: send
`Authorization: Bearer <key>`. When it is false (e.g. behind a trusted reverse
proxy, or `make demo`), no header is needed.
