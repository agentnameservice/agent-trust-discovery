# Extending agent-trust-discovery with a custom signal

A **signal** turns one piece of evidence about an agent into a score in
`[0, 100]`, an explanation, an attestation tier, and zero or more risk codes.
The eight built-ins (`internal/scoring/signals/`) are worked examples; adding
your own is three steps and no code generation (design §4.3).

> "Plug-in" here means *compile your own binary with extra signals registered* —
> the same model the sibling `ans` repo's adapters use. There is no dynamic
> `plugin` loading.

## The contract: `port.Signal`

```go
type Signal interface {
    ID() domain.SignalID
    Dimension() domain.Dimension

    // Derived reports whether the signal computes itself from agent state and
    // rejects imported observations (e.g. agentage). Most signals return false.
    Derived() bool

    // Validate checks an incoming observation value against this signal's own
    // schema. The import service calls it before persisting. The signal IS the
    // schema — there is no separate registry (design §5.2.1).
    Validate(value json.RawMessage) error

    // Evaluate scores the agent. ctx carries request deadlines/cancellation for
    // signals that call the network (the built-ins are pure and ignore it). obs
    // is the latest observation for this (agent, signal), or nil when none has
    // been recorded — a valid input the signal decides how to handle.
    Evaluate(ctx context.Context, agent domain.Agent, obs *domain.SignalObservation) (SignalResult, error)
}

type SignalResult struct {
    Raw         int                // 0..100
    Explanation string             // surfaced in the API response
    Attestation domain.Attestation // unattested | tl_attested | card_attested
    RiskCodes   []string           // zero or more risk codes (§4.7)
}
```

## Three steps

### 1. Implement `port.Signal` in any package

Co-locate the value schema with the signal by enforcing it in `Validate`. A
worked example — an `uptime` signal in the (currently empty) `behavior`
dimension, scoring 90-day availability:

```go
package mysignals

import (
    "context"
    "encoding/json"
    "fmt"

    "github.com/agentnameservice/agent-trust-discovery/internal/domain"
    "github.com/agentnameservice/agent-trust-discovery/internal/port"
)

type Uptime struct{}

func (Uptime) ID() domain.SignalID         { return "uptime" }
func (Uptime) Dimension() domain.Dimension { return domain.DimensionBehavior }
func (Uptime) Derived() bool               { return false }

type uptimeValue struct {
    Uptime90d float64 `json:"uptime90d"` // fraction in [0,1]
}

func (Uptime) Validate(value json.RawMessage) error {
    var v uptimeValue
    if err := json.Unmarshal(value, &v); err != nil {
        return fmt.Errorf("uptime: invalid value: %w", err)
    }
    if v.Uptime90d < 0 || v.Uptime90d > 1 {
        return fmt.Errorf("uptime: uptime90d must be in [0,1], got %v", v.Uptime90d)
    }
    return nil
}

func (Uptime) Evaluate(_ context.Context, _ domain.Agent, obs *domain.SignalObservation) (port.SignalResult, error) {
    if obs == nil {
        return port.SignalResult{
            Raw:         0,
            Explanation: "no uptime observed",
            Attestation: domain.AttestationUnattested,
            RiskCodes:   []string{"BEHAVIOR_UPTIME_UNKNOWN"},
        }, nil
    }
    var v uptimeValue
    if err := json.Unmarshal(obs.Value, &v); err != nil {
        return port.SignalResult{}, err
    }
    raw := int(v.Uptime90d * 100)
    var risks []string
    if raw < 95 {
        risks = []string{"BEHAVIOR_UPTIME_LOW"}
    }
    return port.SignalResult{
        Raw:         raw,
        Explanation: fmt.Sprintf("90-day uptime %.3f", v.Uptime90d),
        Attestation: domain.AttestationUnattested,
        RiskCodes:   risks,
    }, nil
}
```

See `fixtures/examples/example-custom.yaml` for the observation an `uptime`
hydrator would POST.

### 2. Register it

The built-ins are returned by `internal/scoring/signals.BuiltIns` and registered
by `internal/server.Build`. Add your signal to the registry there:

```go
// in internal/server.Build, after registering the built-ins
if err := reg.Register(mysignals.Uptime{}); err != nil {
    return nil, nil, fmt.Errorf("server: register uptime: %w", err)
}
```

`registry.Register` rejects an empty or duplicate ID, so a wiring mistake fails
loudly at boot rather than silently shadowing a signal.

### 3. Give it a weight

Add a weight in `config/default-profile.yaml` (or any profile selected via
`?profile=<name>` on the read endpoints):

```yaml
signalWeights:
  uptime: 1.0
```

A signal with weight `0` is **inactive**: it still computes and displays a
score, but contributes neither to its dimension's weighted average nor to the
risk-factor list (design §4.2).

## Risk codes (§4.7)

Return them in `SignalResult.RiskCodes`. The engine concatenates risk codes
across all signals in registration order, de-duplicates while preserving order,
and drops those from weight-0 signals. Name them `{DIMENSION}_{SIGNAL}_{CONDITION}`
(e.g. `BEHAVIOR_UPTIME_LOW`), matching the built-ins.

## Activating a previously empty dimension (§4.6 two-gate rollout)

`solvency`, `behavior`, and `safety` ship empty (no signals, dimension weight
`0`). They are always present in the Trust Vector with score `0`, but they are
**not active** — they neither block nor enable the `recommendedProfile`
cascade. A dimension becomes active only when **both** gates open:

1. it carries at least one signal with a **non-zero signal weight**, and
2. the profile sets the **dimension weight to `1`**. The dimension weight is an
   on/off gate (§4.6); v1 reads only its sign, so the loader accepts `0` or `1`
   and nothing else.

So lighting up `behavior` with the `uptime` signal takes two profile edits —
`signalWeights.uptime > 0` **and** `dimensionWeights.behavior: 1`. Until both
are set, `uptime` displays its score for transparency without affecting
classification. This lets you roll a new dimension out observably before it
gates trust decisions.

## Is a missing observation informative? (`AbsenceAware`)

By default, a signal with a profile weight but no observation for an agent
scores `0` at full weight and counts toward its dimension. For the integrity
built-ins that is correct — they are computable from public DNS and certificates
at zero marginal cost, so a *missing* observation (no DNSSEC record) is itself
meaningful.

For a **provider-fed** signal it usually is not. Absence in `solvency`,
`behavior`, or `safety` means "no provider has covered this agent yet", which
says nothing about the agent — and scoring it `0` penalizes the agent for a
coverage gap, so adding any provider becomes a global downgrade for every agent
it has not seen (issue #13).

Opt out by implementing the optional interface:

```go
// AbsenceInformative reports false when a missing observation carries no
// information about the agent. The engine then EXCLUDES this signal from the
// dimension roll-up for agents it has no observation for, instead of scoring 0.
func (s MySignal) AbsenceInformative() bool { return false }
```

Signals that do not implement it, or return `true`, keep the default
absence-scores-zero behavior. A dimension whose every signal is absent-excluded
carries no signal scores and stays inactive (unknown) rather than a misleading
active-`0`. This decides whether your signal is a *term* in the average or is
simply *not present* when you have no data on an agent; it does not change how a
present observation scores.

## Term or gate? (`DimensionCap`)

By default a signal is a **term**: its `Raw` feeds the dimension's weighted
average. That is wrong for a **gate** — a hard stop like a sanctions/compliance
screen or a safety hard-fail. Averaged, a block scoring `0` beside one co-signal
scoring `100` reads `50`, placing a blocked agent above a merely-mediocre one.
The risk code survives, but the score says "pass."

A gate returns a `DimensionCap` on its result to cap the dimension instead of
contributing a term:

```go
zero := 0
return port.SignalResult{
    Raw:          0,
    RiskCodes:    []string{"SAFETY_SANCTIONS_BLOCKED"},
    DimensionCap: &zero, // cap the whole dimension at 0 — blocked is a verdict
}, nil
```

The engine computes `score = min(weightedAverage, min(caps))` over the gating
signals in the dimension. So the block above caps safety at `0` no matter how
the other signals score. Leave `DimensionCap` nil (the default) to stay a normal
term. Notes:

- **Caps only pull down.** There is no floor in v1 — the real gates all lower a
  score, and `min` composes cleanly across several gates.
- **Only an active (weighted) gate caps.** Zeroing a gating signal's profile
  weight disables its cap, the same as it drops its risk codes.
- **Composes with `AbsenceAware`.** An absent, non-informative gate is skipped
  before `Evaluate`, so it produces no cap — only a *present* gate caps. A gate
  and the absence policy never fight: absent means "not participating," present
  means "cap applies."

## What you do not do

- No code generation, no `plugin` loading.
- No separate value-schema registry — `Validate` is the schema.
- No engine changes to add a signal — the engine discovers signals through the
  registry. (The absence semantics above are an existing engine capability a
  signal opts into, not a per-signal engine change.)
