# OpenShell Policy-Adherence Signal — Definition

`openshell.behavior.activity` is a policy-adherence score in the `behavior`
dimension (empty in v1; `dimensionWeight 0` in the default profile) for agents
running in [NVIDIA OpenShell](https://github.com/NVIDIA/OpenShell) sandboxes.
It is an opt-in, config-driven registration of the shared score container:
`config/examples/openshell-signals.yaml` registers it, and
`config/examples/openshell-profile.yaml` weights it.

The score is computed by the provider, the
[ans-openshell](https://github.com/agentnameservice/ans-openshell) hydrator,
from OpenShell's OCSF audit log. Core stores and surfaces it without
re-deriving it. Hydrator configuration and the full counting rules are
documented in ans-openshell's `docs/hydrator-activity.md`.

## Observation value

The hydrator posts the generic score container value to
`/v1/internal/observations/import`:

```json
{
  "score": 92,              // integer 0..100 (required)
  "explanation": "…"        // window, per-group decision counts, policy context, findings
}
```

- **Risk codes** — the hydrator sends none. The registration sets
  `threshold: 0`, which disables the generic `BEHAVIOR_OPENSHELL_SCORE_LOW`
  code: the score is an adherence rate, not a pass/fail verdict.
- **Provenance** — `provenance.aimId` identifies the hydrator instance;
  `provenance.evidenceUrl` is set when the operator configures one.
- **Timestamp** — `observedAt` is the end of the measured window.
- **Absence** — like every score-container signal, an agent with no observation
  is excluded from the roll-up rather than scored 0 (`AbsenceInformative` is
  false).

## Definition

**Dimension:** `behavior`

**Definition.** How consistently OpenShell's configured policy allowed an
agent's policy-evaluated network actions during the measured window, taken
from the group of checks with the lowest allowed rate (see below).

**Does NOT measure.** Content safety, task correctness, or whether the policy
itself is appropriate. The score is relative to the policy the operator
configured; scores are comparable only under the same policy, so the
explanation names up to four observed policies by hash prefix and, when
present, version, and says when a policy was loaded mid-window.

**How the score is derived (provider side).** The hydrator counts OpenShell's
allowed, denied and audited policy decisions in four groups: connection checks,
initial HTTP checks, checks after middleware rewrites a request, and WebSocket
message checks. For each group it computes
`100 × allowed / (allowed + denied + audited)` and sends the lowest eligible
group rate, rounded to an integer. An audited decision counts against the score
even when OpenShell let the request through. Connection failures, supervisor
sessions and health reports are not policy decisions and are not counted, and
an upstream error response does not lower the score.

**When no score is sent.** The hydrator sends no observation for an agent when
a window has no eligible decisions, when a group with a denied or audited
decision has fewer decisions than `activity.min_decisions`, or when one of its
input checks fails (for example unreadable records, unrecognized policy syntax,
or an exhausted deduplication budget). The reason is kept in the hydrator's
local evidence output.

**Evidence.** The hydrator can write a local JSONL evidence record per agent
with the decision counts, policy context and diagnostics behind each score.
That file stays with the operator; it is not sent to the Trust Index.

## Rollout: keep the weight at 0

The engine reads the newest observation for each agent and signal, and
retention never removes it. When the hydrator sends no new score, the previous
one, including 100, stays in effect until a later window replaces it. A repeat
of the same window (same `observedAt`) is ignored as a duplicate, even if its
value differs.

The example profile therefore keeps the signal at weight 0: its score and
explanation appear in `signalScores`, but it contributes neither score nor risk
codes, and the behavior dimension stays out of the `recommendedProfile`
cascade. Raise the weight only once stale observations can be invalidated.

## Versioning

This is a **v0** reference definition. The provider-side counting rules are
documented and versioned in ans-openshell; a change to the signal id or value
shape would be made there first and reflected in this example.
