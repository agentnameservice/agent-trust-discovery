#!/usr/bin/env bash
# walkthrough.sh — the eight-stop tour of the agent-trust-discovery read API (design §8.1).
# Pure curl against a running agent-trust-discovery; closes with a one-row-per-agent
# summary table. Pedagogical only — not an API contract. Run via `make demo`,
# or standalone against an already-populated server: BASE=http://host:port bash scripts/demo/walkthrough.sh
set -euo pipefail

BASE="${BASE:-http://localhost:8080}"
RO="/v1/ans/registered-agents"

hr()  { printf '\n──────────────────────────────────────────────────────────────\n'; }
stop() { hr; printf '  STOP %s — %s\n' "$1" "$2"; hr; }

# get PATH  → raw JSON body
get()  { curl -fsS "$BASE$1"; }
# py 'expr-using d'  ← stdin JSON as d
py()   { python3 -c "import sys,json; d=json.load(sys.stdin); $1"; }

# ── Stop 1: list the population ───────────────────────────────────────
stop 1 "List all registered agents"
get "$RO?pageSize=100&totalRequired=true" | py '
print("total indexed:", d.get("totalItems"));
[print(" ", a["agentId"].ljust(12), a["status"].ljust(11), a["displayName"]) for a in d["items"]]'

# ── Stop 2: search ────────────────────────────────────────────────────
stop 2 "Search: query=booking, statuses=ACTIVE"
get "$RO?query=booking&statuses=ACTIVE" | py '
[print(" ", a["agentId"], "→", a["displayName"]) for a in d["items"]] or print("  (no matches)")'

# ── Stop 3: detail with the Trust Evaluation breakdown ────────────────
stop 3 "Detail for agent-001 (Trust Evaluation breakdown)"
echo "  Signals are grouped by pillar (dimension); each pillar score = weighted average of its raw scores."
get "$RO/agent-001" | py '
te=d["trustEvaluation"]; tv=te["trustVector"];
print("  trustVector:", tv);
print("  recommendedProfile:", te["recommendedProfile"]);
print("  verificationTier:", te["verificationTier"]);
print("  riskFactors:", te["riskFactors"]);
print("  scoringProfile:", te["scoringProfile"]);
print("  signals by pillar:");
for dim in te["dimensions"]:
    ss = dim["signalScores"]
    print("    {} (score {}){}".format(dim["dimension"], dim["score"], "" if ss else " — no signals in v1"))
    for s in ss:
        print("      {:26} raw={:>3} w={} {:<12} {}".format(s["signalId"], s["rawScore"], s["weight"], s["attestation"], s["explanation"]))'

# ── Stop 4: mutate a raw observation (certtype DV→EV) and re-score ────
stop 4 "Promote agent-001's certtype DV → EV, then re-score"
curl -fsS -X POST "$BASE/v1/internal/observations/import" \
  -H 'Content-Type: application/json' \
  -d '{"observations":[{"agentId":"agent-001","signalId":"certtype","observedAt":"2026-06-25T00:00:00Z","value":{"type":"EV"}}]}' >/dev/null
echo "  POSTed certtype=EV; re-fetching detail…"
get "$RO/agent-001" | py '
te=d["trustEvaluation"];
print("  identity:", te["trustVector"]["identity"], "(was 40 for DV)");
print("  recommendedProfile:", te["recommendedProfile"]);
print("  riskFactors:", te["riskFactors"], "(IDENTITY_CERT_DV_ONLY should be gone)")'

# ── Stop 5: certificate-fingerprint drift (verdict observation) ───────
stop 5 "Server-cert fingerprint drift on agent-001"
curl -fsS -X POST "$BASE/v1/internal/observations/import" \
  -H 'Content-Type: application/json' \
  -d '{"observations":[{"agentId":"agent-001","signalId":"certfingerprint.server","observedAt":"2026-06-25T00:00:00Z","value":{"expected":"SHA256:1010101010101010101010101010101010101010101010101010101010101010","observed":"SHA256:DEADBEEF10101010101010101010101010101010101010101010101010101010","matched":false,"expectedSource":"tl_attestation","observedSource":"fixture"}}]}' >/dev/null
echo "  POSTed a mismatched server-cert verdict; re-fetching detail…"
get "$RO/agent-001" | py '
te=d["trustEvaluation"];
print("  riskFactors:", te["riskFactors"]);
[print("   ", s["signalId"], "→", s["explanation"]) for dim in te["dimensions"] for s in dim["signalScores"] if s["signalId"].startswith("certfingerprint")]'

# ── Stop 6: DNS-record drift (the pre-rigged drifting-agent) ──────────
stop 6 "DNS _ans drift on agent-006 (pre-rigged fixture)"
get "$RO/agent-006" | py '
te=d["trustEvaluation"];
print("  riskFactors:", te["riskFactors"]);
[print("   ", s["signalId"], "→", s["explanation"]) for dim in te["dimensions"] for s in dim["signalScores"] if s["signalId"].startswith("dnsrecord")]'

# ── Stop 7: compare scoring profiles ──────────────────────────────────
stop 7 "Same agent, two profiles: default vs identity-strict"
for p in default identity-strict; do
  get "$RO/agent-001?profile=$p" | py "
te=d['trustEvaluation'];
print('  {:16} trustVector={} recommendedProfile={}'.format('$p', te['trustVector'], te['recommendedProfile']))"
done

# ── Stop 8: summary table ─────────────────────────────────────────────
stop 8 "Summary table — one row per agent"
printf '  %-12s %-11s %4s %4s %4s %4s %4s  %-14s %s\n' agentId status int idn slv beh saf recommended risks
ids=$(get "$RO?pageSize=100" | py '[print(a["agentId"]) for a in d["items"]]')
for id in $ids; do
  get "$RO/$id" | py "
te=d['trustEvaluation']; tv=te['trustVector'];
print('  {:<12} {:<11} {:>4} {:>4} {:>4} {:>4} {:>4}  {:<14} {}'.format(
  d['agentId'], d['status'], tv['integrity'], tv['identity'], tv['solvency'], tv['behavior'], tv['safety'],
  te['recommendedProfile'], len(te['riskFactors'])))"
done
hr
echo "  Walkthrough complete."
