#!/usr/bin/env bash
# walkthrough-live.sh — live-data variant of walkthrough.sh. Same structure
# (the eight-stop tour of the read API) but every agent ID is resolved from
# the live capture rather than hardcoded to the mock fixture set. The
# pre-rigged DNS-drift stop (Stop 6 in walkthrough.sh) is dropped because
# its target agent only exists in the curated mock fixtures; an inline
# DNS-drift observation is POSTed instead so the same scoring path is
# still exercised.
#
# Run via `make demo-live`, or standalone:
#   BASE=http://host:port bash scripts/demo/walkthrough-live.sh
set -euo pipefail

BASE="${BASE:-http://localhost:8080}"
RO="/v1/ans/registered-agents"

hr()  { printf '\n──────────────────────────────────────────────────────────────\n'; }
stop() { hr; printf '  STOP %s — %s\n' "$1" "$2"; hr; }
get()  { curl -fsS "$BASE$1"; }
py()   { python3 -c "import sys,json; d=json.load(sys.stdin); $1"; }

# snapshot prints a one-line "int=… idn=… profile=… risks=…" for the given
# agent, labelled with $2. Called before and after each mutating stop so the
# effect (or lack of effect — see the notes at each stop) is unambiguous even
# when the live capture already carries drift risks that hold the score down.
snapshot() {
  get "$RO/$1" | py "
te=d['trustEvaluation']; tv=te['trustVector']
print('  {:<7} int={:>3} idn={:>3} slv={:>3} beh={:>3} saf={:>3} profile={:<14} risks={} [{}]'.format(
    '$2:', tv['integrity'], tv['identity'], tv['solvency'], tv['behavior'], tv['safety'],
    te['recommendedProfile'], len(te['riskFactors']), ', '.join(te['riskFactors']) or '—'))"
}

# The store keeps the latest observation per (agent, signal) by observedAt
# (internal/adapter/sqlitestore/agentstore.go:108). The prober just stamped
# its run with time.Now(), so a hand-crafted POST must be NEWER to take
# effect. We stamp every synthesized observation one hour in the future so
# it always wins regardless of prober timing.
NOW_PLUS_1H=$(python3 -c \
  'import datetime,sys; print((datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"))')

# Resolve a representative ACTIVE agent up-front. Every parameterized stop
# below targets this id so the walkthrough is self-contained even when the
# capture set changes between runs.
ID=$(get "$RO?pageSize=100&statuses=ACTIVE" | python3 -c \
  'import sys,json; d=json.load(sys.stdin); print(d["items"][0]["agentId"] if d["items"] else "")')
if [ -z "$ID" ]; then
	echo "✗ no ACTIVE agents in the live capture — try a wider --query / --limit" >&2
	exit 1
fi

# ── Stop 1: list the population ───────────────────────────────────────
stop 1 "List all registered agents"
get "$RO?pageSize=100&totalRequired=true" | py '
print("total indexed:", d.get("totalItems"));
[print(" ", a["agentId"], a["status"].ljust(11), a["displayName"]) for a in d["items"]]'

# ── Stop 2: search (broad — the live set is whatever was captured) ────
stop 2 "Search: statuses=ACTIVE"
get "$RO?statuses=ACTIVE" | py '
[print(" ", a["agentId"], "→", a["displayName"]) for a in d["items"]] or print("  (no matches)")'

# ── Stop 3: detail with the Trust Evaluation breakdown ────────────────
stop 3 "Detail for $ID (Trust Evaluation breakdown)"
echo "  Signals are grouped by pillar (dimension); each pillar score = weighted average of its raw scores."
get "$RO/$ID" | py '
te=d["trustEvaluation"]; tv=te["trustVector"];
vec=" ".join("{}={}".format(k, tv[k]) for k in ("integrity","identity","solvency","behavior","safety"));
print("  trustVector:", vec);
print("  recommendedProfile:", te["recommendedProfile"]);
print("  verificationTier:", te.get("verificationTier") or "unset");
print("  riskFactors:", ", ".join(te["riskFactors"]) or "(none)");
print("  scoringProfile:", te["scoringProfile"]);
print("  signals by pillar:");
for dim in te["dimensions"]:
    ss = dim["signalScores"]
    print("    {} (score {}){}".format(dim["dimension"], dim["score"], "" if ss else " — no signals in v1"))
    for s in ss:
        print("      {:26} raw={:>3} w={} {:<12} {}".format(s["signalId"], s["rawScore"], s["weight"], s["attestation"], s["explanation"]))'

# ── Stop 4: mutate a raw observation (certtype → EV) and re-score ─────
stop 4 "Promote $ID's certtype → EV, then re-score"
snapshot "$ID" "before"
curl -fsS -X POST "$BASE/v1/internal/observations/import" \
  -H 'Content-Type: application/json' \
  -d "{\"observations\":[{\"agentId\":\"$ID\",\"signalId\":\"certtype\",\"observedAt\":\"$NOW_PLUS_1H\",\"value\":{\"type\":\"EV\"}}]}" >/dev/null
echo "  POSTed certtype=EV (observedAt=$NOW_PLUS_1H, newer than prober); re-fetching detail…"
snapshot "$ID" "after"
echo "  Note: certtype feeds the identity dimension, so idn should climb (DV→EV: 40→100)."
echo "        recommendedProfile is a cross-dimension classify; if this agent has real"
echo "        DNSSEC/cert-fingerprint drift from the prober capture, integrity stays"
echo "        low and the profile may not lift. Compare int= before vs after — if it"
echo "        didn't move, the drift risks in [risks: …] are why."

# ── Stop 5: certificate-fingerprint drift (verdict observation) ───────
stop 5 "Server-cert fingerprint drift on $ID"
# Preserve the real TL-attested (sealed) fingerprint from the prober observation;
# only the observed value is faked to trigger drift.
SEALED_CERT=$(get "$RO/$ID" | python3 -c "
import sys, json, re
d = json.load(sys.stdin)
for dim in d['trustEvaluation']['dimensions']:
    for s in dim['signalScores']:
        if s['signalId'] == 'certfingerprint.server':
            m = re.search(r'sealed=(SHA256:\S+)', s.get('explanation', ''))
            if m: print(m.group(1))
            break
")
SEALED_CERT="${SEALED_CERT:-SHA256:0000000000000000000000000000000000000000000000000000000000000000}"
snapshot "$ID" "before"
curl -fsS -X POST "$BASE/v1/internal/observations/import" \
  -H 'Content-Type: application/json' \
  -d "{\"observations\":[{\"agentId\":\"$ID\",\"signalId\":\"certfingerprint.server\",\"observedAt\":\"$NOW_PLUS_1H\",\"value\":{\"expected\":\"$SEALED_CERT\",\"observed\":\"SHA256:DEADBEEF10101010101010101010101010101010101010101010101010101010\",\"matched\":false,\"expectedSource\":\"tl_attestation\",\"observedSource\":\"fixture\"}}]}" >/dev/null
echo "  POSTed a mismatched server-cert verdict; re-fetching detail…"
snapshot "$ID" "after"
echo "  Note: the prober's live TLS handshake may have already produced this same"
echo "        drift risk. If [risks: …] already contained INTEGRITY_SERVER_CERT_FINGERPRINT_DRIFT"
echo "        before, this stop is layering a synthetic verdict on top — the risk-factor"
echo "        count stays the same but the explanation string below now reflects our"
echo "        synthetic (expected, observed) pair instead of the prober's."
get "$RO/$ID" | py '
te=d["trustEvaluation"];
[print("   ", s["signalId"], "→", s["explanation"]) for dim in te["dimensions"] for s in dim["signalScores"] if s["signalId"].startswith("certfingerprint")]'

# ── Stop 6: DNS-record drift (synthesized, since live capture has no rigged drift) ─
stop 6 "DNS _ans drift on $ID (synthesized)"
# Preserve the real TL-attested (sealed) _ans TXT value; only the observed value is faked.
SEALED_ANS=$(get "$RO/$ID" | python3 -c "
import sys, json, re
d = json.load(sys.stdin)
for dim in d['trustEvaluation']['dimensions']:
    for s in dim['signalScores']:
        if s['signalId'] == 'dnsrecord.ans':
            m = re.search(r'sealed=(.+?) observed=', s.get('explanation', ''))
            if m: print(m.group(1))
            break
")
SEALED_ANS="${SEALED_ANS:-v=ans1; version=v1.0.0}"
snapshot "$ID" "before"
curl -fsS -X POST "$BASE/v1/internal/observations/import" \
  -H 'Content-Type: application/json' \
  -d "{\"observations\":[{\"agentId\":\"$ID\",\"signalId\":\"dnsrecord.ans\",\"observedAt\":\"$NOW_PLUS_1H\",\"value\":{\"expected\":\"$SEALED_ANS\",\"observed\":\"v=ans1; version=v9.9.9\",\"matched\":false,\"expectedSource\":\"tl_attestation\",\"observedSource\":\"fixture\"}}]}" >/dev/null
echo "  POSTed a mismatched _ans verdict; re-fetching detail…"
snapshot "$ID" "after"
echo "  Note: same caveat as Stop 5 — if the prober's live DNS query already showed"
echo "        drift, INTEGRITY_DNS_ANS_DRIFT was already in [risks: …] before we POSTed."
echo "        The synthesized verdict here just makes the drift observable-value visible."
get "$RO/$ID" | py '
te=d["trustEvaluation"];
[print("   ", s["signalId"], "→", s["explanation"]) for dim in te["dimensions"] for s in dim["signalScores"] if s["signalId"].startswith("dnsrecord")]'

# ── Stop 7: compare scoring profiles ──────────────────────────────────
stop 7 "Same agent, two profiles: default vs identity-strict"
for p in default identity-strict; do
  get "$RO/$ID?profile=$p" | py "
te=d['trustEvaluation']; tv=te['trustVector'];
vec=' '.join('{}={}'.format(k, tv[k]) for k in ('integrity','identity','solvency','behavior','safety'));
print('  {:16} trustVector=({}) recommendedProfile={}'.format('$p', vec, te['recommendedProfile']))"
done

# ── Stop 8: summary table ─────────────────────────────────────────────
stop 8 "Summary — real observations (one row per agent)"
printf '  %-36s %-11s %4s %4s  %-14s %s\n' agentId status int idn recommended risks
ids=$(get "$RO?pageSize=100" | py '[print(a["agentId"]) for a in d["items"]]')
for id in $ids; do
  get "$RO/$id" | py "
te=d['trustEvaluation']; tv=te['trustVector'];
print('  {:<36} {:<11} {:>4} {:>4}  {:<14} {}'.format(
  d['agentId'], d['status'], tv['integrity'], tv['identity'],
  te['recommendedProfile'], len(te['riskFactors'])))"
done

# ── Stop 9: synthesized observations → different profiles ─────────────
stop 9 "Synthesized observations: driving agents to different profiles"
cat <<'EOS'
  The STOP 8 scores above are real — whatever the capture + live probing produced
  (freshly-registered agents tend to sit at UNTRUSTED; live prod agents vary). To show
  the full recommendedProfile cascade regardless, we now overlay *synthesized* observation
  sets (clearly NOT real signals) to drive up to four ACTIVE agents to distinct tiers:
  UNTRUSTED / READ_ONLY / TRANSACTIONAL / FIDUCIARY. FIDUCIARY needs every non-age
  integrity signal matched plus certtype=EV — agentage is derived from real elapsed time,
  so it can't be synthesized (it only helps, never hurts).
EOS

# Stamp newer than earlier synthesized obs (stops 4-6 used +1h) so these win.
TS2=$(python3 -c 'import datetime;print((datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ"))')
DUMMY_FP="SHA256:$(python3 -c "print('a'*64)")"

postobs() { # $1=agentId $2=signalId $3=value-json
  curl -fsS -X POST "$BASE/v1/internal/observations/import" -H 'Content-Type: application/json' \
    -d "{\"observations\":[{\"agentId\":\"$1\",\"signalId\":\"$2\",\"observedAt\":\"$TS2\",\"value\":$3}]}" >/dev/null
}

apply_tier() { # $1=agentId $2=target
  case "$2" in
    UNTRUSTED)
      postobs "$1" certtype '{"type":"none"}' ;;
    READ_ONLY)
      postobs "$1" certtype '{"type":"DV"}'
      postobs "$1" dnssecurity '{"dnssec":true,"caa":true}'
      postobs "$1" versionstability '{"versionChanges30d":0}' ;;
    TRANSACTIONAL)
      postobs "$1" certtype '{"type":"OV"}'
      postobs "$1" dnssecurity '{"dnssec":true,"caa":true}'
      postobs "$1" versionstability '{"versionChanges30d":0}'
      postobs "$1" dnsrecord.ans '{"expected":"a","observed":"a","matched":true}'
      postobs "$1" dnsrecord.ans-badge '{"expected":"a","observed":"a","matched":true}' ;;
    FIDUCIARY)
      postobs "$1" certtype '{"type":"EV"}'
      postobs "$1" dnssecurity '{"dnssec":true,"caa":true}'
      postobs "$1" versionstability '{"versionChanges30d":0}'
      postobs "$1" dnsrecord.ans '{"expected":"a","observed":"a","matched":true}'
      postobs "$1" dnsrecord.ans-badge '{"expected":"a","observed":"a","matched":true}'
      postobs "$1" certfingerprint.server "{\"expected\":\"$DUMMY_FP\",\"observed\":\"$DUMMY_FP\",\"matched\":true}"
      postobs "$1" certfingerprint.identity "{\"expected\":\"$DUMMY_FP\",\"observed\":\"$DUMMY_FP\",\"matched\":true}" ;;
  esac
}

TARGETS="UNTRUSTED READ_ONLY TRANSACTIONAL FIDUCIARY"
# Collect up to 4 ACTIVE agent ids (portable; bash 3.2 has no mapfile).
TIER_IDS=()
while IFS= read -r line; do [ -n "$line" ] && TIER_IDS+=("$line"); done < <(get "$RO?pageSize=100&statuses=ACTIVE" | py '[print(a["agentId"]) for a in d["items"][:4]]')
N=${#TIER_IDS[@]}
[ "$N" -lt 4 ] && echo "  (only $N ACTIVE agent(s) — showing the first $N tier(s); register 4+ for the full demo)"

# Apply the i-th tier recipe to the i-th agent.
i=0
for tgt in $TARGETS; do
  [ "$i" -ge "$N" ] && break
  apply_tier "${TIER_IDS[$i]}" "$tgt"
  i=$((i + 1))
done

# Focused table: target vs achieved (✓ when they match).
echo
printf '  %-36s %-14s %4s %4s  %-14s %s\n' agentId target int idn recommended ok
i=0
for tgt in $TARGETS; do
  [ "$i" -ge "$N" ] && break
  get "$RO/${TIER_IDS[$i]}" | py "
te=d['trustEvaluation']; tv=te['trustVector']; got=te['recommendedProfile']
ok='✓' if got=='$tgt' else '✗'
print('  {:<36} {:<14} {:>4} {:>4}  {:<14} {}'.format(d['agentId'], '$tgt', tv['integrity'], tv['identity'], got, ok))"
  i=$((i + 1))
done

hr
CAPTURED=$(get "$RO?pageSize=100&totalRequired=true" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("totalItems",""))')
echo "  Walkthrough complete."
echo "  Captured ${CAPTURED:-?} agents from prod → probed live DNS/TLS → scored via the same engine as make demo."
echo "  Snapshot fixtures: fixtures/snapshot/tl-events/ · server logs: ${SERVER_LOG:-/tmp/agent-trust-discovery-live-demo.log}"
