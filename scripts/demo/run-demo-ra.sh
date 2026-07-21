#!/usr/bin/env bash
# run-demo-ra.sh — ra-sync variant of run-demo-live.sh. Captures a fixture set
# from a (private) ANS RA event feed + Transparency Log via agent-ra-sync, then
# runs the unchanged hydrator/prober pipeline against those fixtures.
#
# Requires a reachable RA + TL. Override with RA_URL / TL_URL:
#   RA_URL=http://localhost:18080 TL_URL=http://localhost:18081 make demo-ra
set -euo pipefail

PORT="${PORT:-8080}"
BIN="${BIN:-./bin}"
DB=/tmp/agent-trust-discovery-live-demo.db
SERVER_LOG=/tmp/agent-trust-discovery-ra-demo.log
OUT="${OUT:-fixtures/ra-sync}"
RA_URL="${RA_URL:-http://localhost:18080}"
TL_URL="${TL_URL:-http://localhost:18081}"

# Free :$PORT if a previous demo server (e.g. the /tmp tier-demo server, which
# stays up by design) is still bound. Otherwise our fresh server can't bind,
# the readiness check below silently passes against the STALE server, and
# imported agents accumulate in it across runs instead of showing a clean set.
STALE_PIDS=$(lsof -ti "tcp:$PORT" -sTCP:LISTEN 2>/dev/null || true)
if [ -n "$STALE_PIDS" ]; then
	echo "▶ :$PORT already in use by pid(s) $STALE_PIDS — stopping them for a clean run…"
	# shellcheck disable=SC2086
	kill $STALE_PIDS 2>/dev/null || true
	for _ in $(seq 1 20); do
		[ -z "$(lsof -ti "tcp:$PORT" -sTCP:LISTEN 2>/dev/null || true)" ] && break
		sleep 0.1
	done
	if [ -n "$(lsof -ti "tcp:$PORT" -sTCP:LISTEN 2>/dev/null || true)" ]; then
		echo "✗ could not free :$PORT — stop the process manually and re-run." >&2
		exit 1
	fi
fi

rm -f "$DB"

echo "▶ capturing from RA feed $RA_URL (TL $TL_URL) via agent-ra-sync..."
"$BIN/agent-ra-sync" --ra-url "$RA_URL" --tl-url "$TL_URL" --out "$OUT"

echo "▶ booting agent-trust-discovery on :$PORT (config/demo-live.runtime.yaml, no auth)…"
echo "  (server logs -> $SERVER_LOG)"
"$BIN/agent-trust-discovery" -config config/demo-live.runtime.yaml >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!
cleanup() { kill "$SERVER_PID" 2>/dev/null || true; wait "$SERVER_PID" 2>/dev/null || true; }
trap cleanup EXIT

ready=""
for _ in $(seq 1 50); do
	if curl -fsS "http://localhost:$PORT/health" >/dev/null 2>&1; then ready=1; break; fi
	sleep 0.1
done
if [ -z "$ready" ]; then echo "✗ agent-trust-discovery did not become ready on :$PORT" >&2; exit 1; fi

echo "▶ running agent-hydrator-stub (real mode) against agent-trust-discovery…"
"$BIN/agent-hydrator-stub" -config config/hydrator.ra-sync.yaml

echo "▶ running agent-prober (live DNS/TLS) against the captured hosts…"
"$BIN/agent-prober" -config config/prober.ra-sync.yaml

echo "▶ running the live walkthrough…"
BASE="http://localhost:$PORT" bash scripts/demo/walkthrough-live.sh
