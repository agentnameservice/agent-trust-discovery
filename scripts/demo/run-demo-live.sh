#!/usr/bin/env bash
# run-demo-live.sh — live variant of run-demo.sh (plan §4). Captures a
# fixture snapshot from prod (Search API + Transparency Log), then runs the
# unchanged hydrator/prober pipeline against those fixtures. The prober still
# performs real outbound DNS/TLS probes against the captured hosts.
#
# The mock-demo path (`make demo`, run-demo.sh) is intentionally untouched.
set -euo pipefail

PORT="${PORT:-8080}"
BIN="${BIN:-./bin}"
DB=/tmp/agent-trust-discovery-live-demo.db
SERVER_LOG=/tmp/agent-trust-discovery-live-demo.log
OUT="${OUT:-fixtures/snapshot}"
LIMIT="${LIMIT:-5}"
QUERY="${QUERY:-}"

rm -f "$DB"

echo "▶ capturing snapshot (limit=$LIMIT${QUERY:+, query=\"$QUERY\"})..."
SNAPSHOT_ARGS=(--out "$OUT" --limit "$LIMIT")
if [ -n "$QUERY" ]; then
	SNAPSHOT_ARGS+=(--query "$QUERY")
fi
"$BIN/agent-snapshot" "${SNAPSHOT_ARGS[@]}"

echo "▶ booting agent-trust-discovery on :$PORT (config/demo-live.runtime.yaml, no auth)…"
echo "  (server logs -> $SERVER_LOG)"
"$BIN/agent-trust-discovery" -config config/demo-live.runtime.yaml >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!

cleanup() {
	kill "$SERVER_PID" 2>/dev/null || true
	wait "$SERVER_PID" 2>/dev/null || true
}
trap cleanup EXIT

# Wait for liveness (up to ~5s).
ready=""
for _ in $(seq 1 50); do
	if curl -fsS "http://localhost:$PORT/health" >/dev/null 2>&1; then
		ready=1
		break
	fi
	sleep 0.1
done
if [ -z "$ready" ]; then
	echo "✗ agent-trust-discovery did not become ready on :$PORT" >&2
	exit 1
fi

echo "▶ running agent-hydrator-stub (real mode) against agent-trust-discovery…"
echo "  (real mode: observations come from the prober step, not the hydrator — expect observationsImported:0)"
"$BIN/agent-hydrator-stub" -config config/hydrator.snapshot.yaml

echo "▶ running agent-prober (live DNS/TLS) against the captured hosts…"
"$BIN/agent-prober" -config config/prober.snapshot.yaml

echo "▶ running the live walkthrough…"
BASE="http://localhost:$PORT" bash scripts/demo/walkthrough-live.sh
