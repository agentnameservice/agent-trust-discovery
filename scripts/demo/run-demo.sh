#!/usr/bin/env bash
# run-demo.sh — boot agent-trust-discovery (no auth), hydrate it with the fixtures via
# agent-hydrator-stub, run the walkthrough, then tear down. Fully offline and
# deterministic (design §8). Invoked by `make demo` after the binaries build.
set -euo pipefail

PORT="${PORT:-8080}"
BIN="${BIN:-./bin}"
DB=/tmp/agent-trust-discovery-demo.db
SERVER_LOG=/tmp/agent-trust-discovery-demo.log

rm -f "$DB"

echo "▶ booting agent-trust-discovery on :$PORT (config/demo.runtime.yaml, no auth)…"
echo "  (server logs -> $SERVER_LOG)"
"$BIN/agent-trust-discovery" -config config/demo.runtime.yaml >"$SERVER_LOG" 2>&1 &
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

echo "▶ running agent-hydrator-stub (mock) against agent-trust-discovery…"
"$BIN/agent-hydrator-stub" -config config/hydrator.yaml

echo "▶ running the walkthrough…"
BASE="http://localhost:$PORT" bash scripts/demo/walkthrough.sh
