#!/usr/bin/env bash
# Read-only monitor for a run: progress, logs, capture integrity, Docker state.
set -euo pipefail
cd "$(dirname "$0")/.."
if (( $# < 1 || $# > 2 )); then echo 'Usage: ./setup/staged_v3_status.sh RUN_ID [--follow]' >&2; exit 2; fi
RUN_ID="$1"
[[ "$RUN_ID" =~ ^[A-Za-z0-9_-]+$ ]] || { echo 'Invalid run ID' >&2; exit 2; }
ROOT="src/data/raw/runs/$RUN_ID"
[[ -d "$ROOT" ]] || { echo "Run directory not found: $ROOT" >&2; exit 1; }
printf '\n===== STAGE V3 STATUS: %s =====\n' "$RUN_ID"
if [[ -f "$ROOT/collector_status_v3.json" ]]; then cat "$ROOT/collector_status_v3.json"; else echo 'No V3 status file (older V2 run or not launched).'; fi
printf '\nCompleted rounds: '
find "$ROOT/rounds" -maxdepth 1 -type f -name '*.json' 2>/dev/null | wc -l || true
printf 'Committed episodes: '
[[ -f "$ROOT/episodes.jsonl" ]] && wc -l < "$ROOT/episodes.jsonl" || echo 0
printf 'Observed gateway events: '
[[ -f "$ROOT/gateway_subset.jsonl" ]] && wc -l < "$ROOT/gateway_subset.jsonl" || echo 0
printf 'Complete marker: '
[[ -s "$ROOT/complete.json" ]] && echo yes || echo no
printf '\nCaptured files:\n'
find "$ROOT" -maxdepth 1 -type f -name 'traffic_*.pcap' -printf '%f %s bytes\n' | sort || true
printf '\nCapture processes (this run only):\n'
docker ps --filter "label=phase3.staged.run=$RUN_ID" --format 'table {{.Names}}\t{{.Status}}' 2>/dev/null || true
printf '\nLatest collector log:\n'
latest="$(ls -t "$ROOT"/collector_v3_*.log 2>/dev/null | head -n 1 || true)"
if [[ -n "$latest" ]]; then
  echo "$latest"
  tail -n 16 "$latest"
else
  echo '(not yet created)'
fi
if [[ "${2:-}" == '--follow' ]]; then
  [[ -n "$latest" ]] || { echo 'No log to follow yet' >&2; exit 1; }
  exec tail -n 30 -f "$latest"
fi
