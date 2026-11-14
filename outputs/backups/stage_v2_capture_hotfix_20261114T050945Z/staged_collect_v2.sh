#!/usr/bin/env bash
# Staged-v2 traffic collection with Docker-sidecar packet capture (no sudo-child hang).
# Non-destructive: new run ID or explicit resumable round journals only.
set -euo pipefail
cd "$(dirname "$0")/.."

usage() { cat <<'HELP'
Usage: ./setup/staged_collect_v2.sh [--run-id ID] [--rounds 12] [--test-rounds 12]
       [--seed 20261114] [--capture|--no-capture] [--resume]
The authorised lab sends harmless HTTP requests to private Compose services.
Creates exactly one collection at a time. Existing run IDs require --resume.
HELP
}
RUN_ID="staged_$(date -u +%Y%m%dT%H%M%SZ)_$$"
ROUNDS=12; TEST_ROUNDS=12; SEED=20261114; CAPTURE=1; RESUME=0
while (( $# )); do
  case "$1" in
   --run-id) RUN_ID="$2";shift 2;;
   --rounds) ROUNDS="$2";shift 2;;
   --test-rounds) TEST_ROUNDS="$2";shift 2;;
   --seed) SEED="$2";shift 2;;
   --capture) CAPTURE=1;shift;;
   --no-capture) CAPTURE=0;shift;;
   --resume) RESUME=1;shift;;
   -h|--help) usage;exit 0;;
   *) echo "Unknown argument: $1" >&2;usage >&2;exit 2;;
  esac
done
[[ "$RUN_ID" =~ ^[A-Za-z0-9_-]+$ && "$ROUNDS" =~ ^[0-9]+$ && "$TEST_ROUNDS" =~ ^[0-9]+$ && "$SEED" =~ ^[0-9]+$ ]] || { echo 'Invalid options' >&2;exit 2; }
(( ROUNDS>=3 && ROUNDS<=150 && TEST_ROUNDS>=3 && TEST_ROUNDS<=150 )) || { echo 'Rounds must be 3..150' >&2;exit 2; }
command -v flock >/dev/null || { echo 'flock missing' >&2;exit 1; }
mkdir -p outputs/locks
exec 9>outputs/locks/staged_capture.lock
flock -n 9 || { echo 'Another staged collection is active; refusing concurrent capture' >&2;exit 1; }
docker info >/dev/null || { echo 'Docker daemon unavailable in this shell. Verify docker ps and user group membership.' >&2;exit 1; }
export STAGED_RUN_ID="$RUN_ID"
COMPOSE=(docker compose -f compose.yaml -f compose.staged.capture.yaml --profile capture)
RAW="src/data/raw/runs/$RUN_ID"
PY=python3
if [[ -x .venv-cuda/bin/python ]]; then PY="$PWD/.venv-cuda/bin/python";elif [[ -x .venv/bin/python ]];then PY="$PWD/.venv/bin/python";fi
if (( RESUME )); then
  [[ -s "$RAW/scenario_config.json" ]] || { echo "Cannot resume unknown run $RUN_ID" >&2;exit 1; }
else
  [[ ! -e "$RAW" ]] || { echo "Existing run directory $RAW; use --resume or different ID" >&2;exit 1; }
  "$PY" -m lab.staged_generate --output "$RAW" --rounds "$ROUNDS" --test-rounds "$TEST_ROUNDS" --seed "$SEED" --init-only
fi
# Always check exact config before touching Docker network; --resume replays finished rounds safely.
"$PY" - "$ROUNDS" "$TEST_ROUNDS" "$SEED" <<'PY_CHECK'
import json,os,sys
from pathlib import Path
p=Path('src/data/raw/runs')/os.environ['STAGED_RUN_ID']/'scenario_config.json'
c=json.loads(p.read_text())
if (c['schema'],c['rounds'],c['test_rounds'],c['seed'])!=('staged_v2_1',*map(int,sys.argv[1:])):
    raise SystemExit('Mismatched run configuration: use the original --rounds/--test-rounds/--seed values.')
PY_CHECK
if [[ -s "$RAW/complete.json" ]];then
  if [[ ! -s "$RAW/gateway_subset.jsonl" ]];then
     "$PY" -m setup.university_extract_events --manifest "$RAW/episodes.jsonl" --gateway src/data/raw/gateway_requests.jsonl --out "$RAW/gateway_subset.jsonl"
  fi
  echo "Already completed: $RUN_ID; preserving original data."
  exit 0
fi
# Check for OLD and sidecar captures; never overlap with root-owned orphan tcpdump.
docker compose -f compose.yaml -f compose.staged.capture.yaml config --quiet
"${COMPOSE[@]}" up -d server_a server_b gateway
for network in phase3-adaptive-nids_clients phase3-adaptive-nids_services;do
  [[ "$(docker network inspect -f '{{.Internal}}' "$network")" == true ]] || { echo "$network is not internal" >&2;exit 1; }
done
# Fail closed on lingering old host-bridge tcpdump captures seen in earlier logs.
SVC_NETWORK_ID="$(docker network inspect -f '{{.Id}}' phase3-adaptive-nids_services)"
SVC_BRIDGE="br-${SVC_NETWORK_ID:0:12}"
OLD_HOST_CAPTURE="$(pgrep -a -x tcpdump 2>/dev/null | grep -F -- "-i $SVC_BRIDGE" || true)"
if [[ -n "$OLD_HOST_CAPTURE" ]];then
  echo "STOP: older tcpdump processes still capture the lab bridge $SVC_BRIDGE:" >&2
  echo "$OLD_HOST_CAPTURE" >&2
  echo 'From an approved Ubuntu terminal, inspect exact PID/path and stop ONLY those specific processes with sudo kill -INT PID.' >&2
  exit 1
fi
# Do not replace an old, still-running sidecar capture in the gateway namespace.
EXISTING_CAP="$("${COMPOSE[@]}" ps -q capture 2>/dev/null || true)"
if [[ -n "$EXISTING_CAP" && "$(docker inspect -f '{{.State.Running}}' "$EXISTING_CAP")" == true ]];then
  echo "STOP: an older capture sidecar remains active ($EXISTING_CAP). Inspect it before stopping or starting another." >&2
  exit 1
fi
# Wait for healthy gateway and both backends (no labels emitted here).
READY=0
for _ in $(seq 1 30);do
  if docker compose exec -T gateway python -c 'import socket; [socket.create_connection((h,8080),timeout=2).close() for h in ("127.0.0.1","server_a","server_b")]' >/dev/null 2>&1;then READY=1;break;fi
  sleep 1
done
((READY)) || { echo 'Gateway/backend connection check failed' >&2;exit 1; }
STAGED_CAPTURE_NAME="traffic_$(date -u +%Y%m%dT%H%M%SZ)_$$"
export STAGED_CAPTURE_NAME
CAP_STARTED=0
stop_capture() {
 if (( CAP_STARTED ));then
  echo 'Closing capture sidecar via Docker SIGINT (bounded wait)...'
  timeout 24s "${COMPOSE[@]}" stop -t 8 capture || { echo 'Capture stop failed: verify container state; do not analyse an open PCAP' >&2;return 1; }
  local cid
  cid="$("${COMPOSE[@]}" ps -aq capture | head -1)"
  if [[ -n "$cid" && "$(docker inspect -f '{{.State.Running}}' "$cid")" == true ]];then
    echo 'Capture still active: refusing PCAP analysis' >&2;return 1
  fi
  CAP_STARTED=0
 fi
}
finish() { local code=$?;trap - EXIT;stop_capture || code=1;if ((code));then echo "Interrupted run $RUN_ID: completed rounds are preserved. Repeat with --resume; incomplete episodes are excluded." >&2;fi;exit "$code"; }
trap finish EXIT
if (( CAPTURE ));then
  # Build once; the previously pulled python:3.12-slim base is reused.
  # No host NET_ADMIN/root-owned tcpdump processes are created.
  "${COMPOSE[@]}" build capture
  "${COMPOSE[@]}" up -d --no-deps --force-recreate capture
  CAP_STARTED=1
  CID="$("${COMPOSE[@]}" ps -q capture)"
  [[ -n "$CID" && "$(docker inspect -f '{{.State.Running}}' "$CID")" == true ]] || { echo 'Sidecar did not start' >&2;exit 1; }
  sleep 1
  echo "Capture: $RAW/$STAGED_CAPTURE_NAME.pcap"
fi
CMD=(python -m lab.staged_generate --output "/out/runs/$RUN_ID" --gateway http://gateway:8080 --rounds "$ROUNDS" --test-rounds "$TEST_ROUNDS" --seed "$SEED" --resume)
# The generator writes an atomic per-round journal on the host bind mount.
set +e
timeout -s INT -k 10s 1800s docker compose --profile runner run --rm -T runner "${CMD[@]}" 2>&1 | tee "$RAW/generator_${STAGED_CAPTURE_NAME}.log"
EXIT_CODE=${PIPESTATUS[0]}
set -e
stop_capture
(( EXIT_CODE == 0 )) || { echo "Runner exited $EXIT_CODE: preserve run and resume" >&2;exit "$EXIT_CODE"; }
[[ -s "$RAW/complete.json" ]] || { echo 'Runner returned but complete marker missing' >&2;exit 1; }
"$PY" -m setup.university_extract_events --manifest "$RAW/episodes.jsonl" --gateway src/data/raw/gateway_requests.jsonl --out "$RAW/gateway_subset.jsonl"
if (( CAPTURE ));then
  PCAP="$RAW/$STAGED_CAPTURE_NAME.pcap"
  [[ -s "$PCAP" ]] || { echo 'PCAP missing or empty' >&2;exit 1; }
  tcpdump -r "$PCAP" -c 1 >/dev/null 2>&1 || { echo 'PCAP unreadable' >&2;exit 1; }
  echo "PCAP verified structurally: $PCAP"
fi
printf '\nSTAGED_COLLECTION_COMPLETE: %s\n' "$RUN_ID"
printf 'Ground truth: %s/episodes.jsonl\nReal observed gateway events: %s/gateway_subset.jsonl\n' "$RAW" "$RAW"
printf 'This remains harmless lab traffic, not real malicious network intrusion evidence.\n'
