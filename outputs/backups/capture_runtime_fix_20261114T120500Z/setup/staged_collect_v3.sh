#!/usr/bin/env bash
# Stage V3: explicit Docker-owned capture lifecycle, packet preflight and live progress.
# Never modifies old captures or round bundles. Unlike V2, no Compose capture overlay.
set -Eeuo pipefail
cd "$(dirname "$0")/.."

usage() { cat <<'HELP'
Usage: ./setup/staged_collect_v3.sh --run-id ID --rounds N --test-rounds N --seed N [--capture|--no-capture] [--resume]
Collects only harmless staged HTTP workloads in the isolated Docker lab.
Progress is printed AND written to collector_v3_*.log; no silent long waits.
A completed application-only run with a header-only PCAP cannot be promoted into a packet-captured run.
HELP
}
RUN_ID="staged_v3_$(date -u +%Y%m%dT%H%M%SZ)_$$"
ROUNDS=12; TEST_ROUNDS=12; SEED=20261114; CAPTURE=1; RESUME=0
while (( $# )); do
  case "$1" in
    --run-id) (( $# >= 2 )) || { usage >&2; exit 2; }; RUN_ID="$2"; shift 2;;
    --rounds) (( $# >= 2 )) || { usage >&2; exit 2; }; ROUNDS="$2"; shift 2;;
    --test-rounds) (( $# >= 2 )) || { usage >&2; exit 2; }; TEST_ROUNDS="$2"; shift 2;;
    --seed) (( $# >= 2 )) || { usage >&2; exit 2; }; SEED="$2"; shift 2;;
    --capture) CAPTURE=1; shift;;
    --no-capture) CAPTURE=0; shift;;
    --resume) RESUME=1; shift;;
    --help|-h) usage; exit 0;;
    *) printf 'Unknown argument: %s\n' "$1" >&2; usage >&2; exit 2;;
  esac
done
[[ "$RUN_ID" =~ ^[A-Za-z0-9_-]{1,80}$ && "$ROUNDS" =~ ^[0-9]+$ && "$TEST_ROUNDS" =~ ^[0-9]+$ && "$SEED" =~ ^[0-9]+$ ]] || { echo 'Invalid run ID/arguments' >&2; exit 2; }
(( ROUNDS>=3 && ROUNDS<=150 && TEST_ROUNDS>=3 && TEST_ROUNDS<=150 )) || { echo 'Rounds must be 3..150' >&2; exit 2; }
for cmd in flock timeout docker python3; do command -v "$cmd" >/dev/null || { echo "Missing command: $cmd" >&2; exit 1; }; done
mkdir -p outputs/locks
exec 9>outputs/locks/staged_capture.lock
if ! flock -n 9; then
  echo 'Another staged collector holds outputs/locks/staged_capture.lock.' >&2
  echo 'Check jobs -l; ps -eo pid,ppid,stat,args | grep -E "[s]taged_collect|[d]ocker compose|[t]cpdump"' >&2
  echo 'Do not delete the lock file while a suspended process holds its descriptor.' >&2
  exit 1
fi
docker info >/dev/null || { echo 'Docker unavailable to this shell. Re-login to activate group membership.' >&2; exit 1; }
COMPOSE=(docker compose -f compose.yaml)
RAW="src/data/raw/runs/$RUN_ID"
PY=python3
if [[ -x .venv-cuda/bin/python ]]; then PY="$PWD/.venv-cuda/bin/python"; elif [[ -x .venv/bin/python ]]; then PY="$PWD/.venv/bin/python"; fi

if (( RESUME )); then
  [[ -s "$RAW/scenario_config.json" ]] || { echo "Cannot resume: $RAW/scenario_config.json not found" >&2; exit 1; }
else
  [[ ! -e "$RAW" ]] || { echo "Existing run directory: $RAW; use --resume or another ID" >&2; exit 1; }
  "$PY" -m lab.staged_generate --output "$RAW" --rounds "$ROUNDS" --test-rounds "$TEST_ROUNDS" --seed "$SEED" --init-only
fi
"$PY" - "$RAW/scenario_config.json" "$ROUNDS" "$TEST_ROUNDS" "$SEED" <<'PY_CONFIG'
import json,sys
c=json.load(open(sys.argv[1],encoding='utf-8'))
want=('staged_v2_1', *(int(x) for x in sys.argv[2:]))
actual=(c['schema'],c['rounds'],c['test_rounds'],c['seed'])
if actual != want:
    raise SystemExit(f'STOP: run settings differ: saved {actual}, requested {want}')
PY_CONFIG
STAMP="$(date -u +%Y%m%dT%H%M%SZ)_$$"
LOG="$RAW/collector_v3_${STAMP}.log"
: > "$LOG"
log() { printf '[%s] [STAGE-V3] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" | tee -a "$LOG"; }
step() { "$@" 2>&1 | tee -a "$LOG"; return "${PIPESTATUS[0]}"; }
status() {
  local state="$1"; STATUS_STATE="$state"; local tmp="$RAW/.collector_status_v3.json.pending.$$"
  printf '{"schema":"stage_v3_collector","run_id":"%s","status":"%s","updated_utc":"%s","log":"%s"}\n' \
      "$RUN_ID" "$state" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$LOG" > "$tmp"
  mv -f "$tmp" "$RAW/collector_status_v3.json"
}
CAP_NAME=""; CAP_STARTED=0; CAP_FILE=""; STOP_OK=1
capture_stop() {
  (( CAP_STARTED )) || return 0
  log "Stopping only our capture container: $CAP_NAME (bounded Docker timeout)"
  if [[ "$(timeout 5s docker inspect -f '{{.State.Running}}' "$CAP_NAME" 2>/dev/null || true)" == true ]]; then
    if ! step timeout 16s docker stop --signal SIGINT --timeout 8 "$CAP_NAME"; then
      log "WARNING: graceful Docker stop failed; attempting short bounded stop"
      step timeout 8s docker stop -t 3 "$CAP_NAME" || true
    fi
  fi
  local running
  running="$(timeout 5s docker inspect -f '{{.State.Running}}' "$CAP_NAME" 2>/dev/null || true)"
  if [[ "$running" == true ]]; then
    STOP_OK=0
    log "ERROR: capture is still running: $CAP_NAME. DO NOT analyse active PCAP."
    return 1
  fi
  timeout 8s docker logs "$CAP_NAME" > "$RAW/capture_container_${STAMP}.log" 2>&1 || true
  log "Capture log saved to $RAW/capture_container_${STAMP}.log"
  CAP_STARTED=0
  # Container is removed only after its log is saved; data files remain intact.
  step timeout 8s docker rm "$CAP_NAME" || log 'WARNING: stopped capture container remains; manually inspect it later'
  log 'Capture process confirmed stopped'
}
on_exit() {
  local rc="$1"
  trap - EXIT
  if (( CAP_STARTED )); then capture_stop || rc=1; fi
  if (( rc != 0 )); then
    case "${STATUS_STATE:-}" in
      CAPTURE_PREFLIGHT_FAILED|CAPTURE_TOO_SPARSE|APPLICATION_ONLY_INVALID_CAPTURE|COLLECTOR_INTERRUPTED) ;;
      *) status 'FAILED_OR_INTERRUPTED';;
    esac
    log "EXIT $rc: run journal and captures preserved; rerun with --resume if incomplete"
  fi
  exit "$rc"
}
trap 'on_exit $?' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'log "SIGTSTP received: use Ctrl+C, not Ctrl+Z, to interrupt collectors safely"' TSTP

log "Starting run=$RUN_ID rounds=$ROUNDS test_rounds=$TEST_ROUNDS seed=$SEED capture=$CAPTURE resume=$RESUME"
status 'STARTING'

# A committed run cannot be packet-replayed from the same events. Preserve it, recover
# gateway events if possible, and explicitly reject header-only PCAPs.
if [[ -s "$RAW/complete.json" ]]; then
  log 'All episodes already committed; do not regenerate them.'
  if [[ ! -s "$RAW/gateway_subset.jsonl" ]]; then
    log 'Extracting existing gateway events without modifying raw log'
    step "$PY" -m setup.university_extract_events --manifest "$RAW/episodes.jsonl" --gateway src/data/raw/gateway_requests.jsonl --out "$RAW/gateway_subset.jsonl"
  fi
  if (( CAPTURE )); then
    found_valid=0
    while IFS= read -r p; do
      if "$PY" -m setup.staged_capture_audit --pcap "$p" --min-packets 4 --quiet >> "$LOG" 2>&1; then
        log "Existing captured packets found: $p"; found_valid=1
      else
        log "Invalid or empty existing capture: $p"
      fi
    done < <(find "$RAW" -maxdepth 1 -type f -name 'traffic_*.pcap' -print)
    if (( !found_valid )); then
      status 'APPLICATION_ONLY_INVALID_CAPTURE'
      log 'STOP: cannot recreate missing PCAP from committed traffic. Use a NEW run ID for network capture.'
      exit 4
    fi
  fi
  status 'EXISTING_COMPLETE'
  log "Existing dataset preserved: $RAW/gateway_subset.jsonl"
  exit 0
fi

log 'Checking Compose service configuration without the broken V2 capture overlay'
step "${COMPOSE[@]}" config --quiet
log 'Starting authorised isolated lab services'
step "${COMPOSE[@]}" up -d server_a server_b gateway
for network in phase3-adaptive-nids_clients phase3-adaptive-nids_services; do
  [[ "$(docker network inspect -f '{{.Internal}}' "$network")" == true ]] || { log "ERROR: $network is not internal"; exit 1; }
done
log 'Both Compose network segments confirmed internal'

SVC_NETWORK_ID="$(docker network inspect -f '{{.Id}}' phase3-adaptive-nids_services)"
SVC_BRIDGE="br-${SVC_NETWORK_ID:0:12}"
OLD_HOST_CAPTURE="$(pgrep -a -x tcpdump 2>/dev/null | grep -F -- "-i $SVC_BRIDGE" || true)"
[[ -z "$OLD_HOST_CAPTURE" ]] || { log "STOP: orphan host tcpdump still active: $OLD_HOST_CAPTURE"; exit 1; }
if [[ -n "$(docker ps -q --filter 'name=phase3-adaptive-nids-capture' --filter 'status=running')" ]]; then
  log 'STOP: old Compose capture service still running; inspect and stop it by exact name first.'; exit 1
fi
if [[ -n "$(docker ps -q --filter 'label=phase3.staged.capture=1' --filter 'status=running')" ]]; then
  log 'STOP: another V3 capture already running; inspect before retrying.'; exit 1
fi
READY=0
for attempt in $(seq 1 30); do
  if "${COMPOSE[@]}" exec -T gateway python -c 'import socket; [socket.create_connection((h,8080),timeout=2).close() for h in ("127.0.0.1","server_a","server_b")]' >/dev/null 2>&1; then READY=1; break; fi
  if (( attempt % 5 == 0 )); then log "Readiness check $attempt/30: waiting for gateway and both backends"; fi
  sleep 1
done
(( READY )) || { log 'Gateway and backend readiness failed'; exit 1; }
log 'Gateway and backends ready'

if (( CAPTURE )); then
  IMAGE='phase3-adaptive-nids-capture:latest'
  if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    log 'Building restricted tcpdump image from existing local Dockerfile'
    step docker build -f lab/Dockerfile.capture -t "$IMAGE" .
  fi
  CAP_NAME="p3cap_${RUN_ID}_${STAMP}"
  CAP_FILE="traffic_${STAMP}.pcap"
  GATEWAY_CID="$("${COMPOSE[@]}" ps -q gateway)"
  [[ -n "$GATEWAY_CID" ]] || { log 'Gateway container ID missing'; exit 1; }
  ROOT_RAW="$(realpath "$RAW")"
  log "Starting capture in gateway network namespace; file: $ROOT_RAW/$CAP_FILE"
  # Direct docker run avoids Compose overlay interpolation and stuck Compose stop wrapper.
  step docker run -d --name "$CAP_NAME" --network "container:$GATEWAY_CID" \
     --cap-drop ALL --cap-add NET_RAW --security-opt no-new-privileges:true \
     --read-only --stop-signal SIGINT --stop-timeout 8 --pids-limit 32 \
     --label phase3.staged.capture=1 --label "phase3.staged.run=$RUN_ID" \
     --mount "type=bind,src=$ROOT_RAW,dst=/captures" \
     "$IMAGE" -Z root -i any -p -nn -s 0 -U -w "/captures/$CAP_FILE" 'tcp port 8080'
  CAP_STARTED=1
  sleep 2
  [[ "$(docker inspect -f '{{.State.Running}}' "$CAP_NAME" 2>/dev/null)" == true ]] || {
     log 'ERROR: capture process exited immediately; showing its Docker log'
     step docker logs "$CAP_NAME" || true
     exit 1
  }
  log 'Capture process running; executing 4 genuine HTTP probe requests BEFORE experiment'
  PROBE='import urllib.request; services=["a","b","a","b"]; statuses=[urllib.request.urlopen(urllib.request.Request("http://gateway:8080/"+svc,data=b"capture_check"*8,headers={"X-Lab-Episode":"v3_capture_probe_not_an_experiment"},method="POST"),timeout=5).status for svc in services]; assert statuses==[200]*4; print("CAPTURE_PROBE_HTTP_OK",len(statuses),flush=True)'
  step timeout 45s "${COMPOSE[@]}" --profile runner run --rm -T --no-deps runner python -c "$PROBE"
  captured=0
  for attempt in $(seq 1 8); do
    if "$PY" -m setup.staged_capture_audit --pcap "$RAW/$CAP_FILE" --min-packets 4 --quiet >> "$LOG" 2>&1; then
      captured=1; break
    fi
    log "Capture probe verification $attempt/8: packets not yet flushed; waiting"
    sleep 1
  done
  if (( !captured )); then
    log 'ERROR: capture recorded no usable packets; refusing collection. Docker logs:'
    step docker logs "$CAP_NAME" || true
    status 'CAPTURE_PREFLIGHT_FAILED'
    exit 5
  fi
  log 'Capture preflight passed: actual packet records observed'
else
  log 'WARNING: --no-capture mode requested; this run is application-only and cannot support Zeek network conclusions'
fi

status 'COLLECTING'
RUNLOG="$RAW/generator_${STAMP}.log"
log "Launching runner; full per-round output: $RUNLOG"
CMD=(python -m lab.staged_generate --output "/out/runs/$RUN_ID" --gateway http://gateway:8080 --rounds "$ROUNDS" --test-rounds "$TEST_ROUNDS" --seed "$SEED" --resume)
timeout -s INT -k 10s 1800s "${COMPOSE[@]}" --profile runner run --rm -T --no-deps runner "${CMD[@]}" > "$RUNLOG" 2>&1 &
RUNNER_PID=$!
while kill -0 "$RUNNER_PID" 2>/dev/null; do
  sleep 5
  completed="$(find "$RAW/rounds" -maxdepth 1 -type f -name '*.json' 2>/dev/null | wc -l || true)"
  last="$(tail -n 1 "$RUNLOG" 2>/dev/null || true)"
  log "HEARTBEAT runner PID=$RUNNER_PID completed_rounds=$completed/$((3*ROUNDS+TEST_ROUNDS)); last_output=${last:-waiting for first result}"
done
set +e
wait "$RUNNER_PID"
RUNNER_RC=$?
set -e
log "Runner exit code: $RUNNER_RC; last 15 lines of generator log:"
tail -n 15 "$RUNLOG" | tee -a "$LOG"
if (( RUNNER_RC != 0 )); then
  status 'COLLECTOR_INTERRUPTED'
  log "Runner failed; preserving completed round journals. Same config with --resume restarts safely."
  exit "$RUNNER_RC"
fi
[[ -s "$RAW/complete.json" ]] || { log 'Runner exited but complete.json missing'; exit 1; }
log 'All round records committed. Closing packet capture before extraction.'
if (( CAPTURE )); then capture_stop; fi

status 'POSTPROCESSING'
if [[ ! -s "$RAW/gateway_subset.jsonl" ]]; then
  log 'Extracting ground-truth-aligned gateway observations'
  step "$PY" -m setup.university_extract_events --manifest "$RAW/episodes.jsonl" --gateway src/data/raw/gateway_requests.jsonl --out "$RAW/gateway_subset.jsonl"
fi
if (( CAPTURE )); then
  log 'Validating closed PCAP structure and nonzero observed packet count'
  episode_count="$(wc -l < "$RAW/episodes.jsonl")"
  MIN_PACKETS=$((episode_count * 4))
  AUDIT="$RAW/capture_audit_${STAMP}.json"
  if ! step "$PY" -m setup.staged_capture_audit --pcap "$RAW/$CAP_FILE" --min-packets "$MIN_PACKETS" --output "$AUDIT"; then
    status 'CAPTURE_TOO_SPARSE'
    log "STOP: insufficient packet coverage (expected >=$MIN_PACKETS packet records). Preserve run but do not train on this capture."
    exit 6
  fi
  log "Packet audit written: $AUDIT (independent Zeek alignment still required)"
fi
status 'COLLECTION_COMPLETE'
log "SUCCESS: $RUN_ID; manifest=$RAW/episodes.jsonl, gateway=$RAW/gateway_subset.jsonl, packet=$RAW/$CAP_FILE"
log 'Reminder: benign laboratory behavioural profiles, NOT evidence of genuine network intrusion.'
