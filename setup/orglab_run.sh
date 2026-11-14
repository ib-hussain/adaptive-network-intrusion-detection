#!/usr/bin/env bash
# Additive ORGLAB collection; NEVER modifies the original Stage V3 run IDs.
set -Eeuo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
usage() {
  echo 'Usage: setup/orglab_run.sh --run-id org20_001 [--nodes 20] [--topology flat|departmental] [--rounds 6] [--test-rounds 6] [--seed 20261114] [--step-seconds 0.6] [--train]'
}
NODES=20 TOPOLOGY=flat ROUNDS=6 TEST_ROUNDS=6 SEED=20261114 STEP=0.6 RUN_ID='' TRAIN=0
while (($#)); do
  case "$1" in
    --run-id) RUN_ID="${2:?}"; shift 2;;
    --nodes) NODES="${2:?}"; shift 2;;
    --topology) TOPOLOGY="${2:?}"; shift 2;;
    --rounds) ROUNDS="${2:?}"; shift 2;;
    --test-rounds) TEST_ROUNDS="${2:?}"; shift 2;;
    --seed) SEED="${2:?}"; shift 2;;
    --step-seconds) STEP="${2:?}"; shift 2;;
    --train) TRAIN=1; shift;;
    --help|-h) usage; exit 0;;
    *) echo "Unknown argument: $1" >&2; usage; exit 2;;
  esac
done
[[ "$RUN_ID" =~ ^[A-Za-z][A-Za-z0-9_-]{1,40}$ ]] || { echo 'Invalid/missing --run-id' >&2; exit 2; }
[[ "$NODES" =~ ^[0-9]+$ ]] && ((NODES >= 20 && NODES <= 50)) || { echo 'nodes must be 20..50' >&2; exit 2; }
[[ "$TOPOLOGY" == flat || "$TOPOLOGY" == departmental ]] || { echo "topology must be flat or departmental" >&2; exit 2; }
[[ "$ROUNDS" =~ ^[0-9]+$ ]] && ((ROUNDS >= 4 && ROUNDS <= 100)) || { echo 'rounds must be 4..100' >&2; exit 2; }
[[ "$TEST_ROUNDS" =~ ^[0-9]+$ ]] && ((TEST_ROUNDS >= 1 && TEST_ROUNDS <= 100)) || { echo 'test-rounds must be 1..100' >&2; exit 2; }
command -v docker >/dev/null || { echo 'Docker not installed' >&2; exit 3; }
docker info >/dev/null || { echo 'Cannot contact Docker daemon' >&2; exit 3; }
command -v zeek >/dev/null || { echo 'Zeek required for network research gate' >&2; exit 3; }
[[ ! -e "outputs/orglab/$RUN_ID" ]] || { echo "Run directory already exists; preserve it: outputs/orglab/$RUN_ID" >&2; exit 3; }
# Only one timing-sensitive collection process on the host is acceptable.
if ps -eo args | grep -E '[s]etup/staged_collect_v[23]\.sh.*--capture' | grep -v '^grep' >/dev/null; then
  echo 'An existing staged collector may be running; inspect it first.' >&2; exit 3
fi
export ORG_RUN_ID="$RUN_ID" ORG_UID="$(id -u)" ORG_GID="$(id -g)" ORG_ROUNDS="$ROUNDS" ORG_TEST_ROUNDS="$TEST_ROUNDS" ORG_SEED="$SEED" ORG_STEP_SECONDS="$STEP"
PROJECT="nidsorg${RUN_ID//[^[:alnum:]]/}"
COMPOSE="compose.orglab.${NODES}.${TOPOLOGY}.json"
PYTHON="${VIRTUAL_ENV:+$VIRTUAL_ENV/bin/python}"
PYTHON="${PYTHON:-python3}"
"$PYTHON" -m orglab.composegen --nodes "$NODES" --topology "$TOPOLOGY" --output "$COMPOSE"
mkdir -p "outputs/orglab/$RUN_ID/captures"
LOG="outputs/orglab/$RUN_ID/launcher.log"
exec > >(tee -a "$LOG") 2>&1
log() { printf '[%s] [ORGLAB/%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$RUN_ID" "$*"; }
DC=(docker compose -p "$PROJECT" -f "$COMPOSE")
cleanup() {
  local rc=$?
  trap - EXIT
  log "EXIT=$rc Stopping only ORGLAB project containers; preserving datasets, PCAP and logs"
  "${DC[@]}" --profile capture stop --timeout 8 capture >/dev/null 2>&1 || true
  "${DC[@]}" --profile capture --profile experiment stop --timeout 8 >/dev/null 2>&1 || true
  if ((rc != 0)); then log "FAILED; inspect $LOG and run files; do not reuse this run ID"; fi
  exit "$rc"
}
trap cleanup EXIT
log "START nodes=$NODES topology=$TOPOLOGY rounds=$ROUNDS test_rounds=$TEST_ROUNDS seed=$SEED train=$TRAIN"
log "Docker root space:"
ROOT="$(docker info --format '{{.DockerRootDir}}' 2>/dev/null || true)"
if [[ -n "$ROOT" && -d "$ROOT" ]]; then
  df -h "$ROOT"
  FREE_KB="$(df -Pk "$ROOT" | awk 'NR==2 {print $4}')"
  if [[ "$FREE_KB" =~ ^[0-9]+$ ]] && ((FREE_KB < 3 * 1024 * 1024)); then
    log "Docker root has less than 3 GiB free; aborting before adding 20-50 containers/images"
    exit 3
  fi
else
  log 'WARNING Docker root filesystem space could not be measured; check Docker storage before scale-up'
fi
"${DC[@]}" --profile experiment --profile capture config --quiet
log 'Starting limited private services, then employee containers in batches of 10'
"${DC[@]}" up -d docs crm mail gateway
for ((a=1;a<=NODES;a+=10)); do
  batch=()
  for ((i=a;i<a+10 && i<=NODES;i++)); do printf -v name 'employee_%03d' "$i"; batch+=("$name"); done
  "${DC[@]}" up -d "${batch[@]}"
  log "STARTED employees $a..$((a + ${#batch[@]} - 1))/$NODES"
done
log 'Starting restricted sensor in gateway namespace; no additional host network privileges'
"${DC[@]}" --profile capture up -d --build capture
CAPCID="$("${DC[@]}" --profile capture ps -q capture)"
[[ -n "$CAPCID" ]] || { log 'ERROR capture missing'; exit 1; }
sleep 2
[[ "$(docker inspect -f '{{.State.Running}}' "$CAPCID")" == 'true' ]] || { docker logs "$CAPCID"; log 'ERROR capture exited'; exit 1; }
log 'Running 4 real HTTP probe requests before any labelled episode'
probe_ok=0
for ((try=1;try<=6;try++)); do
  if "${DC[@]}" --profile experiment run --rm --no-deps controller python -u runtime.py controller --probe; then probe_ok=1; break; fi
  log "Probe attempt $try failed; retrying readiness only"; sleep 2
done
((probe_ok == 1)) || { log 'ERROR all HTTP probes failed'; exit 1; }
sleep 1
"$PYTHON" -m orglab.audit --run-dir "outputs/orglab/$RUN_ID" --live --min-packets 4
log 'Capture probe passed with real packet records; beginning labelled collection'
"${DC[@]}" --profile experiment run --rm --no-deps controller
log 'Collection ended; closing capture for rigorous structural audit'
"${DC[@]}" --profile capture stop --timeout 8 capture
"$PYTHON" -m orglab.audit --run-dir "outputs/orglab/$RUN_ID" --min-packets 10
log 'Processing closed PCAP with Zeek; checksum checking remains enabled'
"$PYTHON" -m orglab.zeek_eval --run-dir "outputs/orglab/$RUN_ID"
log 'ZEEK GATE PASSED; output is valid controlled-network data, not actual attack traces'
if ((TRAIN == 1)); then
  log 'Starting gated independent CPU/GPU model workers; packet collection has stopped'
  ./setup/orglab_train_parallel.sh "$RUN_ID"
fi
log 'SUCCESS. Raw and model data saved; inspect outputs/orglab/'"$RUN_ID"
