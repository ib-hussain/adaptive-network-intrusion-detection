#!/usr/bin/env bash
# Exclusive bridge-capture pilot with bounded process shutdown and recorded random seed. NOT in-place game resume.
set -euo pipefail
cd "$(dirname "$0")/.."
EPISODES=4
CAPTURE=1
SEED="$(date +%s)"
RUN_ID="pilot_$(date -u +%Y%m%dT%H%M%SZ)_$$"
while (($#)); do
  case "$1" in
    --episodes) EPISODES="$2"; shift 2;;
    --run-id) RUN_ID="$2"; shift 2;;
    --seed) SEED="$2"; shift 2;;
    --no-capture) CAPTURE=0; shift;;
    --capture) CAPTURE=1; shift;;
    -h|--help) echo "Usage: $0 [--episodes 4..200] [--seed INT] [--run-id ID] [--capture|--no-capture]"; exit 0;;
    *) echo "Unknown argument $1" >&2; exit 2;;
  esac
done
[[ "$EPISODES" =~ ^[0-9]+$ ]] && ((EPISODES>=4 && EPISODES<=200)) || { echo 'Episodes must be integer 4..200' >&2; exit 2; }
[[ "$SEED" =~ ^[0-9]+$ ]] || { echo "Seed must be a non-negative integer" >&2; exit 2; }
[[ "$RUN_ID" =~ ^[A-Za-z0-9_-]+$ ]] || { echo 'Run ID must contain only letters, numbers, hyphen, underscore' >&2; exit 2; }
command -v docker >/dev/null || { echo 'Docker missing' >&2; exit 1; }
docker info >/dev/null || { echo 'Cannot use Docker daemon' >&2; exit 1; }
docker compose -f compose.yaml config --quiet
command -v flock >/dev/null || { echo "flock missing; required to protect shared capture bridge" >&2; exit 1; }
mkdir -p outputs/locks
exec 9>outputs/locks/bridge_capture.lock
flock -n 9 || { echo "Another v3 capture already holds the bridge lock; cannot run concurrent captures" >&2;exit 1; }
if [[ -x .venv-cuda/bin/python ]];then PYTHON="$PWD/.venv-cuda/bin/python"; elif [[ -x .venv/bin/python ]];then PYTHON="$PWD/.venv/bin/python"; else PYTHON="$(command -v python3)"; fi
"$PYTHON" -c 'import sklearn,optuna,matplotlib'
RAW="src/data/raw/runs/$RUN_ID"
RESULTS="outputs/results/$RUN_ID"
LOGS="outputs/logs/zeek/$RUN_ID"
[[ ! -e "$RAW" && ! -e "$RESULTS" && ! -e "$LOGS" ]] || { echo 'Run ID already exists: choose a new ID; no files overwritten' >&2; exit 1; }
if ((CAPTURE)); then
  command -v tcpdump >/dev/null || { echo 'tcpdump missing. Install with lab admin permission or use --no-capture for a non-research pilot.' >&2; exit 1; }
  command -v zeek >/dev/null || { echo 'zeek missing. Install with lab admin permission or use --no-capture for a non-research pilot.' >&2; exit 1; }
  command -v sudo >/dev/null || { echo 'sudo required for host bridge capture; ask lab admin.' >&2; exit 1; }
  sudo -v || { echo 'Host capture requires sudo; ask lab admin.' >&2; exit 1; }
fi
printf '%s\n' "Starting independent pilot: $RUN_ID"
docker compose -f compose.yaml up -d server_a server_b gateway
NETWORK='phase3-adaptive-nids_services'
for name in phase3-adaptive-nids_services phase3-adaptive-nids_clients; do
  [[ "$(docker network inspect -f '{{.Internal}}' "$name")" == 'true' ]] || { echo "Network $name is not internal" >&2; exit 1; }
  [[ "$(docker network inspect -f '{{.Driver}}' "$name")" == 'bridge' ]] || { echo "Network $name is not Linux bridge driver" >&2; exit 1; }
done
# Wait for both services and gateway to accept TCP connections, without creating labelled traffic.
for _ in $(seq 1 20); do
  if docker compose exec -T gateway python -c 'import socket; [(lambda s:(s.close()))(socket.create_connection((h, 8080), timeout=2)) for h in ("127.0.0.1", "server_a", "server_b")]' >/dev/null 2>&1; then ready=1; break; fi
  sleep 1
done
[[ "${ready:-0}" == 1 ]] || { echo 'Gateway/services unavailable' >&2; exit 1; }
mkdir -p "$RAW"
printf '{"run_id":"%s","seed":%s,"episode_budget_per_policy":%s,"capture":%s}\n' "$RUN_ID" "$SEED" "$EPISODES" "$CAPTURE" > "$RAW/scenario_config.json"
CAP_PID=''
stop_capture() {
  if [[ -n "$CAP_PID" ]]; then
    local pid='' cmd='' i
    if [[ -s "$RAW/capture.pid" ]]; then
      pid="$(cat "$RAW/capture.pid")"
      if [[ "$pid" =~ ^[0-9]+$ ]]; then
        cmd="$(sudo -n cat "/proc/$pid/cmdline" 2>/dev/null | tr '\0' ' ' || true)"
        if [[ "$cmd" == *tcpdump* && "$cmd" == *"$RAW/traffic.pcap"* ]]; then
          echo "Stopping this run's tcpdump gracefully (PID $pid)"
          sudo -n kill -INT "$pid" 2>/dev/null || true
          for ((i=0; i<40; i++)); do
            [[ -e "/proc/$pid/cmdline" ]] || break
            cmd="$(sudo -n cat "/proc/$pid/cmdline" 2>/dev/null | tr '\0' ' ' || true)"
            [[ "$cmd" == *tcpdump* ]] || break
            sleep 0.25
          done
          cmd="$(sudo -n cat "/proc/$pid/cmdline" 2>/dev/null | tr '\0' ' ' || true)"
          if [[ "$cmd" == *tcpdump* ]]; then
            echo 'Warning: graceful stop timed out; terminating this capture only' >&2
            sudo -n kill -TERM "$pid" 2>/dev/null || true
          fi
        else
          echo 'Warning: capture PID file did not identify this run; avoiding unrelated process' >&2
        fi
      fi
    fi
    # No unbounded wait on a privileged sudo-wrapper; it caused the university hang.
    sudo -n kill -TERM "$CAP_PID" 2>/dev/null || true
    local remaining=""
    if [[ -s "$RAW/capture.pid" ]]; then
      remaining="$(cat "$RAW/capture.pid")"
      for ((i=0; i<20; i++));do
        [[ ! -d "/proc/$remaining" ]] && break
        cmd="$(sudo -n cat "/proc/$remaining/cmdline" 2>/dev/null | tr '\0' ' ' || true)"
        [[ "$cmd" != *tcpdump* ]] && break
        sleep 0.2
      done
      cmd="$(sudo -n cat "/proc/$remaining/cmdline" 2>/dev/null | tr '\0' ' ' || true)"
      if [[ "$cmd" == *tcpdump* ]];then
        echo "ERROR: capture PID $remaining has not stopped. Stop that PID from an approved administrator terminal and recover this run; no analysis while PCAP open" >&2
        return 1
      fi
    fi
    CAP_PID=''
    if [[ -f "$RAW/traffic.pcap" ]]; then
      sudo -n chown "$(id -u):$(id -g)" "$RAW/traffic.pcap" || true
    fi
  fi
}
shutdown_handler() { status=$?; stop_capture; if ((status)); then echo "Pilot interrupted/failed. Preserve partial logs in $RAW. Do NOT rerun with this ID." >&2; fi; }
trap shutdown_handler EXIT
if ((CAPTURE)); then
  NET_ID="$(docker network inspect -f '{{.Id}}' "$NETWORK")"
  IFACE="br-${NET_ID:0:12}"
  ip link show "$IFACE" >/dev/null 2>&1 || { echo "Bridge $IFACE absent: select verified capture interface manually" >&2; exit 1; }
  if sudo -n pgrep -a -x tcpdump 2>/dev/null | grep -F -- "-i $IFACE" >/dev/null;then
    echo "ERROR: another tcpdump is already recording lab bridge $IFACE. Stop/recover older run first, do NOT mix captures." >&2;exit 1
  fi
  echo "Capturing ONLY lab bridge interface $IFACE (TCP 8080)"
  # Record the real tcpdump PID, not the sudo wrapper PID.
  sudo -n bash -c 'echo "$$" > "$1"; exec tcpdump -i "$2" -s 0 -U -w "$3" "tcp port 8080"' _ "$RAW/capture.pid" "$IFACE" "$PWD/$RAW/traffic.pcap" > "$RAW/tcpdump.log" 2>&1 &
  CAP_PID=$!
  for ((i=0; i<20; i++)); do
    [[ -s "$RAW/capture.pid" ]] && break
    kill -0 "$CAP_PID" 2>/dev/null || break
    sleep 0.1
  done
  [[ -s "$RAW/capture.pid" ]] || { echo 'tcpdump failed to create PID file' >&2; exit 1; }
  kill -0 "$CAP_PID" 2>/dev/null || { echo 'tcpdump did not start' >&2; exit 1; }
fi
# Runner is disposable. The output is a NEW subdirectory on a persistent host bind mount.
docker compose --profile runner run --rm -T runner python -m lab.generate --output "/out/runs/$RUN_ID" --gateway 'http://gateway:8080' --episodes "$EPISODES" --test-episodes "$EPISODES" --seed "$SEED" 2>&1 | tee "$RAW/runner.log"
stop_capture
"$PYTHON" -m setup.university_extract_events --manifest "$RAW/episodes.jsonl" --gateway src/data/raw/gateway_requests.jsonl --out "$RAW/gateway_subset.jsonl"
"$PYTHON" -m src.code.pipeline --manifest "$RAW/episodes.jsonl" --events "$RAW/gateway_subset.jsonl" --source gateway --output "$RESULTS" --trials 0
"$PYTHON" -m tools.validate_outputs --results-directory "$RESULTS"
"$PYTHON" -m src.code.figures --results "$RESULTS/results.json" --output "outputs/figs/$RUN_ID" || echo 'Figures unavailable; inspect results.json'
if ((CAPTURE)); then
  ./setup/zeek_from_pcap_v3.sh "$RAW/traffic.pcap" "$LOGS"
  [[ -s "$LOGS/conn.log" ]] || { echo 'No Zeek conn.log: verify capture and bidirectional visibility' >&2; exit 1; }
  echo 'Zeek log created; alignment with manifest and gateway MUST be validated before scientific conclusions.'
fi
printf '\nSUCCESS: pilot %s\n' "$RUN_ID"
printf 'Raw run: %s\nResults: %s\n' "$RAW" "$RESULTS"
printf 'NOT a real intrusion detection validation; traffic profiles are harmless.\n'
