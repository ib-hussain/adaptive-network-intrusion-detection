#!/usr/bin/env bash
# New independent university pilot per invocation. This is NOT in-place restart/resume.
set -euo pipefail
cd "$(dirname "$0")/.."
EPISODES=4
CAPTURE=1
RUN_ID="pilot_$(date -u +%Y%m%dT%H%M%SZ)_$$"
while (($#)); do
  case "$1" in
    --episodes) EPISODES="$2"; shift 2;;
    --run-id) RUN_ID="$2"; shift 2;;
    --no-capture) CAPTURE=0; shift;;
    --capture) CAPTURE=1; shift;;
    *) echo "Unknown argument $1" >&2; exit 2;;
  esac
done
[[ "$EPISODES" =~ ^[0-9]+$ ]] && ((EPISODES>=4 && EPISODES<=200)) || { echo 'Episodes must be integer 4..200' >&2; exit 2; }
[[ "$RUN_ID" =~ ^[A-Za-z0-9_-]+$ ]] || { echo 'Run ID must contain only letters, numbers, hyphen, underscore' >&2; exit 2; }
command -v docker >/dev/null || { echo 'Docker missing' >&2; exit 1; }
docker info >/dev/null || { echo 'Cannot use Docker daemon' >&2; exit 1; }
docker compose -f compose.yaml config --quiet
if [[ -x .venv/bin/python ]]; then PYTHON="$PWD/.venv/bin/python"; else PYTHON="$(command -v python3)"; fi
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
CAP_PID=''
stop_capture() {
  if [[ -n "$CAP_PID" ]]; then
    sudo -n kill -INT "$CAP_PID" >/dev/null 2>&1 || true
    wait "$CAP_PID" >/dev/null 2>&1 || true
    CAP_PID=''
    [[ -f "$RAW/traffic.pcap" ]] && sudo -n chown "$(id -u):$(id -g)" "$RAW/traffic.pcap" || true
  fi
}
shutdown_handler() { status=$?; stop_capture; if ((status)); then echo "Pilot interrupted/failed. Preserve partial logs in $RAW. Do NOT rerun with this ID." >&2; fi; }
trap shutdown_handler EXIT
if ((CAPTURE)); then
  NET_ID="$(docker network inspect -f '{{.Id}}' "$NETWORK")"
  IFACE="br-${NET_ID:0:12}"
  ip link show "$IFACE" >/dev/null 2>&1 || { echo "Bridge $IFACE absent: select verified capture interface manually" >&2; exit 1; }
  echo "Capturing ONLY lab bridge interface $IFACE (TCP 8080)"
  sudo -n tcpdump -i "$IFACE" -s 0 -U -w "$PWD/$RAW/traffic.pcap" 'tcp port 8080' > "$RAW/tcpdump.log" 2>&1 &
  CAP_PID=$!
  sleep 1
  kill -0 "$CAP_PID" 2>/dev/null || { echo 'tcpdump did not start' >&2; exit 1; }
fi
# Runner is disposable. The output is a NEW subdirectory on a persistent host bind mount.
docker compose --profile runner run --rm runner python -m lab.generate --output "/out/runs/$RUN_ID" --gateway 'http://gateway:8080' --episodes "$EPISODES" --test-episodes "$EPISODES" 2>&1 | tee "$RAW/runner.log"
stop_capture
"$PYTHON" -m setup.university_extract_events --manifest "$RAW/episodes.jsonl" --gateway src/data/raw/gateway_requests.jsonl --out "$RAW/gateway_subset.jsonl"
"$PYTHON" -m src.code.pipeline --manifest "$RAW/episodes.jsonl" --events "$RAW/gateway_subset.jsonl" --source gateway --output "$RESULTS" --trials 0
"$PYTHON" -m tools.validate_outputs --results-directory "$RESULTS"
"$PYTHON" -m src.code.figures --results "$RESULTS/results.json" --output "outputs/figs/$RUN_ID" || echo 'Figures unavailable; inspect results.json'
if ((CAPTURE)); then
  ./setup/zeek_from_pcap.sh "$RAW/traffic.pcap" "$LOGS"
  [[ -s "$LOGS/conn.log" ]] || { echo 'No Zeek conn.log: verify capture and bidirectional visibility' >&2; exit 1; }
  echo 'Zeek log created; alignment with manifest and gateway MUST be validated before scientific conclusions.'
fi
printf '\nSUCCESS: pilot %s\n' "$RUN_ID"
printf 'Raw run: %s\nResults: %s\n' "$RAW" "$RESULTS"
printf 'NOT a real intrusion detection validation; traffic profiles are harmless.\n'
