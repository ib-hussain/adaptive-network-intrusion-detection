#!/usr/bin/env bash
# Read-only snapshot of the existing Stage V3 capture/timeout state.
set -Eeuo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
RUN_ID="${1:-staged_v2_main_01}"
[[ "$RUN_ID" =~ ^[A-Za-z][A-Za-z0-9_-]{1,80}$ ]] || { echo 'Invalid run ID' >&2; exit 2; }
ROOT="src/data/raw/runs/$RUN_ID"
[[ -d "$ROOT" ]] || { echo "No such run: $ROOT" >&2; exit 2; }
NOW="$(date -u +%Y%m%dT%H%M%SZ)"
DIR="outputs/logs/setup/diagnose_v3_${RUN_ID}_${NOW}"
mkdir -p "$DIR"
exec > >(tee -a "$DIR/audit.log") 2>&1
printf 'DATE=%s\nRUN=%s\nPWD=%s\n' "$(date -u -Is)" "$RUN_ID" "$PWD"
printf '\nGIT\n'; git status --short --branch || true
printf '\nCAPTURE INVOCATION / TIMEOUT / PROBE CODE\n'
grep -nE '\-Z root|timeout|CAPTURE_PROBE|probe|tcpdump|sleep|CAPTURE_PREFLIGHT_FAILED' setup/staged_collect_v3.sh | head -130 || true
printf '\nRAW STATUS\n'
find "$ROOT" -maxdepth 2 -type f \( -name '*.json' -o -name '*.jsonl' -o -name '*.pcap' -o -name '*.log' \) -printf '%TY-%Tm-%Td %TH:%TM:%TS %s %p\n' | sort | tail -75
printf '\nCOMPLETE/CONTROLLER STATUS\n'
for f in "$ROOT"/complete.json "$ROOT"/scenario_config.json "$ROOT"/collector_status_v3.json; do
  if [[ -f "$f" ]]; then printf '%s\n' "$f"; head -c 8000 "$f"; printf '\n'; fi
done
printf '\nLATEST CAPTURE CONTAINER LOG TAILS\n'
for f in $(find "$ROOT" -maxdepth 1 -name 'capture_container_*.log' -type f | sort | tail -3); do echo "----- $f"; tail -n 45 "$f"; done
printf '\nLATEST COLLECTOR LOG TAILS\n'
for f in $(find "$ROOT" -maxdepth 1 -name 'collector_v3_*.log' -type f | sort | tail -3); do echo "----- $f"; tail -n 75 "$f"; done
printf '\nLIVE PROCESSES (READ ONLY)\n'
ps -eo pid,ppid,stat,etime,args | grep -E '[s]taged_collect|[t]cpdump' || true
if command -v docker >/dev/null; then
  printf '\nNAMED CAPTURE CONTAINERS (READ ONLY)\n'; docker ps -a --filter 'label=phase3.staged.capture=1' || true
fi
printf '\nSNAPSHOT SAVED: %s\n' "$DIR/audit.log"
echo 'No processes stopped, no locks removed, no PCAP/model/data modified.'
