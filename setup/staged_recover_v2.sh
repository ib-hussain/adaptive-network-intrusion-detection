#!/usr/bin/env bash
# Preserve a completed V2 run, extract observed gateway events and classify PCAP validity.
# NEVER reconstructs PCAP from application events, NEVER deletes old artifacts.
set -euo pipefail
cd "$(dirname "$0")/.."
(( $# == 1 )) || { echo 'Usage: staged_recover_v2.sh RUN_ID' >&2; exit 2; }
RUN_ID="$1"
[[ "$RUN_ID" =~ ^[A-Za-z0-9_-]+$ ]] || exit 2
RAW="src/data/raw/runs/$RUN_ID"
[[ -s "$RAW/complete.json" && -s "$RAW/episodes.jsonl" ]] || { echo 'Run not fully committed; no postprocessing' >&2; exit 1; }
PY="$(command -v python3)"
[[ -x .venv-cuda/bin/python ]] && PY="$PWD/.venv-cuda/bin/python"
if [[ ! -s "$RAW/gateway_subset.jsonl" ]]; then
  echo '[RECOVERY] Extracting observed requests from shared gateway log...'
  "$PY" -m setup.university_extract_events --manifest "$RAW/episodes.jsonl" --gateway src/data/raw/gateway_requests.jsonl --out "$RAW/gateway_subset.jsonl"
else
  echo '[RECOVERY] Existing gateway dataset preserved.'
fi
valid=0
while IFS= read -r p; do
  echo "[RECOVERY] Auditing $p"
  if "$PY" -m setup.staged_capture_audit --pcap "$p" --min-packets 4; then valid=1; fi
done < <(find "$RAW" -maxdepth 1 -type f -name 'traffic_*.pcap' -print)
if (( valid )); then
  echo '[RECOVERY] Packet-bearing PCAP found. Full Zeek/manifest alignment still required.'
else
  echo '[RECOVERY] APPLICATION-ONLY DATA: no valid packet-bearing PCAP. Preserve this run, use a NEW run ID for captured research.' >&2
  exit 4
fi
