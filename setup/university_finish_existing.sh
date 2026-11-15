#!/usr/bin/env bash
# Safely process a COMPLETE existing university pilot without repeating traffic generation.
# Not an in-place continuation of the game policy or incomplete episode.
set -euo pipefail
cd "$(dirname "$0")/.."
if (( $# < 1 || $# > 2 )); then
  echo "Usage: $0 RUN_ID [--skip-zeek]" >&2; exit 2
fi
RUN_ID="$1"
[[ "$RUN_ID" =~ ^[A-Za-z0-9_-]+$ ]] || { echo 'Invalid run ID' >&2; exit 2; }
SKIP_ZEEK=0
if (( $# == 2 )); then
  [[ "$2" == '--skip-zeek' ]] || { echo 'Only optional flag is --skip-zeek' >&2; exit 2; }
  SKIP_ZEEK=1
fi
RAW="src/data/raw/runs/$RUN_ID"
LOGS="outputs/logs/zeek/$RUN_ID"
[[ -s "$RAW/episodes.jsonl" ]] || { echo "Missing/empty $RAW/episodes.jsonl" >&2; exit 1; }
[[ -f src/data/raw/gateway_requests.jsonl ]] || { echo 'Missing shared gateway event log' >&2; exit 1; }
if [[ -x .venv/bin/python ]]; then PYTHON="$PWD/.venv/bin/python"; else PYTHON="$(command -v python3)"; fi
"$PYTHON" - "$RAW/episodes.jsonl" <<'PY'
import sys
from collections import Counter
from src.code.ingest import load_manifest
m=load_manifest(sys.argv[1]); k=Counter((x['policy'],x['condition']) for x in m.values())
policies=('fixed','random','strategic','test')
counts=[k[(p,c)] for p in policies for c in ('benign','incident')]
if not counts or min(counts)<4 or len(set(counts))!=1 or len(m)!=sum(counts):
    raise SystemExit(f'Incomplete experiment or unequal policy/condition counts: {dict(k)}')
if any(v['condition']=='incident' and not (v.get('start_ts') <= v.get('onset_ts') <= v.get('milestone_ts') <= v.get('end_ts')) for v in m.values()):
    raise SystemExit('Invalid incident chronology; cannot postprocess')
print(f'Complete experiment manifest: {len(m)} episodes, {len(m)*12} expected requests')
PY
if [[ ! -e "$RAW/gateway_subset.jsonl" ]]; then
  "$PYTHON" -m setup.university_extract_events --manifest "$RAW/episodes.jsonl" --gateway src/data/raw/gateway_requests.jsonl --out "$RAW/gateway_subset.jsonl"
else
  echo 'Existing gateway subset preserved; checking per-episode counts and HTTP status.'
  "$PYTHON" - "$RAW/episodes.jsonl" "$RAW/gateway_subset.jsonl" <<'PY_CHECK'
import sys
from collections import Counter
from src.code.ingest import load_manifest, read_jsonl, load_events
manifest=load_manifest(sys.argv[1]); rows=read_jsonl(sys.argv[2])
counts=Counter(r.get('episode_id') for r in rows)
for eid,e in manifest.items():
    if counts[eid]!=int(e['requests']):
        raise SystemExit(f'Existing subset incomplete/duplicated for {eid}: {counts[eid]} != {e["requests"]}')
if len(rows)!=sum(int(e['requests']) for e in manifest.values()) or any(r.get('status')!=200 for r in rows):
    raise SystemExit('Existing gateway subset has extra observations or failed request')
if len(load_events(sys.argv[2], manifest, 'gateway'))!=len(rows):
    raise SystemExit('Existing subset failed timestamp alignment')
print('Existing gateway subset validated.')
PY_CHECK
fi
# Process into a NEW results directory. Never overwrite a completed or partial output.
RESULTS="outputs/results/${RUN_ID}_postprocess_$(date -u +%Y%m%dT%H%M%SZ)_$$"
"$PYTHON" -m src.code.pipeline --manifest "$RAW/episodes.jsonl" --events "$RAW/gateway_subset.jsonl" --source gateway --output "$RESULTS" --trials 0
"$PYTHON" -m tools.validate_outputs --results-directory "$RESULTS"
"$PYTHON" -m src.code.figures --results "$RESULTS/results.json" --output "outputs/figs/$(basename "$RESULTS")" || echo 'Figure export unavailable; results JSON preserved.' >&2
if (( ! SKIP_ZEEK )); then
  if [[ ! -s "$RAW/traffic.pcap" ]]; then
    echo 'Warning: no nonempty PCAP. Sensor research validation PENDING.' >&2
  elif [[ -s "$LOGS/conn.log" ]]; then
    echo "Existing Zeek conn.log preserved in $LOGS"
  else
    if [[ -e "$LOGS" ]] && [[ -n "$(ls -A "$LOGS" 2>/dev/null)" ]]; then
      echo "Nonempty but incomplete Zeek directory: $LOGS. Will not overwrite." >&2
    else
      ./setup/zeek_from_pcap.sh "$RAW/traffic.pcap" "$LOGS"
    fi
  fi
fi
printf '\nPOSTPROCESS COMPLETED: %s\n' "$RUN_ID"
printf 'Results: %s\n' "$RESULTS"
printf 'Gateway baseline and Zeek PCAP remain DISTINCT data sources. This is not verified real intrusion evidence.\n'
