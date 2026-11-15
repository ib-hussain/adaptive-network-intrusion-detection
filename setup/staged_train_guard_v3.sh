#!/usr/bin/env bash
# Front-door guard for training: capture integrity and metadata completeness.
set -euo pipefail
cd "$(dirname "$0")/.."
(( $# >= 1 )) || { echo 'Usage: ./setup/staged_train_guard_v3.sh RUN_ID [--hpo-trials N --gru-epochs N]' >&2; exit 2; }
RUN_ID="$1"; shift
[[ "$RUN_ID" =~ ^[A-Za-z0-9_-]+$ ]] || exit 2
RAW="src/data/raw/runs/$RUN_ID"
[[ -s "$RAW/complete.json" && -s "$RAW/episodes.jsonl" && -s "$RAW/gateway_subset.jsonl" ]] || {
  echo 'STOP: complete.json / episodes.jsonl / gateway_subset.jsonl required. No training started.' >&2; exit 2;
}
PY="$(command -v python3)"
[[ -x .venv-cuda/bin/python ]] && PY="$PWD/.venv-cuda/bin/python"
"$PY" - "$RAW" <<'PYCHECK'
import sys
from pathlib import Path
from setup.staged_capture_audit import inspect_pcap
root=Path(sys.argv[1]); eps=sum(1 for _ in (root/'episodes.jsonl').open())
files=sorted(root.glob('traffic_*.pcap'))
results=[inspect_pcap(p) for p in files]
valid=[r for r in results if r['complete'] and r['packets'] > 0]
total=sum(r['packets'] for r in valid)
need=4*eps
print(f'[CAPTURE-GATE] episode_count={eps} pcap_segments={len(files)} valid_segments={len(valid)} packets={total} minimum={need}',flush=True)
for r in results:
    print(f"[CAPTURE-GATE] {Path(r['path']).name}: packets={r['packets']} complete={r['complete']} issue={r['issue']}",flush=True)
if total < need:
    raise SystemExit('STOP: insufficient independent PCAP packet evidence; training not started')
PYCHECK
printf '[%s] [TRAIN-GATE] Capture structure passed. Zeek/manifest alignment remains a separate scientific requirement.\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
exec ./setup/staged_train_start.sh "$RUN_ID" "$@"
