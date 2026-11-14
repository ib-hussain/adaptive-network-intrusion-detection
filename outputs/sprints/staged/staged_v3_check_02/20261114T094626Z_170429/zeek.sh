#!/bin/bash
set -euo pipefail
cd "/home/fastlab/deepFakeDetection/adaptive-network-intrusion-detection"
export PATH="/opt/zeek/bin:$PATH"
"/home/fastlab/deepFakeDetection/adaptive-network-intrusion-detection/.venv-cuda/bin/python" -m setup.staged_zeek --run "staged_v3_check_02" --output "/home/fastlab/deepFakeDetection/adaptive-network-intrusion-detection/outputs/sprints/staged/staged_v3_check_02/20261114T094626Z_170429/zeek"
# Strong gate: sufficient observed connections from every independent episode.
if "/home/fastlab/deepFakeDetection/adaptive-network-intrusion-detection/.venv-cuda/bin/python" - "/home/fastlab/deepFakeDetection/adaptive-network-intrusion-detection/outputs/sprints/staged/staged_v3_check_02/20261114T094626Z_170429/zeek/audit.json" <<'PYCHECK'
import json,sys
r=json.load(open(sys.argv[1]))
if r['window_coverage'] < 0.90 or r['test_episodes_missing_3_connections']:
    print('ZEEK_BASELINE_GATED: insufficient coverage or test episodes missing Zeek windows')
    sys.exit(1)
PYCHECK
then
 "/home/fastlab/deepFakeDetection/adaptive-network-intrusion-detection/.venv-cuda/bin/python" -m src.code.pipeline --manifest "src/data/raw/runs/staged_v3_check_02/episodes.jsonl" --events "/home/fastlab/deepFakeDetection/adaptive-network-intrusion-detection/outputs/sprints/staged/staged_v3_check_02/20261114T094626Z_170429/zeek/conn_combined.jsonl" --source zeek --output "outputs/results/staged_zeek_staged_v3_check_02_20261114T094626Z_170429" --causal-labels --trials 0
 "/home/fastlab/deepFakeDetection/adaptive-network-intrusion-detection/.venv-cuda/bin/python" -m tools.validate_outputs --results-directory "outputs/results/staged_zeek_staged_v3_check_02_20261114T094626Z_170429"
else
 echo 'Zeek model skipped: inspect the network audit; no fabricated flows or metrics' >&2
fi
