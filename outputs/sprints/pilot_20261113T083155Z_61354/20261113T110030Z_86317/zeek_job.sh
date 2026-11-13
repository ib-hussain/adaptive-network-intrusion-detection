#!/usr/bin/env bash
set -euo pipefail
cd "/home/fastlab/deepFakeDetection/adaptive-network-intrusion-detection"
export PATH="/opt/zeek/bin:$PATH"
"/home/fastlab/deepFakeDetection/adaptive-network-intrusion-detection/.venv-cuda/bin/python" -m setup.sprint_audit --run "pilot_20261113T083155Z_61354" --output "/home/fastlab/deepFakeDetection/adaptive-network-intrusion-detection/outputs/sprints/pilot_20261113T083155Z_61354/20261113T110030Z_86317/audit"
# Only fit network-flow baselines if packet metadata passes the independent audit.
"/home/fastlab/deepFakeDetection/adaptive-network-intrusion-detection/.venv-cuda/bin/python" -m setup.sprint_zeek_eval --run "pilot_20261113T083155Z_61354" --audit "/home/fastlab/deepFakeDetection/adaptive-network-intrusion-detection/outputs/sprints/pilot_20261113T083155Z_61354/20261113T110030Z_86317/audit" --output "/home/fastlab/deepFakeDetection/adaptive-network-intrusion-detection/outputs/sprints/pilot_20261113T083155Z_61354/20261113T110030Z_86317/zeek_results" || echo "Zeek-based model gated: inspect audit.json, do not claim network-flow validity" >&2
