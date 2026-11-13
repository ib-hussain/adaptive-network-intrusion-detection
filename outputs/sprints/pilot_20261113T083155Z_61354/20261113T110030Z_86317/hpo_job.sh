#!/usr/bin/env bash
set -euo pipefail
cd "/home/fastlab/deepFakeDetection/adaptive-network-intrusion-detection"
export OMP_NUM_THREADS=4 OPENBLAS_NUM_THREADS=4 MKL_NUM_THREADS=4
"/home/fastlab/deepFakeDetection/adaptive-network-intrusion-detection/.venv-cuda/bin/python" -m setup.sprint_hpo --run "pilot_20261113T083155Z_61354" --trials "30" --output "outputs/hpo/sprints/pilot_20261113T083155Z_61354"
