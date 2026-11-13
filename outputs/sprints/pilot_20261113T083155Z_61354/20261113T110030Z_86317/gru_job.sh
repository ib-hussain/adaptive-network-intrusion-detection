#!/usr/bin/env bash
set -euo pipefail
cd "/home/fastlab/deepFakeDetection/adaptive-network-intrusion-detection"
export OMP_NUM_THREADS=2 OPENBLAS_NUM_THREADS=2 MKL_NUM_THREADS=2
"/home/fastlab/deepFakeDetection/adaptive-network-intrusion-detection/.venv-cuda/bin/python" -m src.code.temporal_gru_sprint --run "pilot_20261113T083155Z_61354" --epochs "60" --device auto --output "outputs/model/sprints/pilot_20261113T083155Z_61354"
