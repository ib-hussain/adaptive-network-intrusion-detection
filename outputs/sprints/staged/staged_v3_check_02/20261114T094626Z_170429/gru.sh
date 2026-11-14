#!/bin/bash
set -euo pipefail
cd "/home/fastlab/deepFakeDetection/adaptive-network-intrusion-detection"
export OMP_NUM_THREADS=2 OPENBLAS_NUM_THREADS=2 MKL_NUM_THREADS=2
"/home/fastlab/deepFakeDetection/adaptive-network-intrusion-detection/.venv-cuda/bin/python" -m src.code.temporal_gru_sprint --run "staged_v3_check_02" --epochs "80" --device auto --output "outputs/model/staged/staged_v3_check_02" --causal-labels
