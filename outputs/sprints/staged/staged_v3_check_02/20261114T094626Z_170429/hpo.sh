#!/bin/bash
set -euo pipefail
cd "/home/fastlab/deepFakeDetection/adaptive-network-intrusion-detection"
export OMP_NUM_THREADS=3 OPENBLAS_NUM_THREADS=3 MKL_NUM_THREADS=3
"/home/fastlab/deepFakeDetection/adaptive-network-intrusion-detection/.venv-cuda/bin/python" -m setup.sprint_hpo --run "staged_v3_check_02" --trials "30" --output "outputs/hpo/staged/staged_v3_check_02" --causal-labels
