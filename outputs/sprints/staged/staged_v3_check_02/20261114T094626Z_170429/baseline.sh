#!/bin/bash
set -euo pipefail
cd "/home/fastlab/deepFakeDetection/adaptive-network-intrusion-detection"
export OMP_NUM_THREADS=2 OPENBLAS_NUM_THREADS=2 MKL_NUM_THREADS=2
"/home/fastlab/deepFakeDetection/adaptive-network-intrusion-detection/.venv-cuda/bin/python" -m src.code.pipeline --manifest "src/data/raw/runs/staged_v3_check_02/episodes.jsonl" --events "src/data/raw/runs/staged_v3_check_02/gateway_subset.jsonl" --output "outputs/results/staged_staged_v3_check_02_20261114T094626Z_170429" --causal-labels --trials 0
"/home/fastlab/deepFakeDetection/adaptive-network-intrusion-detection/.venv-cuda/bin/python" -m tools.validate_outputs --results-directory "outputs/results/staged_staged_v3_check_02_20261114T094626Z_170429"
