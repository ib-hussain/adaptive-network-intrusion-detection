#!/usr/bin/env bash
# Non-destructive readiness check for the Phase 3 Ubuntu pilot.
set -euo pipefail
cd "$(dirname "$0")/.."
printf '%s\n' '===== UNIVERSITY PHASE 3 READINESS ====='
printf 'Working directory: %s\n' "$PWD"
python3 --version
for tool in docker zeek tcpdump sudo rsync tmux nvidia-smi; do
  if command -v "$tool" >/dev/null 2>&1; then printf '%-14s %s\n' "$tool" "$(command -v "$tool")"; else printf '%-14s %s\n' "$tool" 'NOT INSTALLED'; fi
done
printf '\nDISK: PROJECT\n'; df -h .
printf '\nDISK: DOCKER\n'
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  DOCKER_DIR="$(docker info --format '{{.DockerRootDir}}')"
  printf 'Docker root: %s\n' "$DOCKER_DIR"
  if [ -d "$DOCKER_DIR" ]; then df -h "$DOCKER_DIR"; fi
  docker system df || true
  printf '\nCOMPOSE SYNTAX\n'; docker compose -f compose.yaml config --quiet && echo 'valid'
else
  echo 'Docker daemon not usable by this account (check service/permissions).'
fi
printf '\nGPU\n'
if command -v nvidia-smi >/dev/null 2>&1; then nvidia-smi --query-gpu=name,memory.total,memory.free,driver_version --format=csv,noheader || true; fi
if [ -x .venv/bin/python ]; then
  .venv/bin/python - <<'PY'
try:
 import torch
 print(f'PyTorch {torch.__version__}; CUDA available: {torch.cuda.is_available()}')
except ImportError:
 print('PyTorch not installed in this venv (not required by current sklearn models)')
PY
fi
printf '\nRESEARCH CAUTION: Current RF/IsolationForest models are CPU-only.\n'
