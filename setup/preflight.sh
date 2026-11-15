#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
echo '== PHASE 3 PREFLIGHT =='
python --version
python - <<'PY'
import importlib.util, platform, os, shutil
for x in ('numpy','pandas','sklearn','optuna','pytest','torch'):
 print(x + ':', 'installed' if importlib.util.find_spec(x) else 'MISSING')
if importlib.util.find_spec('torch'):
 import torch
 print('CUDA available:',torch.cuda.is_available())
 if torch.cuda.is_available(): print('GPU:',torch.cuda.get_device_name(0))
print('CPUs:',os.cpu_count(),'Docker:',bool(shutil.which('docker')),'Zeek:',bool(shutil.which('zeek')))
PY
python -m compileall -q lab src/code setup/run_local_smoke.py
python -m pytest -q tests
if command -v docker >/dev/null 2>&1; then docker compose -f compose.yaml config --quiet; else echo 'Docker missing: cannot validate/run Compose in current environment'; fi
