#!/usr/bin/env bash
# Parallelise completed-run analysis; NEVER collect traffic while model jobs run.
set -euo pipefail
cd "$(dirname "$0")/.."
if (( $# < 1 ));then echo 'Usage: staged_train_start.sh RUN_ID [--hpo-trials 30] [--gru-epochs 80]' >&2;exit 2;fi
RUN_ID="$1";shift;TRIALS=30;EPOCHS=80
while (($#));do
 case "$1" in
  --hpo-trials) TRIALS="$2";shift 2;;
  --gru-epochs) EPOCHS="$2";shift 2;;
  *) echo "Unknown: $1" >&2;exit 2;;
 esac
done
[[ "$RUN_ID" =~ ^[A-Za-z0-9_-]+$ && "$TRIALS" =~ ^[0-9]+$ && "$EPOCHS" =~ ^[0-9]+$ ]] || exit 2
(( TRIALS>=1 && TRIALS<=500 && EPOCHS>=1 && EPOCHS<=500 )) || exit 2
RAW="src/data/raw/runs/$RUN_ID"
[[ -s "$RAW/complete.json" && -s "$RAW/gateway_subset.jsonl" && -s "$RAW/episodes.jsonl" ]] || { echo 'Completed captured run with extracted gateway subset required' >&2;exit 1; }
# Critical: prevent simultaneous write access to same Optuna DB or epoch checkpoint.
for name in "stg_${RUN_ID}_";do
  if tmux ls 2>/dev/null | grep -F "$name" >/dev/null;then
    echo 'An existing staged training job for this run is active; inspect tmux ls first' >&2;exit 1
  fi
done
PY="$PWD/.venv-cuda/bin/python"
[[ -x "$PY" ]] || PY="$PWD/.venv/bin/python"
[[ -x "$PY" ]] || PY="$(command -v python3)"
"$PY" -c 'import torch,optuna,sklearn,pandas,numpy'
STAMP="$(date -u +%Y%m%dT%H%M%SZ)_$$"
WORK="outputs/sprints/staged/$RUN_ID/$STAMP"
mkdir -p "$WORK"
WORK="$(realpath "$WORK")"
export PYTEST_DISABLE_PLUGIN_AUTOLOAD=1
# Script files persist: jobs are independently restartable (restart with fresh launcher).
cat > "$WORK/baseline.sh" <<EOJOB
#!/bin/bash
set -euo pipefail
cd "$PWD"
export OMP_NUM_THREADS=2 OPENBLAS_NUM_THREADS=2 MKL_NUM_THREADS=2
"$PY" -m src.code.pipeline --manifest "$RAW/episodes.jsonl" --events "$RAW/gateway_subset.jsonl" --output "outputs/results/staged_${RUN_ID}_${STAMP}" --causal-labels --trials 0
"$PY" -m tools.validate_outputs --results-directory "outputs/results/staged_${RUN_ID}_${STAMP}"
EOJOB
cat > "$WORK/hpo.sh" <<EOJOB
#!/bin/bash
set -euo pipefail
cd "$PWD"
export OMP_NUM_THREADS=3 OPENBLAS_NUM_THREADS=3 MKL_NUM_THREADS=3
"$PY" -m setup.sprint_hpo --run "$RUN_ID" --trials "$TRIALS" --output "outputs/hpo/staged/$RUN_ID" --causal-labels
EOJOB
cat > "$WORK/gru.sh" <<EOJOB
#!/bin/bash
set -euo pipefail
cd "$PWD"
export OMP_NUM_THREADS=2 OPENBLAS_NUM_THREADS=2 MKL_NUM_THREADS=2
"$PY" -m src.code.temporal_gru_sprint --run "$RUN_ID" --epochs "$EPOCHS" --device auto --output "outputs/model/staged/$RUN_ID" --causal-labels
EOJOB
if compgen -G "$RAW/traffic_*.pcap" >/dev/null;then
cat > "$WORK/zeek.sh" <<EOJOB
#!/bin/bash
set -euo pipefail
cd "$PWD"
export PATH="/opt/zeek/bin:\$PATH"
"$PY" -m setup.staged_zeek --run "$RUN_ID" --output "$WORK/zeek"
# Strong gate: sufficient observed connections from every independent episode.
if "$PY" - "$WORK/zeek/audit.json" <<'PYCHECK'
import json,sys
r=json.load(open(sys.argv[1]))
if r['window_coverage'] < 0.90 or r['test_episodes_missing_3_connections']:
    print('ZEEK_BASELINE_GATED: insufficient coverage or test episodes missing Zeek windows')
    sys.exit(1)
PYCHECK
then
 "$PY" -m src.code.pipeline --manifest "$RAW/episodes.jsonl" --events "$WORK/zeek/conn_combined.jsonl" --source zeek --output "outputs/results/staged_zeek_${RUN_ID}_${STAMP}" --causal-labels --trials 0
 "$PY" -m tools.validate_outputs --results-directory "outputs/results/staged_zeek_${RUN_ID}_${STAMP}"
else
 echo 'Zeek model skipped: inspect the network audit; no fabricated flows or metrics' >&2
fi
EOJOB
fi
for task in baseline hpo gru zeek;do
  [[ -f "$WORK/$task.sh" ]] || continue
  SESS="stg_${RUN_ID}_${STAMP}_${task}"
  tmux new-session -d -s "$SESS" "bash '$WORK/$task.sh' > '$WORK/$task.log' 2>&1; echo \$? > '$WORK/$task.exitcode'"
  echo "$task: $SESS; log: $WORK/$task.log"
done
printf '%s\n' "$WORK" > outputs/sprints/latest_staged_path.txt
echo 'Monitor: ./setup/staged_status.sh ; tmux ls'
echo 'Do NOT run concurrent captures: collection traffic timing would be confounded.'
