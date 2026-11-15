#!/usr/bin/env bash
# Start independent read-only/restartable research jobs in parallel using tmux.
set -euo pipefail
cd "$(dirname "$0")/.."
if (($# < 1)); then echo "Usage: $0 RUN_ID [--hpo-trials 30] [--gru-epochs 60]" >&2;exit 2;fi
RUN_ID="$1";shift
TRIALS=30;EPOCHS=60
while (($#));do
  case "$1" in
   --hpo-trials) TRIALS="$2";shift 2;;
   --gru-epochs) EPOCHS="$2";shift 2;;
   *) echo "Unknown argument $1" >&2;exit 2;;
  esac
done
[[ "$RUN_ID" =~ ^[a-zA-Z0-9_-]+$ ]] || { echo 'Invalid run id' >&2;exit 2; }
[[ "$TRIALS" =~ ^[0-9]+$ && "$EPOCHS" =~ ^[0-9]+$ ]] || { echo 'Invalid numeric argument' >&2;exit 2; }
command -v tmux >/dev/null || { echo 'Install tmux with administrator permission' >&2;exit 1; }
if [[ -x .venv-cuda/bin/python ]];then PY="$PWD/.venv-cuda/bin/python";
elif [[ -x .venv/bin/python ]];then PY="$PWD/.venv/bin/python";
else PY="$(command -v python3)";fi
"$PY" -c 'import numpy,sklearn,optuna,torch' || exit 1
[[ -s "src/data/raw/runs/$RUN_ID/episodes.jsonl" && -s "src/data/raw/runs/$RUN_ID/gateway_subset.jsonl" ]] || { echo 'Completed pilot manifest and validated gateway subset required' >&2;exit 1; }
[[ -s "src/data/raw/runs/$RUN_ID/traffic.pcap" ]] || { echo 'PCAP required for Zeek audit' >&2;exit 1; }
export PYTEST_DISABLE_PLUGIN_AUTOLOAD=1
STAMP="$(date -u +%Y%m%dT%H%M%SZ)_$$"
WORK="outputs/sprints/${RUN_ID}/${STAMP}"
mkdir -p "$WORK"
WORK="$(realpath "$WORK")"
cat > "$WORK/zeek_job.sh" <<EOF
#!/usr/bin/env bash
set -euo pipefail
cd "$PWD"
export PATH="/opt/zeek/bin:\$PATH"
"$PY" -m setup.sprint_audit --run "$RUN_ID" --output "$WORK/audit"
# Only fit network-flow baselines if packet metadata passes the independent audit.
"$PY" -m setup.sprint_zeek_eval --run "$RUN_ID" --audit "$WORK/audit" --output "$WORK/zeek_results" || echo "Zeek-based model gated: inspect audit.json, do not claim network-flow validity" >&2
EOF
cat > "$WORK/hpo_job.sh" <<EOF
#!/usr/bin/env bash
set -euo pipefail
cd "$PWD"
export OMP_NUM_THREADS=4 OPENBLAS_NUM_THREADS=4 MKL_NUM_THREADS=4
"$PY" -m setup.sprint_hpo --run "$RUN_ID" --trials "$TRIALS" --output "outputs/hpo/sprints/$RUN_ID"
EOF
cat > "$WORK/gru_job.sh" <<EOF
#!/usr/bin/env bash
set -euo pipefail
cd "$PWD"
export OMP_NUM_THREADS=2 OPENBLAS_NUM_THREADS=2 MKL_NUM_THREADS=2
"$PY" -m src.code.temporal_gru_sprint --run "$RUN_ID" --epochs "$EPOCHS" --device auto --output "outputs/model/sprints/$RUN_ID"
EOF
for job in zeek hpo gru;do
  sess="p3_${STAMP##*_}_${job}"
  # tmux captures log even if session exits; no tasks run on your university machine until THIS command is executed there.
  tmux new-session -d -s "$sess" "bash '$WORK/${job}_job.sh' > '$WORK/${job}.log' 2>&1; echo \$? > '$WORK/${job}.exitcode'"
  echo "$job : tmux=$sess log=$WORK/${job}.log"
done
printf '%s\n' "$WORK" > outputs/sprints/latest_sprint_path.txt
printf '\nMonitor: tmux ls ; tail -f "%s/gru.log"\n' "$WORK"
printf 'Run-specific outputs persist across shutdown; active processes do NOT survive shutdown. Rerun completed-safe GPU jobs; HPO invocation adds trials.\n'
