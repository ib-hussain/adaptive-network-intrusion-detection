#!/usr/bin/env bash
# Six isolated CPU baselines + one serial GPU GraphSAGE/GRU worker, only AFTER valid capture.
set -Eeuo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
[[ $# -ge 1 && $# -le 3 ]] || { echo 'Usage: setup/orglab_train_parallel.sh RUN_ID [--graph-epochs N]' >&2; exit 2; }
RUN_ID="$1"; shift
EPOCHS=30
if (($#)); then
  [[ "${1:-}" == '--graph-epochs' && "${2:-}" =~ ^[0-9]+$ ]] || { echo 'Expected --graph-epochs N' >&2; exit 2; }
  EPOCHS="$2"
fi
[[ "$RUN_ID" =~ ^[A-Za-z][A-Za-z0-9_-]{1,40}$ ]] || { echo 'Invalid run ID' >&2; exit 2; }
BASE="outputs/orglab/$RUN_ID"
[[ -f "$BASE/zeek_audit.json" && -f "$BASE/collection_complete.json" ]] || { echo 'Required completed collection / Zeek audit missing' >&2; exit 3; }
python3 - "$BASE" <<'PY'
import json,sys
from pathlib import Path
p=Path(sys.argv[1]); j=json.loads((p/'zeek_audit.json').read_text())
if j.get('status') != 'PASS' or j.get('episode_coverage',0)<1:
    raise SystemExit('Zeek audit does not prove full episode coverage; refusing training')
print('CAPTURE_GATED: Zeek PASS, episode coverage',j['episode_coverage'],flush=True)
PY
[[ ! -e "$BASE/training" ]] || { echo "Existing training state must be inspected before restart: $BASE/training" >&2; exit 3; }
mkdir -p "$BASE/training/logs" "$BASE/training/models"
export PYTHONUNBUFFERED=1 OMP_NUM_THREADS=2 OPENBLAS_NUM_THREADS=2 MKL_NUM_THREADS=2 NUMEXPR_NUM_THREADS=2
PYTHON="${VIRTUAL_ENV:+$VIRTUAL_ENV/bin/python}"
PYTHON="${PYTHON:-python3}"
status() { printf '[%s] [ORGLAB-TRAIN/%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$RUN_ID" "$*"; }
status "START CPU policies=3 algorithms=RF+IsolationForest graph=2-layer directed MeanSAGE+GRU device=auto epochs=$EPOCHS"
pids=()
for policy in fixed random strategic; do
  for algo in rf iforest; do
    name="${policy}_${algo}"
    (
      set +e
      "$PYTHON" -u -m orglab.train --run-dir "$BASE" --output "$BASE/training/models/$name" --policy "$policy" --algo "$algo" >"$BASE/training/logs/$name.log" 2>&1
      rc=$?
      printf '%s\n' "$rc" > "$BASE/training/logs/$name.exitcode"
      exit "$rc"
    ) &
    pids+=("$!")
    status "LAUNCHED CPU $name PID=$! logs=$BASE/training/logs/$name.log"
  done
done
(
  set +e
  rc=0
  for policy in fixed random strategic; do
    "$PYTHON" -u -m orglab.graph_train --run-dir "$BASE" --output "$BASE/training/models/${policy}_graphgru" \
      --policy "$policy" --epochs "$EPOCHS" --device auto >"$BASE/training/logs/${policy}_graphgru.log" 2>&1
    this=$?
    printf '%s\n' "$this" >"$BASE/training/logs/${policy}_graphgru.exitcode"
    [[ "$this" == 0 ]] || rc=1
  done
  exit "$rc"
) &
pids+=("$!")
status "LAUNCHED one serial GPU graph worker PID=$! (not three competing GPU jobs)"
while true; do
  alive=0
  for pid in "${pids[@]}"; do if kill -0 "$pid" 2>/dev/null; then alive=$((alive+1)); fi; done
  [[ "$alive" == 0 ]] && break
  status "HEARTBEAT live_worker_processes=$alive/7 finished_exitcodes=$(find "$BASE/training/logs" -name '*.exitcode' | wc -l | tr -d ' ')"
  for f in "$BASE/training/logs"/*graphgru.log; do
    [[ -f "$f" ]] && tail -n 1 "$f" | sed "s|^|  $(basename "$f"): |"
  done
  sleep 15
done
failed=0
for pid in "${pids[@]}"; do wait "$pid" || failed=1; done
"$PYTHON" - "$BASE/training" <<'PY'
import json,sys
from datetime import datetime,timezone
from pathlib import Path
p=Path(sys.argv[1]); codes={q.stem:int(q.read_text().strip()) for q in p.glob('logs/*.exitcode')}
obj={'utc':datetime.now(timezone.utc).isoformat(), 'worker_exit_codes':codes,
     'expected_workers':9, 'all_success':len(codes)==9 and all(x==0 for x in codes.values())}
(p/'training_summary.json').write_text(json.dumps(obj,indent=2)+'\n')
print('TRAIN_SUMMARY',json.dumps(obj),flush=True)
PY
[[ "$failed" == 0 ]] && grep -q '"all_success": true' "$BASE/training/training_summary.json" || {
  status "FAILED/INCOMPLETE. All results and checkpoint/latest.pt are preserved; inspect individual logs."; exit 1
}
status "SUCCESS 6 CPU + 3 sequential GPU policy models; inspect metrics; no real-attack claims"
