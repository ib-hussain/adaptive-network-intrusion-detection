#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
[[ -s outputs/sprints/latest_staged_path.txt ]] || { echo 'No staged sprint launched' >&2;exit 1; }
WORK="$(cat outputs/sprints/latest_staged_path.txt)"
echo "SPRINT: $WORK"
for task in baseline hpo gru zeek;do
  [[ -f "$WORK/$task.sh" ]] || continue
  echo "===== $task ====="
  if [[ -e "$WORK/$task.exitcode" ]];then echo "exitcode=$(cat "$WORK/$task.exitcode")";else echo 'running or interrupted before exit marker';fi
  tail -n 5 "$WORK/$task.log" 2>/dev/null || true
done
