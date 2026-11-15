#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
[[ -s outputs/sprints/latest_sprint_path.txt ]] || { echo 'No sprint run yet';exit 1; }
WORK="$(cat outputs/sprints/latest_sprint_path.txt)"
printf 'SPRINT DIRECTORY: %s\n' "$WORK"
for job in zeek hpo gru;do
  echo "=== $job ==="
  if [[ -s "$WORK/$job.exitcode" ]];then echo "exit code: $(cat "$WORK/$job.exitcode")";else echo 'running or terminated without exit marker';fi
  [[ -f "$WORK/$job.log" ]] && tail -n 10 "$WORK/$job.log"
done
printf '\nACTIVE TMUX SESSIONS\n';tmux ls 2>/dev/null || true
