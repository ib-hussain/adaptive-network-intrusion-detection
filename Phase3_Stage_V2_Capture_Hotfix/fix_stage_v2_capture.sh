#!/usr/bin/env bash
# Non-destructive, idempotent hotfix for Stage V2 Docker Compose interpolation.
set -euo pipefail
REPO="${1:-$PWD}"
REPO="$(realpath "$REPO")"
TARGET="$REPO/setup/staged_collect_v2.sh"
[[ -f "$TARGET" ]] || { echo "ERROR: Missing $TARGET" >&2; exit 1; }
python3 - "$TARGET" "$REPO" <<'PY'
import datetime
import os
from pathlib import Path
import shutil
import sys
import tempfile

src=Path(sys.argv[1]); repo=Path(sys.argv[2]); s=src.read_text()
new_marker='# Stage V2 hotfix: define all Compose interpolation vars before ANY Compose call.'
if new_marker in s:
    assert s.index('export STAGED_CAPTURE_NAME') < s.index('COMPOSE=(docker compose'), 'Capture variable still exported too late'
    print('Already patched; source unchanged.')
    raise SystemExit(0)
old_begin='export STAGED_RUN_ID="$RUN_ID"\nCOMPOSE=(docker compose -f compose.yaml -f compose.staged.capture.yaml --profile capture)'
new_begin=('export STAGED_RUN_ID="$RUN_ID"\n'
           + new_marker + '\n'
           + 'STAGED_CAPTURE_NAME="traffic_$(date -u +%Y%m%dT%H%M%SZ)_$$"\n'
           + 'export STAGED_CAPTURE_NAME\n'
           + 'COMPOSE=(docker compose -f compose.yaml -f compose.staged.capture.yaml --profile capture)')
old_late=('STAGED_CAPTURE_NAME="traffic_$(date -u +%Y%m%dT%H%M%SZ)_$$"\n'
          + 'export STAGED_CAPTURE_NAME\nCAP_STARTED=0')
if s.count(old_begin)!=1 or s.count(old_late)!=1:
    raise SystemExit('STOP: unexpected launcher contents; no edits. Inspect setup/staged_collect_v2.sh manually.')
new=s.replace(old_begin,new_begin,1).replace(old_late,'CAP_STARTED=0',1)
assert new.count('STAGED_CAPTURE_NAME="traffic_')==1
assert new.index('export STAGED_CAPTURE_NAME') < new.index('docker compose -f compose.yaml -f compose.staged.capture.yaml config --quiet')
backup=repo/'outputs'/'backups'/('stage_v2_capture_hotfix_'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ'))
backup.mkdir(parents=True, exist_ok=False)
shutil.copy2(src, backup/src.name)
fd,tmp=tempfile.mkstemp(prefix='.staged_collect_v2.',dir=src.parent)
try:
    with os.fdopen(fd,'w') as f:
        f.write(new); f.flush(); os.fsync(f.fileno())
    os.chmod(tmp,src.stat().st_mode)
    os.replace(tmp,src)
finally:
    if os.path.exists(tmp): os.remove(tmp)
print('PATCH APPLIED; previous launcher backed up at:',backup/src.name)
PY
bash -n "$TARGET"
echo 'Bash syntax valid. No run data, captures, checkpoints or other project files modified.'
