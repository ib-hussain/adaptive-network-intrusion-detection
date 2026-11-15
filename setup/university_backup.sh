#!/usr/bin/env bash
# Non-destructive end-of-day backup to user-selected persistent or external destination.
set -euo pipefail
cd "$(dirname "$0")/.."
if (($# != 1)); then echo 'Usage: ./setup/university_backup.sh /path/to/external-or-persistent-backup' >&2; exit 2; fi
command -v rsync >/dev/null || { echo 'rsync missing. Install with permission.' >&2; exit 1; }
mkdir -p "$1"
DEST="$(realpath "$1")"
ROOT="$PWD"
case "$DEST" in "$ROOT"|"$ROOT"/*) echo 'Backup destination must be outside the repository' >&2; exit 1;; esac
if [[ "$(stat -c '%d' "$ROOT")" == "$(stat -c '%d' "$DEST")" ]]; then
  echo 'WARNING: backup destination is on the same filesystem as the project; NOT protection against drive loss.' >&2
fi
SNAP="$DEST/adaptive-nids-backup"
mkdir -p "$SNAP"
echo "Backing up $ROOT -> $SNAP (no --delete, no destructive cleanup)"
rsync -a --partial --exclude='/.git/' --exclude='/.venv/' --exclude='__pycache__/' --exclude='.pytest_cache/' -- "$ROOT/" "$SNAP/"
date -u '+%Y-%m-%dT%H:%M:%SZ' > "$SNAP/BACKUP_COMPLETED_UTC.txt"
echo 'Backup completed. Review size and retained content:'
du -sh "$SNAP"
find "$SNAP/src/data/raw" -type f \( -name 'episodes.jsonl' -o -name 'gateway_subset.jsonl' \) -print 2>/dev/null | sort | tail -30 || true
