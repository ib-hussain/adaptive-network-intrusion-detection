#!/usr/bin/env bash
# Offline analysis of one run's PCAP in its own empty directory; preserve original files.
set -euo pipefail
if (( $# != 2 ));then echo "Usage: $0 PCAP NEW_OUTPUT_DIR" >&2;exit 2;fi
command -v zeek >/dev/null || { echo 'Zeek unavailable' >&2;exit 1; }
PCAP="$(realpath "$1")";OUT="$2"
[[ -s "$PCAP" ]] || { echo 'PCAP missing or empty' >&2;exit 1; }
[[ ! -e "$OUT" ]] || { echo 'Output exists; refusing overwrite' >&2;exit 1; }
mkdir -p "$OUT"
(cd "$OUT" && zeek -C -r "$PCAP" LogAscii::use_json=T)
[[ -s "$OUT/conn.log" ]] || { echo 'No Zeek conn.log: validate capture bridge and payload visibility' >&2;exit 1; }
echo "Wrote offline Zeek JSON logs to $OUT; independent timing and content audit still required"
