#!/usr/bin/env bash
set -euo pipefail
if (( $# != 2 )); then echo "Usage: $0 <capture.pcap> <empty-output-directory>" >&2; exit 2; fi
if ! command -v zeek >/dev/null 2>&1; then echo "Zeek is not installed" >&2; exit 1; fi
pcap="$(realpath "$1")"
out="$2"
[[ -f "$pcap" ]] || { echo "Missing PCAP" >&2; exit 1; }
mkdir -p "$out"
[[ -z "$(ls -A "$out")" ]] || { echo "Output directory must be empty" >&2; exit 1; }
(cd "$out" && zeek -r "$pcap" LogAscii::use_json=T)
echo "Zeek JSON connection log: $out/conn.log"
