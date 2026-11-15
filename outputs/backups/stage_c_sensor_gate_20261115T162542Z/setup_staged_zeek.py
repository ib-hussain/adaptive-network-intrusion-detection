"""Fresh offline Zeek audit of completed staged-v2 PCAP segments.

Keeps original packet capture immutable. Duplicate connections across the gateway's
multiple network interfaces are possible, so record counts are NOT HTTP-request counts.
"""
from __future__ import annotations
import argparse
from bisect import bisect_right
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
from src.code.ingest import load_manifest, load_events, read_jsonl


def _hash(path):
    h = hashlib.sha256()
    with path.open("rb") as fp:
        for chunk in iter(lambda: fp.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def audit(run, output):
    raw = Path("src/data/raw/runs") / run
    if not (raw / "complete.json").exists():
        raise ValueError("Cannot evaluate an incomplete or unverified staged collection")
    manifest = load_manifest(raw / "episodes.jsonl")
    pcaps = sorted(raw.glob("traffic_*.pcap"))
    if not pcaps:
        raise FileNotFoundError("No staged capture found")
    output.mkdir(parents=True, exist_ok=False)
    entries, details = [], []
    for i, pcap in enumerate(pcaps):
        part = output / f"segment_{i:03d}"
        part.mkdir()
        proc = subprocess.run(["zeek", "-C", "-r", str(pcap.resolve()), "LogAscii::use_json=T"],
                              cwd=part, capture_output=True, text=True, timeout=300, check=False)
        d = {"filename": pcap.name, "pcap_sha256": _hash(pcap), "bytes": pcap.stat().st_size,
             "zeek_rc": proc.returncode, "stderr": proc.stderr[-1200:]}
        details.append(d)
        if proc.returncode:
            raise RuntimeError(f"Zeek failed on {pcap}: {proc.stderr[-300:]}")
        if (part / "conn.log").is_file():
            entries.extend(read_jsonl(part / "conn.log"))
    entries.sort(key=lambda item: float(item.get("ts", 0)))
    temp = output / "conn_combined.jsonl"
    with temp.open("x", encoding="utf-8") as fp:
        for entry in entries:
            fp.write(json.dumps(entry, sort_keys=True) + "\n")
    # A conn record is assigned only by time, never by label or attack ID.
    observed = load_events(temp, manifest, source="zeek")
    per_episode = Counter(row["episode_id"] for row in observed)
    ncovered = sum(per_episode[eid] >= 3 for eid in manifest)
    missing_test = [eid for eid, ep in manifest.items() if ep['policy']=='test' and per_episode[eid] < 3]
    report = {"run": run, "pcap_parts": details, "zeek_raw_conn": len(entries),
              "zeek_assigned_conn": len(observed), "episodes_total": len(manifest),
              "episodes_with_3_or_more_conns": ncovered,
              "window_coverage": ncovered / len(manifest), "test_episodes_missing_3_connections": missing_test,
              "gateway_flow_duplicate_warning": "Gateway namespace captures two distinct links; do not equate Zeek flows to request counts.",
              "caution": "Zeek -C ignores checksum validation; does not prove full bidirectional visibility or realistic attacks."}
    (output / "audit.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--run", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(audit(args.run, args.output), sort_keys=True, indent=2))

if __name__ == "__main__":
    main()
