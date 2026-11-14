"""Post-capture Zeek evaluation for ORGLAB (never relabel HTTP as TCP flows)."""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from bisect import bisect_right
from pathlib import Path

from orglab.audit import audit_run, load_jsonl


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def assign(episodes: list[dict], conns: list[dict]):
    sorted_eps = sorted(episodes, key=lambda x: x["start_ts"])
    starts = [ep["start_ts"] for ep in sorted_eps]
    coverage = {ep["episode_id"]: {"connections": 0, "bidirectional": 0, "orig_bytes": 0, "resp_bytes": 0}
                for ep in sorted_eps}
    unmatched = 0
    for c in conns:
        try:
            ts = float(c["ts"])
        except (KeyError, ValueError, TypeError):
            unmatched += 1
            continue
        idx = bisect_right(starts, ts) - 1
        if idx < 0 or ts >= sorted_eps[idx]["end_ts"]:
            unmatched += 1
            continue
        e = coverage[sorted_eps[idx]["episode_id"]]
        e["connections"] += 1
        a = int(c.get("orig_bytes") or 0)
        b = int(c.get("resp_bytes") or 0)
        e["orig_bytes"] += a
        e["resp_bytes"] += b
        if a > 0 and b > 0:
            e["bidirectional"] += 1
    return coverage, unmatched


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--run-dir", type=Path, required=True)
    p.add_argument("--ignore-checksum", action="store_true", help="Only for documented offload artifacts; invokes zeek -C")
    p.add_argument("--minimum-episode-coverage", type=float, default=1.0)
    args = p.parse_args()
    run = args.run_dir.resolve()
    audit = audit_run(run, live=False, min_packets=4)
    pcap = run / "captures" / "orglab.pcap"
    out = run / "zeek"
    out.mkdir(exist_ok=True)
    if (out / "conn.log").exists():
        raise SystemExit("Zeek output already exists; refusing overwrite")
    command = ["zeek"] + (["-C"] if args.ignore_checksum else []) + ["-r", str(pcap), "LogAscii::use_json=T"]
    print("ZEEK_START", json.dumps(command), flush=True)
    process = subprocess.run(command, cwd=out, capture_output=True, text=True, check=False)
    (out / "zeek.stdout.log").write_text(process.stdout)
    (out / "zeek.stderr.log").write_text(process.stderr)
    if process.returncode != 0 or not (out / "conn.log").is_file():
        raise SystemExit(f"Zeek returned {process.returncode}; inspect {out / 'zeek.stderr.log'}")
    eps = load_jsonl(run / "episodes.jsonl")
    conns = load_jsonl(out / "conn.log")
    coverage, unmatched = assign(eps, conns)
    covered = sum(int(x["connections"] > 0 and x["bidirectional"] > 0) for x in coverage.values())
    fraction = covered / len(eps) if eps else 0
    report = {"pcap_sha256": sha256(pcap), "manifest_sha256": sha256(run / "episodes.jsonl"),
              "gateway_sha256": sha256(run / "gateway_requests.jsonl"),
              "zeek_returncode": process.returncode, "connections": len(conns),
              "unassigned_connections": unmatched, "episodes": len(eps),
              "episodes_with_bidirectional_connections": covered, "episode_coverage": fraction,
              "per_episode": coverage, "packet_count": audit["pcap"]["packets"],
              "checksum_validation_disabled": args.ignore_checksum,
              "status": "PASS" if fraction >= args.minimum_episode_coverage else "FAILED_COVERAGE"}
    (run / "zeek_audit.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print("ZEEK_AUDIT", json.dumps({k: report[k] for k in ("connections", "episodes", "episode_coverage", "status")}), flush=True)
    if report["status"] != "PASS":
        raise SystemExit("Zeek per-episode coverage below required minimum")


if __name__ == "__main__":
    main()
