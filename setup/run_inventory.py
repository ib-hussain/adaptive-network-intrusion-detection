"""Build the deterministic run inventory for a completed staged run.

The inventory is the single pointer a reader needs: run identity, the exact
command, every input hash, the observed counts, the sensor evidence tag and the
deterministic paths of every derived artefact.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256(path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as fp:
        for chunk in iter(lambda: fp.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_jsonl(path: Path):
    rows = []
    if not path.is_file():
        return rows
    with path.open(encoding="utf-8") as fp:
        for line in fp:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def build(run_id: str, sensor_audit: Path | None, collection_log: Path | None,
          command: str | None = None) -> dict:
    raw = REPO_ROOT / "src" / "data" / "raw" / "runs" / run_id
    episodes = _read_jsonl(raw / "episodes.jsonl")
    gateway = _read_jsonl(raw / "gateway_subset.jsonl")
    game = _read_jsonl(raw / "game_rounds.jsonl")
    config = {}
    if (raw / "scenario_config.json").is_file():
        config = json.loads((raw / "scenario_config.json").read_text(encoding="utf-8"))
    complete = {}
    if (raw / "complete.json").is_file():
        complete = json.loads((raw / "complete.json").read_text(encoding="utf-8"))
    pcaps = sorted(raw.glob("traffic_*.pcap"))
    audit = {}
    if sensor_audit and Path(sensor_audit).is_file():
        audit = json.loads(Path(sensor_audit).read_text(encoding="utf-8"))

    policy_counts = Counter(e.get("policy") for e in episodes)
    condition_counts = Counter(e.get("condition") for e in episodes)
    profile_counts = Counter(e.get("profile") for e in episodes)
    policy_profile = Counter((e.get("policy"), e.get("profile")) for e in episodes)
    requests = sum(int(e.get("requests") or 0) for e in episodes)

    inventory = {
        "schema": "phase3_run_inventory_v1",
        "generated_utc": _utc(),
        "run_id": run_id,
        "raw_dir": str(raw),
        "scenario_config": config,
        "scenario_config_sha256": sha256(raw / "scenario_config.json") if (raw / "scenario_config.json").is_file() else None,
        "complete_marker": complete,
        "collection_command": command,
        "collection_log": str(collection_log) if collection_log else None,
        "counts": {
            "episodes": len(episodes),
            "requests_in_manifest": requests,
            "gateway_events": len(gateway),
            "gateway_events_per_episode": (len(gateway) / len(episodes)) if episodes else None,
            "game_rounds": len(game),
            "pcap_segments": len(pcaps),
            "pcap_bytes": sum(p.stat().st_size for p in pcaps),
            "pcap_packets": sum(int(p.get("packets") or 0) for p in audit.get("pcaps", [])),
            "zeek_conn_entries": sum(int(r.get("conn_entries") or 0)
                                     for r in audit.get("zeek", {}).get("repaired_strict", [])
                                     or audit.get("zeek", {}).get("strict", [])),
            "episodes_by_policy": dict(policy_counts),
            "episodes_by_condition": dict(condition_counts),
            "episodes_by_profile": dict(profile_counts),
            "episodes_by_policy_profile": {f"{k[0]}/{k[1]}": v for k, v in sorted(policy_profile.items(),
                                                                                 key=lambda kv: str(kv[0]))},
        },
        "evidence": {
            "tag": audit.get("evidence_tag", "UNKNOWN"),
            "checksum_validation_ignored": audit.get("checksum_validation_ignored"),
            "checksum_repaired": audit.get("checksum_repaired"),
            "checks": {cid: {"passed": c.get("passed"), "detail": c.get("detail")}
                       for cid, c in sorted(audit.get("checks", {}).items())},
            "caveats": audit.get("evidence_caveats", []),
            "sensor_audit_path": str(sensor_audit) if sensor_audit else None,
            "sensor_audit_sha256": sha256(sensor_audit) if sensor_audit and Path(sensor_audit).is_file() else None,
        },
        "source_hashes": {},
        "paths": {
            "episodes_manifest": str(raw / "episodes.jsonl"),
            "gateway_subset": str(raw / "gateway_subset.jsonl"),
            "game_rounds": str(raw / "game_rounds.jsonl"),
            "scenario_config": str(raw / "scenario_config.json"),
            "complete_marker": str(raw / "complete.json"),
            "collector_status": str(raw / "collector_status_v3.json"),
            "pcaps": [str(p) for p in pcaps],
            "collector_logs": sorted(str(p) for p in raw.glob("collector_v3_*.log")),
            "generator_logs": sorted(str(p) for p in raw.glob("generator_*.log")),
            "capture_container_logs": sorted(str(p) for p in raw.glob("capture_container_*.log")),
            "capture_audits": sorted(str(p) for p in raw.glob("capture_audit_*.json")),
        },
        "environment": {"python": sys.version.split()[0], "platform": platform.platform(),
                        "host": platform.node()},
    }
    for name in ("episodes.jsonl", "gateway_subset.jsonl", "game_rounds.jsonl",
                 "scenario_config.json", "complete.json"):
        path = raw / name
        if path.is_file():
            inventory["source_hashes"][name] = sha256(path)
    for p in pcaps:
        inventory["source_hashes"][p.name] = sha256(p)
    return inventory


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", required=True)
    parser.add_argument("--sensor-audit", type=Path, default=None)
    parser.add_argument("--collection-log", type=Path, default=None)
    parser.add_argument("--command", default=None)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    inventory = build(args.run, args.sensor_audit, args.collection_log, args.command)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    if args.output.exists():
        raise FileExistsError(f"Refusing to overwrite: {args.output}")
    with args.output.open("x", encoding="utf-8") as fp:
        json.dump(inventory, fp, indent=2, sort_keys=True, allow_nan=False)
        fp.write("\n")
    print(f"Wrote {args.output}")
    print(json.dumps({"run_id": inventory["run_id"], "evidence_tag": inventory["evidence"]["tag"],
                      "counts": inventory["counts"]}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
