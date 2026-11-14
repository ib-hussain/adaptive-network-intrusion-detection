"""Fail-closed PCAP, ground-truth and gateway-count audit for the ORGLAB add-on.

Structural PCAP validation is NOT proof of complete bidirectional Zeek coverage.
"""
from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path

MAGIC = {
    b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">",
    b"\x4d\x3c\xb2\xa1": "<", b"\xa1\xb2\x3c\x4d": ">",
}


def count_pcap(path: Path, *, live: bool = False) -> dict:
    if not path.is_file():
        raise ValueError(f"missing PCAP: {path}")
    with path.open("rb") as f:
        head = f.read(24)
        if len(head) != 24 or head[:4] not in MAGIC:
            raise ValueError("not a supported classic PCAP global header")
        order = MAGIC[head[:4]]
        _, _, _, _, snaplen, linktype = struct.unpack(order + "HHiiii", head[4:24])
        # unpack iiii signed permits small, normal snaplen and DLT; sanity check below.
        if not 64 <= snaplen <= 262144:
            raise ValueError(f"unreasonable capture snaplen: {snaplen}")
        count, payload_bytes, truncated = 0, 0, False
        while True:
            record = f.read(16)
            if not record:
                break
            if len(record) != 16:
                if live:
                    truncated = True
                    break
                raise ValueError("truncated PCAP record header")
            _, _, captured, original = struct.unpack(order + "IIII", record)
            if captured == 0 or captured > snaplen or original < captured:
                raise ValueError("invalid PCAP record length")
            data = f.read(captured)
            if len(data) != captured:
                if live:
                    truncated = True
                    break
                raise ValueError("truncated PCAP packet")
            count += 1
            payload_bytes += captured
    return {"packets": count, "payload_bytes": payload_bytes, "linktype": linktype,
            "partial_tail_during_live_capture": truncated, "size_bytes": path.stat().st_size}


def load_jsonl(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def audit_run(root: Path, *, live: bool, min_packets: int) -> dict:
    pcap = count_pcap(root / "captures" / "orglab.pcap", live=live)
    if pcap["packets"] < min_packets:
        raise ValueError(f"packet count {pcap['packets']} < {min_packets}; header-only PCAP is invalid")
    result = {"pcap": pcap, "capture_structurally_valid": not (pcap["partial_tail_during_live_capture"] and not live)}
    if live:
        return result
    marker = json.loads((root / "collection_complete.json").read_text(encoding="utf-8"))
    episodes = load_jsonl(root / "episodes.jsonl")
    gateway = load_jsonl(root / "gateway_requests.jsonl")
    observed = [r for r in gateway if not r.get("probe")]
    expected = marker["expected_gateway_requests"]
    if len(episodes) != marker["expected_episodes"]:
        raise ValueError(f"episode count mismatch {len(episodes)} != {marker['expected_episodes']}")
    if len(observed) != expected:
        raise ValueError(f"gateway count mismatch {len(observed)} != {expected}")
    if len({e["episode_id"] for e in episodes}) != len(episodes):
        raise ValueError("duplicate episode IDs")
    if not all(e["start_ts"] < e["end_ts"] for e in episodes):
        raise ValueError("invalid episode time bounds")
    for e in episodes:
        if e["condition"] == "incident":
            if not e["start_ts"] <= e["onset_ts"] < e["escalation_ts"] < e["milestone_ts"] < e["end_ts"]:
                raise ValueError(f"invalid onset/escalation/milestone ordering: {e['episode_id']}")
    distinct_hosts = len({r["source_ip"] for r in observed})
    expected_hosts = int(episodes[0]["nodes"])
    if distinct_hosts < expected_hosts:
        raise ValueError(f"only {distinct_hosts}/{expected_hosts} independent employee IPs observed; incomplete multi-node coverage")
    result.update({"episodes": len(episodes), "gateway_requests": len(observed),
                   "probe_requests": len(gateway) - len(observed), "unique_worker_ips": distinct_hosts,
                   "gateway_and_manifest_counts_valid": True,
                   "zeek_per_episode_coverage_validated": False,
                   "science_status": "GATEWAY_AND_PCAP_STRUCTURE_ONLY; ZEEK_ALIGNMENT_REQUIRED"})
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--run-dir", type=Path, required=True)
    p.add_argument("--live", action="store_true", help="allow incomplete last record while capture is running (probe only)")
    p.add_argument("--min-packets", type=int, default=4)
    a = p.parse_args()
    try:
        result = audit_run(a.run_dir, live=a.live, min_packets=a.min_packets)
        print(json.dumps({"status": "PASS", **result}, indent=2, sort_keys=True))
    except Exception as exc:
        print(json.dumps({"status": "FAIL", "reason": str(exc)}, indent=2))
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
