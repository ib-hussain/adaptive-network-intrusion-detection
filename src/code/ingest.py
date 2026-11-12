"""Validated ingestion of application gateway events or Zeek JSON conn.log.

The sources MUST NOT be silently merged: they may observe duplicate network actions.
"""
from __future__ import annotations
import json
import math
from pathlib import Path

REQUIRED_EPISODE_FIELDS = {"episode_id", "condition", "policy", "start_ts", "end_ts", "milestone_ts"}


def read_jsonl(path):
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(path)
    output = []
    with path.open(encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_num}: invalid JSON") from exc
            if not isinstance(item, dict):
                raise ValueError(f"{path}:{line_num}: object expected")
            output.append(item)
    if not output:
        raise ValueError(f"{path}: no records")
    return output


def load_manifest(path):
    entries = read_jsonl(path)
    manifest = {}
    for e in entries:
        if not REQUIRED_EPISODE_FIELDS.issubset(e):
            raise ValueError("Manifest missing required fields")
        eid = e["episode_id"]
        if not isinstance(eid, str) or not eid or eid in manifest:
            raise ValueError("Duplicate or invalid episode_id")
        start, end = float(e["start_ts"]), float(e["end_ts"])
        if not math.isfinite(start) or not math.isfinite(end) or start >= end:
            raise ValueError(f"Invalid episode interval {eid}")
        if e["condition"] not in ("benign", "incident") or e["policy"] not in ("fixed", "random", "strategic", "test"):
            raise ValueError(f"Invalid episode class/policy {eid}")
        milestone = e["milestone_ts"]
        if e["condition"] == "incident" and (milestone is None or not start <= float(milestone) <= end):
            raise ValueError(f"Incident without valid milestone: {eid}")
        if e["condition"] == "benign" and milestone is not None:
            raise ValueError(f"Benign episode has impact milestone: {eid}")
        manifest[eid] = e
    # Prevent ambiguous time-range assignment for Zeek conn records.
    sorted_entries = sorted(manifest.values(), key=lambda e: e["start_ts"])
    for left, right in zip(sorted_entries, sorted_entries[1:]):
        if left["end_ts"] > right["start_ts"]:
            raise ValueError("Overlapping episode intervals; Zeek joining could leak labels")
    return manifest


def _nonnegative_num(value, field):
    if value in (None, "-"):
        return 0.0
    try:
        result = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Invalid numeric field: {field}") from exc
    if not math.isfinite(result) or result < 0:
        raise ValueError(f"Non-finite or negative {field}")
    return result


def load_events(path, manifest, source="gateway"):
    if source not in ("gateway", "zeek"):
        raise ValueError("source must be 'gateway' or 'zeek'")
    raw = read_jsonl(path)
    episodes_by_time = sorted(manifest.values(), key=lambda e: e["start_ts"])
    result = []
    for row in raw:
        ts = _nonnegative_num(row.get("ts"), "ts")
        if source == "gateway":
            if row.get("sensor") != "application_gateway":
                raise ValueError("Expected gateway event; cannot silently mix log sources")
            eid = row.get("episode_id")
            if eid not in manifest:
                raise ValueError("Application event has missing/unmatched episode")
            # Captured timestamps may differ slightly from client send-times, but must be within recorded bounds.
            if not manifest[eid]["start_ts"] - .1 <= ts <= manifest[eid]["end_ts"] + .1:
                raise ValueError("Event timestamp outside episode")
            src, dst = str(row.get("src_host", "")), str(row.get("dst_host", ""))
            orig = _nonnegative_num(row.get("orig_bytes"), "orig_bytes")
            resp = _nonnegative_num(row.get("resp_bytes"), "resp_bytes")
        else:
            candidates = [e["episode_id"] for e in episodes_by_time if e["start_ts"] <= ts <= e["end_ts"]]
            if len(candidates) != 1:
                # Drop traffic outside experiment windows; never infer a label from ambiguous matches.
                if not candidates:
                    continue
                raise ValueError("Zeek timestamp ambiguously matches episodes")
            eid = candidates[0]
            src, dst = str(row.get("id.orig_h", "")), str(row.get("id.resp_h", ""))
            orig = _nonnegative_num(row.get("orig_bytes"), "orig_bytes")
            resp = _nonnegative_num(row.get("resp_bytes"), "resp_bytes")
        if not src or not dst:
            raise ValueError("Missing source/destination endpoint")
        duration = _nonnegative_num(row.get("duration"), "duration")
        result.append({"episode_id": eid, "ts": ts, "src_host": src, "dst_host": dst,
                       "proto": str(row.get("proto", "tcp")), "duration": duration,
                       "orig_bytes": orig, "resp_bytes": resp, "source": source})
    result.sort(key=lambda x: (x["episode_id"], x["ts"]))
    if not result:
        raise ValueError("No valid events after episode joining")
    return result
