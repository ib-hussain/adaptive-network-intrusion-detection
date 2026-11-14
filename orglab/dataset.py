"""Episode-disjoint, causal feature construction from observed ORGLAB HTTP gateway logs.

Gateway records are application observations, not Zeek TCP flows. Raw controller
labels and episode metadata are used only to partition/score, never as features.
"""
from __future__ import annotations

import math
from bisect import bisect_right
from collections import Counter
from pathlib import Path

from orglab.audit import load_jsonl

FEATURES = (
    "window_count", "distinct_employees", "distinct_services", "distinct_employee_service_edges",
    "top_employee_share", "mean_interarrival_s", "std_interarrival_s",
    "mean_gateway_latency_s", "mean_request_bytes", "service_docs_share",
    "service_crm_share", "service_mail_share",
)


def assign_records(episodes: list[dict], gateway: list[dict]) -> tuple[dict, int]:
    eps = sorted(episodes, key=lambda e: e["start_ts"])
    if len({e["episode_id"] for e in eps}) != len(eps):
        raise ValueError("duplicate episode IDs")
    if any(a["end_ts"] > b["start_ts"] for a, b in zip(eps, eps[1:])):
        raise ValueError("overlapping episode intervals; joins would be ambiguous")
    starts = [float(ep["start_ts"]) for ep in eps]
    by_episode = {ep["episode_id"]: [] for ep in eps}
    unmatched = 0
    for record in gateway:
        if record.get("probe"):
            continue
        ts = float(record["ts"])
        j = bisect_right(starts, ts) - 1
        if j >= 0 and ts < float(eps[j]["end_ts"]):
            by_episode[eps[j]["episode_id"]].append(record)
        else:
            unmatched += 1
    for ep in eps:
        records = by_episode[ep["episode_id"]]
        records.sort(key=lambda x: x["ts"])
        if len(records) != ep["requests"]:
            raise ValueError(f"episode {ep['episode_id']} has {len(records)} gateway records, expected {ep['requests']}")
    return by_episode, unmatched


def vector_from_history(history: list[dict]) -> list[float]:
    if not history:
        raise ValueError("empty causal observation window")
    emps = [str(r["employee"]) for r in history]
    svcs = [str(r["service"]) for r in history]
    times = [float(r["ts"]) for r in history]
    gaps = [max(0.0, b - a) for a, b in zip(times, times[1:])]
    mu = sum(gaps) / len(gaps) if gaps else 0.0
    sd = (sum((x - mu) ** 2 for x in gaps) / len(gaps)) ** 0.5 if gaps else 0.0
    counts = Counter(emps)
    features = [
        float(len(history)), float(len(counts)), float(len(set(svcs))),
        float(len(set(zip(emps, svcs)))), max(counts.values()) / len(history),
        mu, sd,
        sum(float(r["elapsed"]) for r in history) / len(history),
        sum(float(r["request_bytes"]) for r in history) / len(history),
        *(svcs.count(s) / len(history) for s in ("docs", "crm", "mail")),
    ]
    if any(not math.isfinite(v) for v in features):
        raise ValueError("non-finite feature")
    return features


def build_rows(episodes: list[dict], gateway: list[dict], *, lookback: int = 8):
    if not 2 <= lookback <= 32:
        raise ValueError("lookback outside supported range")
    by_episode, unmatched = assign_records(episodes, gateway)
    rows = []
    for ep in episodes:
        obs = by_episode[ep["episode_id"]]
        for j, record in enumerate(obs):
            ts = float(record["ts"])
            if ep["condition"] == "incident" and ts >= ep["milestone_ts"]:
                continue  # no training/early warning after the independently logged milestone
            history = obs[max(0, j - lookback + 1): j + 1]
            x = vector_from_history(history)
            label = int(ep["condition"] == "incident" and ts >= ep["onset_ts"])
            rows.append({"episode_id": ep["episode_id"], "policy": ep["policy"],
                         "round": int(ep["round"]), "condition": ep["condition"],
                         "ts": ts, "label": label, "features": x})
    return rows, {"unmatched_gateway_records": unmatched, "windows": len(rows),
                  "source": "application_gateway_real_observed_http_not_zeek"}


def load_rows(run_dir: Path, lookback: int = 8):
    episodes = load_jsonl(run_dir / "episodes.jsonl")
    gateway = load_jsonl(run_dir / "gateway_requests.jsonl")
    rows, audit = build_rows(episodes, gateway, lookback=lookback)
    return episodes, rows, audit
