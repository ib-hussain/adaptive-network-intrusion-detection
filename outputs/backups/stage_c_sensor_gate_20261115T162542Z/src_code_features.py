"""Causal, episode-contained network communication window features."""
from collections import defaultdict
import math
import statistics

FEATURE_COLUMNS = (
    "event_count", "rate_per_s", "gap_mean_s", "gap_std_s", "gap_cv",
    "bytes_mean", "bytes_total", "origin_bytes_mean", "response_bytes_mean",
    "duration_mean_s", "unique_destinations", "unique_links", "destination_entropy",
    "large_flow_fraction", "tcp_fraction",
)


def make_windows(events, manifest, n_events=4, stride=1, min_events=3, before_milestone_only=True, causal_stage_labels=False):
    if n_events < 2 or min_events < 2 or stride < 1 or min_events > n_events:
        raise ValueError("Invalid window parameters")
    grouped = defaultdict(list)
    for row in events:
        if row["episode_id"] not in manifest:
            raise ValueError("Event references unknown episode")
        grouped[row["episode_id"]].append(row)
    windows = []
    for eid, episode in manifest.items():
        rows = sorted(grouped.get(eid, []), key=lambda v: v["ts"])
        impact = episode["milestone_ts"]
        if before_milestone_only and impact is not None:
            rows = [r for r in rows if r["ts"] < float(impact)]
        for end in range(min_events, len(rows) + 1, stride):
            chunk = rows[max(0, end - n_events):end]
            timestamps = [r["ts"] for r in chunk]
            gaps = [max(0.0, b-a) for a, b in zip(timestamps, timestamps[1:])]
            span = max(1e-4, timestamps[-1] - timestamps[0])
            gm = statistics.mean(gaps) if gaps else 0.0
            gs = statistics.pstdev(gaps) if len(gaps) > 1 else 0.0
            sizes = [r["orig_bytes"] + r["resp_bytes"] for r in chunk]
            destinations = [r["dst_host"] for r in chunk]
            counts = [destinations.count(x)/len(destinations) for x in set(destinations)]
            entropy = -sum(p * math.log2(p) for p in counts)
            features = {
                "event_count": len(chunk), "rate_per_s": (len(chunk) - 1) / span,
                "gap_mean_s": gm, "gap_std_s": gs, "gap_cv": gs/gm if gm > 0 else 0.0,
                "bytes_mean": statistics.mean(sizes), "bytes_total": sum(sizes),
                "origin_bytes_mean": statistics.mean(r["orig_bytes"] for r in chunk),
                "response_bytes_mean": statistics.mean(r["resp_bytes"] for r in chunk),
                "duration_mean_s": statistics.mean(r["duration"] for r in chunk),
                "unique_destinations": len(set(destinations)),
                "unique_links": len({(r["src_host"], r["dst_host"]) for r in chunk}),
                "destination_entropy": entropy,
                "large_flow_fraction": sum(size > 1024 for size in sizes) / len(sizes),
                "tcp_fraction": sum(r["proto"] == "tcp" for r in chunk) / len(chunk),
            }
            if not all(math.isfinite(x) for x in features.values()):
                raise ValueError("Non-finite features")
            windows.append({"episode_id": eid, "policy": episode["policy"], "label": int(episode["condition"] == "incident" and (not causal_stage_labels or timestamps[-1] >= float(episode.get("onset_ts") or episode["start_ts"]))),
                            "window_start_ts": timestamps[0], "window_end_ts": timestamps[-1],
                            **features})
    return windows
