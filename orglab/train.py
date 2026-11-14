"""Train/evaluate leak-safe CPU baselines on *captured* ORGLAB HTTP gateway observations.

Requires valid PCAP/Zeek audit by default. Use --allow-gateway-only ONLY for
software diagnostics, not as evidence of network-level research.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import statistics
from collections import defaultdict
from pathlib import Path

from orglab.audit import audit_run
from orglab.dataset import FEATURES, load_rows


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for part in iter(lambda: f.read(1 << 20), b""):
            h.update(part)
    return h.hexdigest()


def splits(episodes: list[dict], policy: str):
    policy_eps = [e for e in episodes if e["policy"] == policy]
    test = [e for e in episodes if e["policy"] == "test"]
    rounds = sorted({int(e["round"]) for e in policy_eps})
    if len(rounds) < 4:
        raise ValueError(f"need >=4 rounds per training policy for held-out validation, got {len(rounds)}")
    cutoff = min(len(rounds) - 1, max(2, int(len(rounds) * 0.75)))
    train_rounds, val_rounds = set(rounds[:cutoff]), set(rounds[cutoff:])
    train = [e for e in policy_eps if e["round"] in train_rounds]
    val = [e for e in policy_eps if e["round"] in val_rounds]
    for part in (train, val, test):
        if {e["condition"] for e in part} != {"benign", "incident"}:
            raise ValueError("invalid class balance in episode-disjoint split")
    all_ids = [[e["episode_id"] for e in a] for a in (train, val, test)]
    if len(set(sum(all_ids, []))) != sum(map(len, all_ids)):
        raise ValueError("episode leakage between partitions")
    return {"train": train, "validation": val, "test": test}


def partition_rows(rows: list[dict], group: list[dict]) -> list[dict]:
    ids = {e["episode_id"] for e in group}
    return [x for x in rows if x["episode_id"] in ids]


def alerts(rows: list[dict], scores: list[float], threshold: float, persistence: int = 2):
    grouped = defaultdict(list)
    for r, score in zip(rows, scores):
        grouped[r["episode_id"]].append((r["ts"], score))
    result = {}
    for episode_id, events in grouped.items():
        count, times = 0, []
        for ts, score in sorted(events):
            if score >= threshold:
                count += 1
                if count == persistence:
                    times.append(ts)
            else:
                count = 0
        result[episode_id] = times
    return result


def warning_metrics(group: list[dict], rows: list[dict], scores: list[float], threshold: float, persistence: int = 2):
    marked = alerts(rows, scores, threshold, persistence)
    incidents = [e for e in group if e["condition"] == "incident"]
    benign = [e for e in group if e["condition"] == "benign"]
    lead_times, preonset, miss, false_episodes, total_false = [], 0, 0, 0, 0
    for ep in incidents:
        a = marked.get(ep["episode_id"], [])
        preonset += sum(t < ep["onset_ts"] for t in a)
        valid = [t for t in a if ep["onset_ts"] <= t < ep["milestone_ts"]]
        if valid:
            lead_times.append(ep["milestone_ts"] - valid[0])
        else:
            miss += 1
    for ep in benign:
        a = marked.get(ep["episode_id"], [])
        false_episodes += int(bool(a))
        total_false += len(a)
    benign_hours = sum(e["end_ts"] - e["start_ts"] for e in benign) / 3600
    n = len(incidents)
    return {"warning_coverage": len(lead_times) / n if n else 0,
            "warned_incidents": len(lead_times), "incident_episodes": n, "missed_incidents": miss,
            "conditional_mean_lead_s": statistics.mean(lead_times) if lead_times else None,
            "conditional_median_lead_s": statistics.median(lead_times) if lead_times else None,
            "coverage_adjusted_mean_lead_s": sum(lead_times) / n if n else 0,
            "false_positive_episodes": false_episodes, "benign_episodes": len(benign),
            "false_positive_episode_fraction": false_episodes / len(benign) if benign else None,
            "false_alarms_per_benign_hour": total_false / benign_hours if benign_hours else None,
            "preonset_sustained_alarms": preonset}


def threshold_from_validation(episodes, rows, scores, alpha: float, persistence: int):
    if not 0 <= alpha <= 1:
        raise ValueError("alpha must be between 0 and 1")
    candidates = sorted(set(float(x) for x in scores))
    candidates.append(math.nextafter(max(candidates), float("inf")))
    good = []
    for threshold in candidates:
        stats = warning_metrics(episodes, rows, scores, threshold, persistence)
        if stats["false_positive_episode_fraction"] is not None and stats["false_positive_episode_fraction"] <= alpha:
            good.append((stats["coverage_adjusted_mean_lead_s"], stats["warning_coverage"],
                         -stats["false_positive_episodes"], threshold))
    if not good:
        raise ValueError("no validation threshold meets false alarm episode constraint")
    return max(good)[3]


def train_one(run: Path, out: Path, *, policy: str, algo: str, alpha: float,
              persistence: int, allow_gateway_only: bool):
    import joblib
    import numpy as np
    from sklearn.ensemble import IsolationForest, RandomForestClassifier
    from sklearn.metrics import average_precision_score, f1_score, precision_score, recall_score

    audit = audit_run(run, live=False, min_packets=4)
    if not allow_gateway_only:
        zeek_path = run / "zeek_audit.json"
        if not zeek_path.is_file() or json.loads(zeek_path.read_text())["status"] != "PASS":
            raise ValueError("capture+Zeek alignment gate failed; use --allow-gateway-only only for diagnostics")
    eps, rows, load_audit = load_rows(run)
    groups = splits(eps, policy)
    r_train, r_val, r_test = [partition_rows(rows, groups[x]) for x in ("train", "validation", "test")]
    if not all(x for x in (r_train, r_val, r_test)):
        raise ValueError("empty partition")
    Xtrain = np.asarray([x["features"] for x in r_train], dtype="float64")
    Xval = np.asarray([x["features"] for x in r_val], dtype="float64")
    Xtest = np.asarray([x["features"] for x in r_test], dtype="float64")
    ytrain = np.asarray([x["label"] for x in r_train], dtype="int64")
    ytest = np.asarray([x["label"] for x in r_test], dtype="int64")
    if len(set(ytrain)) != 2 or len(set(ytest)) != 2:
        raise ValueError("both train and test must contain benign and post-onset windows")
    if not all(np.isfinite(arr).all() for arr in (Xtrain, Xval, Xtest)):
        raise ValueError("nonfinite feature tensor")
    if algo == "rf":
        model = RandomForestClassifier(n_estimators=140, max_depth=7, min_samples_leaf=2,
                                       class_weight="balanced", random_state=20261114, n_jobs=2)
        model.fit(Xtrain, ytrain)
        score = lambda x: model.predict_proba(x)[:, 1]
    elif algo == "iforest":
        model = IsolationForest(n_estimators=120, contamination="auto", random_state=20261114, n_jobs=2)
        model.fit(Xtrain[ytrain == 0])
        score = lambda x: -model.decision_function(x)
    else:
        raise ValueError("unknown algorithm")
    sval = score(Xval).tolist()
    stest = score(Xtest).tolist()
    threshold = threshold_from_validation(groups["validation"], r_val, sval, alpha, persistence)
    wm = warning_metrics(groups["test"], r_test, stest, threshold, persistence)
    predictions = (np.asarray(stest) >= threshold).astype("int64")
    result = {"policy": policy, "algorithm": algo, "threshold": threshold, "alpha_validation_fp_episode": alpha,
              "warning_persistence": persistence, "warning": wm,
              "detection": {"macro_f1": float(f1_score(ytest, predictions, average="macro", zero_division=0)),
                            "positive_precision": float(precision_score(ytest, predictions, zero_division=0)),
                            "positive_recall": float(recall_score(ytest, predictions, zero_division=0)),
                            "pr_auc": float(average_precision_score(ytest, stest))},
              "episodes": {k: len(v) for k, v in groups.items()},
              "windows": {"train": len(r_train), "validation": len(r_val), "test": len(r_test)},
              "feature_names": FEATURES, "source": load_audit["source"],
              "capture_gate": "zeek_pass" if not allow_gateway_only else "gateway_diagnostic_only",
              "dataset_sha256": {"episodes": digest(run / "episodes.jsonl"),
                                 "gateway": digest(run / "gateway_requests.jsonl"),
                                 "pcap": digest(run / "captures" / "orglab.pcap")},
              "caveat": "Authorised harmless lab traffic; scores do not establish real intrusion or zero-day detection"}
    out.mkdir(parents=True, exist_ok=False)
    joblib.dump({"model": model, "features": FEATURES, "threshold": threshold}, out / "model.joblib")
    (out / "results.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    with (out / "test_predictions.jsonl").open("w", encoding="utf-8") as f:
        for r, s in zip(r_test, stest):
            f.write(json.dumps({"episode_id": r["episode_id"], "ts": r["ts"],
                                "label": r["label"], "score": float(s), "alert": bool(s >= threshold)}) + "\n")
    print(f"TRAINING_COMPLETE policy={policy} algo={algo} test_PR_AUC={result['detection']['pr_auc']:.3f} "
          f"coverage={wm['warning_coverage']:.3f} false_alarms_per_benign_hour={wm['false_alarms_per_benign_hour']} "
          f"out={out}", flush=True)
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--run-dir", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--policy", choices=["fixed", "random", "strategic"], required=True)
    p.add_argument("--algo", choices=["rf", "iforest"], default="rf")
    p.add_argument("--max-false-positive-episode-fraction", type=float, default=0.1)
    p.add_argument("--persistence", type=int, default=2)
    p.add_argument("--allow-gateway-only", action="store_true")
    a = p.parse_args()
    train_one(a.run_dir, a.output, policy=a.policy, algo=a.algo,
              alpha=a.max_false_positive_episode_fraction, persistence=a.persistence,
              allow_gateway_only=a.allow_gateway_only)


if __name__ == "__main__":
    main()
