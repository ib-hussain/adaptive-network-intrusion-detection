"""Study pipeline. Reads observed HTTP/Zeek logs; never invents research measurements."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
import platform
import random
from pathlib import Path
import numpy as np
from sklearn.metrics import average_precision_score, f1_score, precision_score, recall_score, roc_auc_score
from .ingest import load_manifest, load_events
from .features import make_windows, FEATURE_COLUMNS
from .models import fit_baseline, predict_scores, tune_forest, arrays
from .early_warning import early_warning_metrics, early_warning_bootstrap_ci
import joblib


def split_episode_ids(manifest, policy, seed=42, val_fraction=.25):
    rng = random.Random(seed)
    selected = [e for e in manifest.values() if e["policy"] == policy]
    training, validation = set(), set()
    for condition in ("benign", "incident"):
        episodes = sorted(e["episode_id"] for e in selected if e["condition"] == condition)
        if len(episodes) < 3:
            raise ValueError(f"Need >=3 independent {condition} episodes in policy {policy} for train/val")
        rng.shuffle(episodes)
        nval = max(1, round(len(episodes) * val_fraction))
        validation.update(episodes[:nval])
        training.update(episodes[nval:])
    if training & validation:
        raise ValueError("Leakage: same episode in training and validation")
    return training, validation


def episode_detection_metrics(predictions, manifest, threshold):
    # Score per independent episode, not per overlapping observation window.
    max_scores = {}
    for p in predictions:
        eid = p["episode_id"]
        max_scores[eid] = max(max_scores.get(eid, 0.0), float(p["score"]))
    episodes = [eid for eid in sorted(manifest) if eid in max_scores]
    y = np.array([int(manifest[eid]["condition"] == "incident") for eid in episodes])
    scores = np.array([max_scores[eid] for eid in episodes])
    pred = scores >= threshold
    if len(y) == 0 or len(np.unique(y)) < 2:
        raise ValueError("Evaluation requires independent episodes from both classes")
    return {"episode_f1": float(f1_score(y, pred, zero_division=0)),
            "episode_precision": float(precision_score(y, pred, zero_division=0)),
            "episode_recall": float(recall_score(y, pred, zero_division=0)),
            "episode_pr_auc": float(average_precision_score(y, scores)),
            "episode_roc_auc": float(roc_auc_score(y, scores)),
            "n_scored_episodes": len(y)}


def choose_validation_threshold(predictions, manifest, max_false_positive_episodes=.15):
    # Threshold selected strictly on validation episodes; prefer coverage-adjusted mean lead.
    candidates = [float(x) for x in np.linspace(.25, .95, 15)]
    eligible = []
    for threshold in candidates:
        metrics = early_warning_metrics(predictions, manifest, threshold)
        fpr = metrics["false_positive_episode_rate"]
        if fpr is not None and fpr <= max_false_positive_episodes:
            eligible.append((metrics["coverage_adjusted_mean_lead_s"] or 0.0,
                             metrics["pre_milestone_coverage"] or 0.0, threshold))
    if not eligible:
        # Explicitly mark infeasibility rather than secretly relax the false alarm bound.
        return None
    return sorted(eligible, reverse=True)[0][2]


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fp:
        json.dump(value, fp, indent=2, sort_keys=True, allow_nan=False)
        fp.write("\n")


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as fp:
        for chunk in iter(lambda: fp.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run_pipeline(manifest_path, events_path, out_dir, source="gateway", seed=20261112, trials=0, n_events=4):
    output = Path(out_dir)
    if output.exists() and any(output.iterdir()):
        raise FileExistsError("Output directory is not empty; preserve earlier experimental results")
    manifest = load_manifest(manifest_path)
    observations = load_events(events_path, manifest, source)
    windows = make_windows(observations, manifest, n_events=n_events, min_events=3, before_milestone_only=True)
    test_ids = {eid for eid, e in manifest.items() if e["policy"] == "test"}
    if len({manifest[eid]["condition"] for eid in test_ids}) != 2:
        raise ValueError("Independent test set lacks benign or incident episodes")
    test_manifest = {eid: manifest[eid] for eid in test_ids}
    test_windows_all = make_windows(observations, manifest, n_events=n_events, min_events=3, before_milestone_only=False)
    test_windows = [r for r in test_windows_all if r["episode_id"] in test_ids]
    test_pre_windows = [r for r in windows if r["episode_id"] in test_ids]
    report = {"status": "completed_on_supplied_observed_events_not_independently_validated",
              "dataset_kind": source, "unseen_topology_tested": False,
              "caution": "Gateway data are actual controlled HTTP request observations, not Zeek PCAP captures or real malicious exploits",
              "seed": seed, "n_events": len(observations), "n_windows": len(windows),
              "n_episodes": len(manifest), "feature_columns": list(FEATURE_COLUMNS),
              "sources": {"manifest": str(manifest_path), "manifest_sha256": sha256(manifest_path),
                          "events": str(events_path), "events_sha256": sha256(events_path)},
              "runtime": {"python": platform.python_version(), "platform": platform.platform()}, "methods": {}}
    predictions_export = []
    for policy in ("fixed", "random", "strategic"):
        train_ids, val_ids = split_episode_ids(manifest, policy, seed)
        train_rows = [r for r in windows if r["episode_id"] in train_ids]
        val_rows = [r for r in windows if r["episode_id"] in val_ids]
        if set(r["episode_id"] for r in train_rows) & set(r["episode_id"] for r in val_rows):
            raise AssertionError("Episode overlap")
        if not train_rows or not val_rows or not test_windows:
            raise ValueError("Insufficient real observations to evaluate")
        policy_report = {"train_episodes": len(train_ids), "validation_episodes": len(val_ids),
                         "test_episodes": len(test_ids), "models": {}}
        for kind in ("rf", "isolation_forest"):
            kwargs = {}
            if kind == "rf" and trials:
                db = output / "hpo" / f"{policy}_rf.sqlite3"
                db.parent.mkdir(parents=True, exist_ok=True)
                best = tune_forest(train_rows, val_rows, seed=seed, trials=trials, db_path=db,
                                   study_name=f"{policy}_rf_v1")
                kwargs.update(best)
                policy_report.setdefault("hpo_trials", {})[kind] = best
            model = fit_baseline(train_rows, kind=kind, seed=seed, **kwargs)
            (output / "model").mkdir(parents=True, exist_ok=True)
            joblib.dump({"model": model, "feature_columns": list(FEATURE_COLUMNS), "kind": kind,
                         "policy": policy, "seed": seed}, output / "model" / f"{policy}_{kind}.joblib")
            val_pred = predict_scores(model, val_rows, kind)
            val_manifest = {eid: manifest[eid] for eid in val_ids}
            threshold = choose_validation_threshold(val_pred, val_manifest)
            if threshold is None:
                policy_report["models"][kind] = {"status": "threshold_unavailable_under_constraint", "max_validation_fp_episode_rate": .15}
                continue
            test_pred = predict_scores(model, test_windows, kind)
            metrics = episode_detection_metrics(test_pred, test_manifest, threshold)
            pre_pred = predict_scores(model, test_pre_windows, kind)
            pre_metrics = episode_detection_metrics(pre_pred, test_manifest, threshold)
            warning = early_warning_metrics(test_pred, test_manifest, threshold, persistence=1)
            warning_ci = early_warning_bootstrap_ci(warning["episode_results"], seed=seed)
            # Full score records are exported for independent audit, not fed into training.
            for p in test_pred:
                predictions_export.append({**p, "train_policy": policy, "model": kind, "threshold": threshold})
            policy_report["models"][kind] = {"status": "evaluated", "threshold_chosen_on_validation": threshold,
                                              "detection_all_windows_including_milestone": metrics,
                                              "detection_pre_milestone": pre_metrics,
                                              "early_warning_bootstrap_ci_95pct": warning_ci,
                                              "warning": {k: v for k, v in warning.items() if k != "episode_results"},
                                              "per_episode_warning": warning["episode_results"]}
        report["methods"][policy] = policy_report
    output.mkdir(parents=True, exist_ok=True)
    write_json(output / "results.json", report)
    with (output / "test_predictions.jsonl").open("w", encoding="utf-8") as fp:
        for row in predictions_export:
            fp.write(json.dumps(row, sort_keys=True) + "\n")
    # For reproducibility, store split assignments without any test labels in training sets.
    splits = {policy: {"train": sorted(split_episode_ids(manifest, policy, seed)[0]),
                       "validation": sorted(split_episode_ids(manifest, policy, seed)[1])}
              for policy in ("fixed", "random", "strategic")}
    splits["test"] = {"held_out": sorted(test_ids)}
    write_json(output / "splits.json", splits)
    return report


def main():
    p = argparse.ArgumentParser(description="Evaluate fixed/random/strategic collection under a shared held-out test")
    p.add_argument("--manifest", required=True)
    p.add_argument("--events", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--source", choices=["gateway", "zeek"], default="gateway")
    p.add_argument("--seed", type=int, default=20261112)
    p.add_argument("--trials", type=int, default=0, help="0=fast smoke only; 10+ recommended for research runs")
    p.add_argument("--n-events", type=int, default=4)
    args = p.parse_args()
    result = run_pipeline(args.manifest, args.events, args.output, args.source, args.seed, args.trials, args.n_events)
    for policy, r in result["methods"].items():
        for model, info in r["models"].items():
            print(f"{policy}/{model}: {info['status']}")
    print(f"Wrote {Path(args.output) / 'results.json'}")

if __name__ == "__main__":
    main()
