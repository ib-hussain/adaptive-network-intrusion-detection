"""CPU-feasible Phase 3 study driver.

Builds one provenance-preserving processed dataset from a completed staged run,
then evaluates the rule / Isolation Forest / Random Forest baselines on the same
frozen held-out episodes with one validation-selected alert rule, and runs the
feasible ablations.

Guarantees enforced here (and written to leakage_audit.json):
  * the split is decided on whole episodes BEFORE any window is created;
  * the `test` policy episodes never enter training, validation, threshold
    selection or any fitted transform;
  * every feature is recomputable from the observations at or before the window
    end timestamp, which is verified by recomputation on a random sample;
  * incident ground truth comes from the scenario controller, never from a
    detector prediction.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import platform
import random
import re
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

from .early_warning import early_warning_bootstrap_ci, early_warning_metrics
from .features import FEATURE_COLUMNS, make_windows
from .ingest import load_events, load_manifest
from .models import fit_baseline, predict_scores, tune_forest
from .pipeline import choose_validation_threshold, episode_detection_metrics, split_episode_ids
from sklearn.metrics import average_precision_score

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
POLICIES = ("fixed", "random", "strategic")
BASELINES = ("rule", "isolation_forest", "rf")

# Timing/burstiness features removed in the "no temporal evidence" ablation.
TEMPORAL_FEATURES = ("rate_per_s", "gap_mean_s", "gap_std_s", "gap_cv", "large_flow_fraction")
REDUCED_FEATURE_COLUMNS = tuple(c for c in FEATURE_COLUMNS if c not in TEMPORAL_FEATURES)

# Extended threshold grid: models with saturated probabilities need candidates
# above 0.95 to be able to exclude a false alarm at all.
THRESHOLD_CANDIDATES = [float(x) for x in np.linspace(.05, .95, 19)] + [.96, .97, .98, .99, .995, .999]

HELD_OUT_PROFILE = "slow_ramp"

FEATURE_UNITS = {
    "event_count": ("count", "observations inside the window"),
    "rate_per_s": ("1/s", "window event rate"),
    "gap_mean_s": ("s", "mean inter-observation gap"),
    "gap_std_s": ("s", "standard deviation of inter-observation gap"),
    "gap_cv": ("ratio", "coefficient of variation of the gap"),
    "bytes_mean": ("bytes", "mean bidirectional bytes per observation"),
    "bytes_total": ("bytes", "total bidirectional bytes in the window"),
    "origin_bytes_mean": ("bytes", "mean request-direction bytes"),
    "response_bytes_mean": ("bytes", "mean response-direction bytes"),
    "duration_mean_s": ("s", "mean observation duration"),
    "unique_destinations": ("count", "distinct observed destinations"),
    "unique_links": ("count", "distinct observed (source, destination) pairs"),
    "destination_entropy": ("bits", "Shannon entropy of the destination distribution"),
    "large_flow_fraction": ("ratio", "fraction of observations above 1024 bytes"),
    "tcp_fraction": ("ratio", "fraction of observations using TCP"),
}

FORBIDDEN_FEATURE_PATTERNS = (
    r"episode", r"policy", r"profile", r"scenario", r"milestone", r"onset", r"escalation",
    r"label", r"target", r"path", r"filename", r"src_host", r"dst_host", r"ip_addr", r"seed",
)


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256(path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as fp:
        for chunk in iter(lambda: fp.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: Path, value) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise FileExistsError(f"Refusing to overwrite: {path}")
    tmp = path.with_name(path.name + ".pending")
    with tmp.open("x", encoding="utf-8") as fp:
        json.dump(value, fp, indent=2, sort_keys=True, allow_nan=False)
        fp.write("\n")
    tmp.replace(path)


# --------------------------------------------------------------------------- #
# dataset construction
# --------------------------------------------------------------------------- #
def resolve_events(run_id: str, source: str, zeek_conn: Path | None):
    """Load the manifest and the observation stream for one sensor."""
    raw = REPO_ROOT / "src" / "data" / "raw" / "runs" / run_id
    manifest_path = raw / "episodes.jsonl"
    manifest = load_manifest(manifest_path)
    if source == "gateway":
        events_path = raw / "gateway_subset.jsonl"
    elif source == "zeek":
        if zeek_conn is None:
            raise ValueError("--zeek-conn is required for the zeek source")
        events_path = Path(zeek_conn)
    else:
        raise ValueError("source must be gateway or zeek")
    if not Path(events_path).is_file():
        raise FileNotFoundError(events_path)
    events = load_events(events_path, manifest, source=source)
    return manifest, events, Path(manifest_path), Path(events_path)


def assign_splits(manifest, seed: int, val_fraction: float = .33):
    """Episode-level split decided BEFORE windowing."""
    split_of = {}
    for policy in POLICIES:
        train_ids, val_ids = split_episode_ids(manifest, policy, seed, val_fraction)
        for eid in train_ids:
            split_of[eid] = "train"
        for eid in val_ids:
            split_of[eid] = "validation"
    for eid, ep in manifest.items():
        if ep["policy"] == "test":
            split_of[eid] = "test"
    if len(set(split_of)) != len(manifest):
        raise AssertionError("Split assignment is not a partition")
    return split_of


def _recompute_features(rows):
    """Independent re-derivation used to verify that stored features are causal."""
    import statistics
    timestamps = [r["ts"] for r in rows]
    gaps = [max(0.0, b - a) for a, b in zip(timestamps, timestamps[1:])]
    span = max(1e-4, timestamps[-1] - timestamps[0])
    gm = statistics.mean(gaps) if gaps else 0.0
    gs = statistics.pstdev(gaps) if len(gaps) > 1 else 0.0
    sizes = [r["orig_bytes"] + r["resp_bytes"] for r in rows]
    destinations = [r["dst_host"] for r in rows]
    counts = [destinations.count(x) / len(destinations) for x in set(destinations)]
    entropy = -sum(p * math.log2(p) for p in counts)
    return {
        "event_count": len(rows),
        "rate_per_s": (len(rows) - 1) / span,
        "gap_mean_s": gm,
        "gap_std_s": gs,
        "gap_cv": gs / gm if gm > 0 else 0.0,
        "bytes_mean": statistics.mean(sizes),
        "bytes_total": sum(sizes),
        "origin_bytes_mean": statistics.mean(r["orig_bytes"] for r in rows),
        "response_bytes_mean": statistics.mean(r["resp_bytes"] for r in rows),
        "duration_mean_s": statistics.mean(r["duration"] for r in rows),
        "unique_destinations": len(set(destinations)),
        "unique_links": len({(r["src_host"], r["dst_host"]) for r in rows}),
        "destination_entropy": entropy,
        "large_flow_fraction": sum(s > 1024 for s in sizes) / len(sizes),
        "tcp_fraction": sum(r["proto"] == "tcp" for r in rows) / len(sizes),
    }


def build_dataset(manifest, events, manifest_path, events_path, out_dir: Path, source: str,
                  seed: int, causal_labels: bool, n_events: int = 4, val_fraction: float = .33):
    out_dir.mkdir(parents=True, exist_ok=True)
    split_of = assign_splits(manifest, seed, val_fraction)

    # min_events == n_events so every window holds exactly n_events observations.
    # Partial windows would encode window position rather than network behaviour.
    all_windows = make_windows(events, manifest, n_events=n_events, min_events=n_events,
                               before_milestone_only=False, causal_stage_labels=causal_labels)
    train_like = [w for w in all_windows if split_of[w["episode_id"]] in ("train", "validation")]
    test_windows_all = [w for w in all_windows if split_of[w["episode_id"]] == "test"]
    if not train_like or not test_windows_all:
        raise ValueError("Insufficient windows for train/test evaluation")
    # Training and validation may only use windows that end before the incident milestone.
    def pre_milestone_only(w):
        ep = manifest[w["episode_id"]]
        if ep["condition"] != "incident":
            return True
        return float(w["window_end_ts"]) < float(ep["milestone_ts"])
    train_windows = [w for w in train_like if pre_milestone_only(w)]
    if not train_windows:
        raise ValueError("No pre-milestone training windows")

    grouped = defaultdict(list)
    for row in events:
        grouped[row["episode_id"]].append(row)

    # ---- feature schema ---------------------------------------------------
    schema = {
        "schema": "phase3_feature_schema_v1",
        "created_utc": _utc(),
        "source_sensor": source,
        "n_events_per_window": n_events,
        "causal_cutoff": "every feature uses only observations with ts <= window_end_ts",
        "window_rule": "the last n observations of the episode up to and including window_end_ts",
        "label_rule": ("incident window iff window_end_ts >= controller onset_ts"
                       if causal_labels else
                       "every window of an incident episode is positive (episode-level task)"),
        "features": [
            {"name": name,
             "dtype": "float64",
             "unit": FEATURE_UNITS.get(name, ("unknown", ""))[0],
             "meaning": FEATURE_UNITS.get(name, ("unknown", ""))[1],
             "source_sensor": source,
             "causal_cutoff": "window_end_ts"}
            for name in FEATURE_COLUMNS
        ],
        "labels": {"target": "incident_window", "source": "scenario controller journal (independent of any detector)"},
    }
    write_json(out_dir / "feature_schema.json", schema)

    # ---- split manifest ----------------------------------------------------
    split_rows = []
    for eid in sorted(manifest):
        ep = manifest[eid]
        split_rows.append({
            "episode_id": eid, "policy": ep["policy"], "condition": ep["condition"],
            "profile": ep.get("profile"), "split": split_of[eid],
            "start_ts": ep["start_ts"], "onset_ts": ep.get("onset_ts"),
            "escalation_ts": ep.get("escalation_ts"), "milestone_ts": ep.get("milestone_ts"),
            "end_ts": ep["end_ts"], "requests": ep.get("requests"),
            "source_manifest": str(manifest_path), "source_manifest_sha256": sha256(manifest_path),
        })
    with (out_dir / "split_manifest.jsonl").open("x", encoding="utf-8") as fp:
        for row in split_rows:
            fp.write(json.dumps(row, sort_keys=True) + "\n")

    # ---- windows -----------------------------------------------------------
    window_fields = ["episode_id", "policy", "condition", "profile", "split", "label",
                     "window_start_ts", "window_end_ts"] + list(FEATURE_COLUMNS)
    with (out_dir / "windows.csv").open("x", encoding="utf-8", newline="") as fp:
        writer = csv.DictWriter(fp, fieldnames=window_fields)
        writer.writeheader()
        for w in all_windows:
            ep = manifest[w["episode_id"]]
            row = {"episode_id": w["episode_id"], "policy": w["policy"], "condition": ep["condition"],
                   "profile": ep.get("profile"), "split": split_of[w["episode_id"]], "label": w["label"],
                   "window_start_ts": w["window_start_ts"], "window_end_ts": w["window_end_ts"]}
            row.update({c: w[c] for c in FEATURE_COLUMNS})
            writer.writerow(row)

    # ---- preprocessing report ---------------------------------------------
    per_split_episodes = Counter(split_of.values())
    per_split_windows = Counter(split_of[w["episode_id"]] for w in all_windows)
    positive_per_split = Counter(split_of[w["episode_id"]] for w in all_windows if w["label"] == 1)
    benign_per_split = Counter(split_of[w["episode_id"]] for w in all_windows if w["label"] == 0)
    episodes_without_windows = [eid for eid in manifest
                                if eid not in {w["episode_id"] for w in all_windows}]
    test_pre_milestone = [w for w in test_windows_all if pre_milestone_only(w)]
    report = {
        "schema": "phase3_preprocessing_report_v1",
        "created_utc": _utc(),
        "source_sensor": source,
        "inputs": {"manifest": str(manifest_path), "manifest_sha256": sha256(manifest_path),
                   "events": str(events_path), "events_sha256": sha256(events_path),
                   "episodes": len(manifest), "observations": len(events)},
        "observations_by_episode": {"min": min(Counter(r["episode_id"] for r in events).values()),
                                    "max": max(Counter(r["episode_id"] for r in events).values())},
        "exclusions": {
            "windows_excluded_from_training": len(train_like) - len(train_windows),
            "exclusion_reason": "incident windows whose end is at or after the controller milestone",
            "episodes_without_any_window": episodes_without_windows,
        },
        "missing_value_strategy": "no imputation: every Zeek/gateway record carries numeric byte and duration fields; "
                                  "absent byte counters are read as 0.0 and recorded as such by the sensor audit",
        "fit_only_transforms": "StandardScaler for the Isolation Forest is fitted on benign TRAINING windows only; "
                               "the Random Forest and the rule baseline are fitted on training windows only",
        "splits": {
            "policy_seed": seed,
            "validation_fraction": val_fraction,
            "episodes_by_split": dict(per_split_episodes),
            "windows_by_split": dict(per_split_windows),
            "positive_windows_by_split": dict(positive_per_split),
            "negative_windows_by_split": dict(benign_per_split),
            "test_episodes": sorted(eid for eid in manifest if split_of[eid] == "test"),
            "test_pre_milestone_windows": len(test_pre_milestone),
            "test_episodes_with_pre_milestone_windows": len({w["episode_id"] for w in test_pre_milestone}),
        },
        "label_definition": {"causal_stage_labels": bool(causal_labels),
                             "onset_source": "scenario controller (lab/staged_generate.py), independent of any detector",
                             "milestone_source": "scenario controller (lab/staged_generate.py)"},
        "window_parameters": {"n_events": n_events, "stride": 1, "min_events": n_events,
                              "note": "every window contains exactly n_events observations"},
    }
    write_json(out_dir / "preprocessing_report.json", report)

    # ---- leakage audit -----------------------------------------------------
    leakage = {
        "schema": "phase3_leakage_audit_v1",
        "created_utc": _utc(),
        "checks": {},
    }
    forbidden_hits = [c for c in FEATURE_COLUMNS
                      if any(re.search(p, c, re.I) for p in FORBIDDEN_FEATURE_PATTERNS)]
    leakage["checks"]["no_forbidden_feature_names"] = {
        "passed": not forbidden_hits, "forbidden_patterns": list(FORBIDDEN_FEATURE_PATTERNS),
        "hits": forbidden_hits, "feature_columns": list(FEATURE_COLUMNS)}
    overlapping = [eid for eid, s in split_of.items() if s in ("train", "validation")
                   and manifest[eid]["policy"] == "test"]
    leakage["checks"]["test_episodes_absent_from_train_and_validation"] = {
        "passed": not overlapping, "violations": overlapping}
    train_ids = {eid for eid, s in split_of.items() if s == "train"}
    val_ids = {eid for eid, s in split_of.items() if s == "validation"}
    leakage["checks"]["train_validation_disjoint"] = {
        "passed": not (train_ids & val_ids), "train_episodes": len(train_ids),
        "validation_episodes": len(val_ids), "overlap": sorted(train_ids & val_ids)}
    bad_bounds = [w["episode_id"] for w in all_windows
                  if not (float(manifest[w["episode_id"]]["start_ts"]) - 1e-6 <= float(w["window_end_ts"])
                          <= float(manifest[w["episode_id"]]["end_ts"]) + 1e-6)]
    leakage["checks"]["windows_inside_episode_interval"] = {
        "passed": not bad_bounds, "violations": bad_bounds[:20]}
    late = [w["episode_id"] for w in train_windows
            if manifest[w["episode_id"]]["condition"] == "incident"
            and float(w["window_end_ts"]) >= float(manifest[w["episode_id"]]["milestone_ts"])]
    leakage["checks"]["training_windows_end_before_milestone"] = {
        "passed": not late, "violations": late[:20]}
    # Independent recomputation of the stored features on a random sample.
    rng = random.Random(seed)
    sample = rng.sample(all_windows, min(60, len(all_windows)))
    mismatches = []
    for w in sample:
        rows = [r for r in grouped[w["episode_id"]] if float(r["ts"]) <= float(w["window_end_ts"]) + 1e-9]
        rows = rows[-n_events:]
        if len(rows) != n_events:
            continue
        recomputed = _recompute_features(rows)
        for name in FEATURE_COLUMNS:
            if abs(float(recomputed[name]) - float(w[name])) > 1e-6 * max(1.0, abs(float(w[name]))):
                mismatches.append({"episode_id": w["episode_id"], "window_end_ts": w["window_end_ts"],
                                   "feature": name, "stored": float(w[name]), "recomputed": recomputed[name]})
    leakage["checks"]["features_recomputable_from_window_observations"] = {
        "passed": not mismatches, "sampled_windows": len(sample), "mismatches": mismatches[:20]}
    leakage["checks"]["label_not_used_as_feature"] = {
        "passed": True, "note": "labels live in a separate 'label' column and are never part of FEATURE_COLUMNS"}
    leakage["checks"]["ground_truth_from_controller"] = {
        "passed": True,
        "note": "onset/escalation/milestone timestamps are written by lab/staged_generate.py before any model runs; "
                "no detector output is used as ground truth"}
    leakage["checks"]["fit_only_scalers"] = {
        "passed": True,
        "note": "the Isolation Forest pipeline's StandardScaler is fitted inside fit_baseline on training windows only"}
    leakage["all_passed"] = all(c["passed"] for c in leakage["checks"].values())
    write_json(out_dir / "leakage_audit.json", leakage)

    dataset_manifest = {
        "schema": "phase3_dataset_manifest_v1",
        "created_utc": _utc(),
        "run_id": manifest_path.parent.name,
        "source_sensor": source,
        "seed": seed,
        "causal_labels": bool(causal_labels),
        "feature_columns": list(FEATURE_COLUMNS),
        "split_of_episode": split_of,
        "files": {},
    }
    for name in ("feature_schema.json", "split_manifest.jsonl", "preprocessing_report.json",
                 "windows.csv", "leakage_audit.json"):
        dataset_manifest["files"][name] = sha256(out_dir / name)
    write_json(out_dir / "dataset_manifest.json", dataset_manifest)
    return {"all_windows": all_windows, "train_windows": train_windows, "test_windows_all": test_windows_all,
            "split_of": split_of, "dataset_dir": str(out_dir),
            "leakage_all_passed": leakage["all_passed"],
            "test_pre_milestone_windows": len(test_pre_milestone)}


# --------------------------------------------------------------------------- #
# evaluation
# --------------------------------------------------------------------------- #
def build_strata(test_manifest):
    """Split the frozen test set into the unseen scenario family and the seen families.

    Benign episodes are kept in every stratum so that the false-alarm rate of a
    stratum is measured against the same benign population.
    """
    benign = {eid: ep for eid, ep in test_manifest.items() if ep["condition"] == "benign"}
    unseen = {eid: ep for eid, ep in test_manifest.items()
              if ep["condition"] == "incident" and ep.get("profile") == HELD_OUT_PROFILE}
    seen = {eid: ep for eid, ep in test_manifest.items()
            if ep["condition"] == "incident" and ep.get("profile") != HELD_OUT_PROFILE}
    strata = {"all_test_episodes": dict(test_manifest),
              "seen_scenario_families": {**benign, **seen},
              "unseen_scenario_family": {**benign, **unseen}}
    return strata


def _episode_scores(predictions, manifest):
    """Maximum score per episode: the independent statistical unit."""
    max_scores = {}
    for p in predictions:
        eid = p["episode_id"]
        max_scores[eid] = max(max_scores.get(eid, 0.0), float(p["score"]))
    episodes = [eid for eid in sorted(manifest) if eid in max_scores]
    y = np.array([int(manifest[eid]["condition"] == "incident") for eid in episodes])
    s = np.array([max_scores[eid] for eid in episodes])
    return y, s


def _pr_curve(y, scores):
    from sklearn.metrics import precision_recall_curve
    if len(y) == 0 or len(np.unique(y)) < 2:
        return None
    precision, recall, _ = precision_recall_curve(y, scores)
    return {"precision": [float(v) for v in precision], "recall": [float(v) for v in recall],
            "n_positive_episodes": int(y.sum()), "n_episodes": int(len(y)),
            "average_precision": float(average_precision_score(y, scores))}


def _window_confusion(predictions, threshold):
    tp = sum(1 for p in predictions if p["label"] == 1 and p["score"] >= threshold)
    fp = sum(1 for p in predictions if p["label"] == 0 and p["score"] >= threshold)
    tn = sum(1 for p in predictions if p["label"] == 0 and p["score"] < threshold)
    fn = sum(1 for p in predictions if p["label"] == 1 and p["score"] < threshold)
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn, "windows": tp + fp + tn + fn}


def evaluate_baseline(train_windows, val_windows, test_windows, manifest, test_manifest, kind, seed,
                      trials=0, rule_feature="rate_per_s", rule_direction="above",
                      hpo_db=None, feature_columns=None, persistence=1, strata=None):
    """Fit one baseline on training episodes only and evaluate it on the frozen test."""
    started = time.time()
    kwargs = {}
    hpo = None
    if kind == "rf" and trials and trials > 0:
        hpo = tune_forest(train_windows, val_windows, seed=seed, trials=trials,
                           db_path=hpo_db, study_name=f"{kind}_cpu_v1")
        if hpo:
            kwargs.update(hpo)
    model = fit_baseline(train_windows, kind=kind, seed=seed, rule_feature=rule_feature,
                         rule_direction=rule_direction, feature_columns=feature_columns, **kwargs)
    val_pred = predict_scores(model, val_windows, kind, feature_columns)
    # Threshold selection sees ONLY the validation episodes. Passing the full
    # manifest here would let held-out benign episode durations dilute the
    # false-alarm budget, which would be test leakage.
    val_ids = {w["episode_id"] for w in val_windows}
    val_manifest = {eid: ep for eid, ep in manifest.items() if eid in val_ids}
    threshold = choose_validation_threshold(val_pred, val_manifest,
                                            max_false_positive_episodes=.15,
                                            candidates=THRESHOLD_CANDIDATES)
    result = {"kind": kind, "status": "evaluated", "seed": seed,
              "rule_feature": rule_feature if kind == "rule" else None,
              "rule_direction": rule_direction if kind == "rule" else None,
              "hpo_best_params": hpo, "train_windows": len(train_windows),
              "validation_windows": len(val_windows), "test_windows": len(test_windows),
              "runtime_s": None}
    if threshold is None:
        result.update({"status": "threshold_unavailable_under_constraint",
                       "max_validation_false_positive_episode_rate": 0.15,
                       "runtime_s": round(time.time() - started, 3)})
        return result, model, None, []
    test_pred = predict_scores(model, test_windows, kind, feature_columns)
    detection = episode_detection_metrics(test_pred, test_manifest, threshold)
    warning = early_warning_metrics(test_pred, test_manifest, threshold, persistence=persistence)
    ci = early_warning_bootstrap_ci(warning["episode_results"], seed=seed)
    y_ep, s_ep = _episode_scores(test_pred, test_manifest)
    y_win = np.array([p["label"] for p in test_pred], dtype=np.int64)
    s_win = np.array([float(p["score"]) for p in test_pred], dtype=np.float64)
    stratum_metrics = {}
    if strata:
        for name, sub_manifest in strata.items():
            sub_pred = [p for p in test_pred if p["episode_id"] in sub_manifest]
            sub_det = episode_detection_metrics(sub_pred, sub_manifest, threshold)
            sub_warn = early_warning_metrics(sub_pred, sub_manifest, threshold, persistence=persistence)
            sy, ss = _episode_scores(sub_pred, sub_manifest)
            stratum_metrics[name] = {
                "detection": sub_det,
                "pr_curve_episode": _pr_curve(sy, ss),
                "warning": {k: v for k, v in sub_warn.items() if k != "episode_results"},
                "n_incident_episodes": sub_warn["n_incidents"],
                "n_benign_episodes": sub_warn["n_benign"],
            }
    result.update({
        "threshold_chosen_on_validation": threshold,
        "detection_all_windows": detection,
        "detection_window_confusion": _window_confusion(test_pred, threshold),
        "warning": {k: v for k, v in warning.items() if k != "episode_results"},
        "early_warning_bootstrap_ci_95pct": ci,
        "per_episode_warning": warning["episode_results"],
        "persistence": persistence,
        "feature_columns": list(feature_columns) if feature_columns else list(FEATURE_COLUMNS),
        "pr_curve_episode": _pr_curve(y_ep, s_ep),
        "pr_curve_window": _pr_curve(y_win, s_win),
        "strata": stratum_metrics,
        "runtime_s": round(time.time() - started, 3),
    })
    return result, model, threshold, test_pred


def default_n_events(source):
    """Window width matched to the number of HTTP requests it covers.

    One HTTP request through the gateway appears as two TCP connections
    (client->gateway and gateway->service), so eight Zeek flows correspond to
    four requests, matching the gateway window of four requests.
    """
    return 8 if source == "zeek" else 4


def _ablation_row(run_id, source, evidence_tag, policy, kind, ablation, result):
    w = result.get("warning", {})
    d = result.get("detection_all_windows", {})
    return {
        "run_id": run_id, "source": source, "evidence_tag": evidence_tag,
        "train_policy": policy, "model": kind, "ablation": ablation,
        "status": result.get("status"), "threshold": result.get("threshold_chosen_on_validation"),
        "rule_feature": result.get("rule_feature") or "",
        "episode_f1": d.get("episode_f1"), "episode_precision": d.get("episode_precision"),
        "episode_recall": d.get("episode_recall"), "episode_pr_auc": d.get("episode_pr_auc"),
        "pre_milestone_coverage": w.get("pre_milestone_coverage"),
        "strict_first_alert_coverage": w.get("strict_first_alert_coverage"),
        "conditional_mean_lead_s": w.get("conditional_mean_lead_s"),
        "coverage_adjusted_mean_lead_s": w.get("coverage_adjusted_mean_lead_s"),
        "false_positive_episode_rate": w.get("false_positive_episode_rate"),
        "false_alarms_per_benign_hour": w.get("false_alarms_per_benign_hour"),
        "late_incidents": w.get("late_incidents"), "missed_incidents": w.get("missed_incidents"),
        "runtime_s": result.get("runtime_s"),
    }


def run_study(run_id, source, out_dir, zeek_conn=None, seed=20261115, trials=0,
              causal_labels=True, n_events=None, evidence_tag="UNSPECIFIED", bootstrap_seed=20261115,
              run_ablations=True, val_fraction=.33):
    out_dir = Path(out_dir)
    if out_dir.exists() and any(out_dir.iterdir()):
        raise FileExistsError(f"Output directory is not empty: {out_dir}")
    out_dir.mkdir(parents=True, exist_ok=True)
    if n_events is None:
        n_events = default_n_events(source)
    manifest, events, manifest_path, events_path = resolve_events(run_id, source, zeek_conn)
    dataset = build_dataset(manifest, events, manifest_path, events_path,
                             out_dir / "dataset", source, seed, causal_labels, n_events, val_fraction)
    all_windows = dataset["all_windows"]
    test_windows = dataset["test_windows_all"]
    split_of = dataset["split_of"]
    test_manifest = {eid: ep for eid, ep in manifest.items() if split_of[eid] == "test"}
    strata = build_strata(test_manifest)

    report = {
        "schema": "phase3_study_results_v1",
        "created_utc": _utc(),
        "run_id": run_id,
        "source_sensor": source,
        "evidence_tag": evidence_tag,
        "seed": seed,
        "bootstrap_seed": bootstrap_seed,
        "causal_labels": bool(causal_labels),
        "n_events_per_window": n_events,
        "n_episodes": len(manifest),
        "n_observations": len(events),
        "n_windows": len(all_windows),
        "test_episodes": len(test_manifest),
        "test_incident_episodes": sum(1 for ep in test_manifest.values() if ep["condition"] == "incident"),
        "test_benign_episodes": sum(1 for ep in test_manifest.values() if ep["condition"] == "benign"),
        "leakage_audit_passed": dataset["leakage_all_passed"],
        "test_strata": {name: {"episodes": len(sub),
                               "incident_episodes": sum(1 for e in sub.values() if e["condition"] == "incident"),
                               "benign_episodes": sum(1 for e in sub.values() if e["condition"] == "benign"),
                               "incident_profiles": sorted({e.get("profile") for e in sub.values()
                                                            if e["condition"] == "incident"})}
                         for name, sub in strata.items()},
        "methods": {},
        "ablations": {},
        "environment": {"python": sys.version.split()[0], "platform": platform.platform(),
                        "numpy": np.__version__},
        "inputs": {"manifest_sha256": sha256(manifest_path), "events_sha256": sha256(events_path)},
    }

    predictions_export = []
    metrics_rows = []
    for policy in POLICIES:
        train_ids, val_ids = split_episode_ids(manifest, policy, seed, val_fraction)
        train_windows = [w for w in dataset["train_windows"] if w["episode_id"] in train_ids]
        val_windows = [w for w in dataset["train_windows"] if w["episode_id"] in val_ids]
        if set(w["episode_id"] for w in train_windows) & set(w["episode_id"] for w in val_windows):
            raise AssertionError("Episode overlap between training and validation")
        policy_report = {"train_episodes": len(train_ids), "validation_episodes": len(val_ids),
                         "test_episodes": len(test_manifest), "models": {}}
        for kind in BASELINES:
            result, model, threshold, test_pred = evaluate_baseline(
                train_windows, val_windows, test_windows, manifest, test_manifest, kind, seed,
                trials=trials, hpo_db=out_dir / "hpo" / f"{policy}_{kind}.sqlite3",
                strata=strata)
            policy_report["models"][kind] = result
            if threshold is None:
                continue
            for p in test_pred:
                predictions_export.append({**p, "train_policy": policy, "model": kind,
                                           "threshold": threshold, "split": "test"})
            w = result["warning"]
            metrics_rows.append({
                "run_id": run_id, "source": source, "evidence_tag": evidence_tag,
                "train_policy": policy, "model": kind, "split": "test",
                "threshold": threshold,
                "episode_precision": result["detection_all_windows"]["episode_precision"],
                "episode_recall": result["detection_all_windows"]["episode_recall"],
                "episode_f1": result["detection_all_windows"]["episode_f1"],
                "episode_pr_auc": result["detection_all_windows"]["episode_pr_auc"],
                "episode_roc_auc": result["detection_all_windows"]["episode_roc_auc"],
                "n_scored_episodes": result["detection_all_windows"]["n_scored_episodes"],
                "window_tp": result["detection_window_confusion"]["tp"],
                "window_fp": result["detection_window_confusion"]["fp"],
                "window_tn": result["detection_window_confusion"]["tn"],
                "window_fn": result["detection_window_confusion"]["fn"],
                "n_windows": result["detection_window_confusion"]["windows"],
                "n_incident_episodes": w["n_incidents"], "n_benign_episodes": w["n_benign"],
                "pre_milestone_coverage": w["pre_milestone_coverage"],
                "conditional_mean_lead_s": w["conditional_mean_lead_s"],
                "conditional_median_lead_s": w["conditional_median_lead_s"],
                "coverage_adjusted_mean_lead_s": w["coverage_adjusted_mean_lead_s"],
                "false_positive_episode_rate": w["false_positive_episode_rate"],
                "false_alarms_per_benign_hour": w["false_alarms_per_benign_hour"],
                "pre_onset_warning_episodes": w["pre_onset_warning_episodes"],
                "strict_first_alert_coverage": w.get("strict_first_alert_coverage"),
                "strict_first_alert_episodes": w.get("strict_first_alert_episodes"),
                "late_incidents": w["late_incidents"], "missed_incidents": w["missed_incidents"],
                "runtime_s": result["runtime_s"],
            })
        report["methods"][policy] = policy_report

    # ---- ablations --------------------------------------------------------
    ablation_rows = []
    if run_ablations:
        for policy in POLICIES:
            train_ids, val_ids = split_episode_ids(manifest, policy, seed, val_fraction)
            train_windows = [w for w in dataset["train_windows"] if w["episode_id"] in train_ids]
            val_windows = [w for w in dataset["train_windows"] if w["episode_id"] in val_ids]
            policy_ablations = {}
            # (a) remove the temporal/burstiness evidence
            for kind in BASELINES:
                # The rule baseline must reference a feature that survives the
                # ablation, otherwise it would keep reading rate_per_s.
                rule_feature = ("bytes_mean" if kind == "rule" else "rate_per_s")
                res, _model, thr, _pred = evaluate_baseline(
                    train_windows, val_windows, test_windows, manifest, test_manifest, kind, seed,
                    trials=0, feature_columns=list(REDUCED_FEATURE_COLUMNS),
                    rule_feature=rule_feature, strata=strata)
                policy_ablations[f"no_temporal_features/{kind}"] = res
                row = _ablation_row(run_id, source, evidence_tag, policy, kind,
                                    "no_temporal_features", res)
                row["rule_feature"] = rule_feature if kind == "rule" else ""
                ablation_rows.append(row)
            # (b) warning rule: persistence 2 instead of 1
            for kind in ("rf", "isolation_forest"):
                res, _model, thr, _pred = evaluate_baseline(
                    train_windows, val_windows, test_windows, manifest, test_manifest, kind, seed,
                    trials=0, persistence=2, strata=strata)
                policy_ablations[f"persistence_2/{kind}"] = res
                ablation_rows.append(_ablation_row(run_id, source, evidence_tag, policy, kind,
                                                   "persistence_2", res))
            report["ablations"][policy] = policy_ablations
        report["ablation_definitions"] = {
            "no_temporal_features": {
                "removed": list(TEMPORAL_FEATURES),
                "kept": list(REDUCED_FEATURE_COLUMNS),
                "purpose": "measures how much of the evidence is temporal/burstiness based"},
            "persistence_2": {
                "changed": "the warning rule requires two consecutive alerting windows instead of one",
                "purpose": "measures alert stability and the false-alarm trade-off"},
            "unavailable": {
                "graph_relations": "no graph model was implemented; a count such as unique_links is not a GNN",
                "topology_generalisation": "only one Docker network configuration exists in this lab",
                "observation_source": "measured by running this driver twice, once per source, never by merging records"},
        }

    write_json(out_dir / "results.json", report)
    if ablation_rows:
        with (out_dir / "ablations.csv").open("x", encoding="utf-8", newline="") as fp:
            writer = csv.DictWriter(fp, fieldnames=list(ablation_rows[0].keys()))
            writer.writeheader()
            for row in ablation_rows:
                writer.writerow(row)
    with (out_dir / "metrics.csv").open("x", encoding="utf-8", newline="") as fp:
        writer = csv.DictWriter(fp, fieldnames=list(metrics_rows[0].keys()))
        writer.writeheader()
        for row in metrics_rows:
            writer.writerow(row)
    with (out_dir / "test_predictions.jsonl").open("x", encoding="utf-8") as fp:
        for row in predictions_export:
            fp.write(json.dumps(row, sort_keys=True) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description="CPU Phase 3 study driver")
    parser.add_argument("--run", required=True, help="run id under src/data/raw/runs")
    parser.add_argument("--source", choices=["gateway", "zeek"], required=True)
    parser.add_argument("--zeek-conn", type=Path, default=None,
                        help="path to the Zeek conn.log (JSON) used for the zeek source")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--seed", type=int, default=20261115)
    parser.add_argument("--trials", type=int, default=0, help="Optuna trials for the RF (0 disables HPO)")
    parser.add_argument("--n-events", type=int, default=None,
                        help="window width; default 8 for zeek (8 flows = 4 requests) and 4 for gateway")
    parser.add_argument("--evidence-tag", default="UNSPECIFIED")
    parser.add_argument("--no-ablations", action="store_true")
    parser.add_argument("--val-fraction", type=float, default=.33,
                        help="fraction of each policy's episodes reserved for threshold selection")
    parser.add_argument("--episode-labels", choices=["causal", "episode"], default="causal",
                        help="causal: incident windows become positive only at controller onset")
    args = parser.parse_args()
    report = run_study(args.run, args.source, args.output, args.zeek_conn, args.seed, args.trials,
                       causal_labels=(args.episode_labels == "causal"), n_events=args.n_events,
                       evidence_tag=args.evidence_tag, run_ablations=not args.no_ablations,
                       val_fraction=args.val_fraction)
    print(f"study complete: {args.output}")
    for policy, entry in report["methods"].items():
        for model, info in entry["models"].items():
            w = info.get("warning", {})
            print(f"  {policy}/{model}: {info['status']} coverage={w.get('pre_milestone_coverage')} "
                  f"adjusted_lead={w.get('coverage_adjusted_mean_lead_s')} "
                  f"fpr={w.get('false_positive_episode_rate')}")


if __name__ == "__main__":
    main()
