"""Verify that the numbers quoted in the Phase 3 report match the stored artefacts.

The check is deliberately mechanical: each quoted value is compared with the
value in the artefact that produced it, at the report's own rounding. A single
mismatch fails the script.
"""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path


def _load_metrics(study: Path):
    return {(r["train_policy"], r["model"]): r for r in
            csv.DictReader((study / "metrics.csv").open(encoding="utf-8"))}


def _load_ablations(study: Path):
    return {(r["train_policy"], r["model"], r["ablation"]): r for r in
            csv.DictReader((study / "ablations.csv").open(encoding="utf-8"))}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--zeek-study", required=True, type=Path)
    parser.add_argument("--gateway-study", required=True, type=Path)
    parser.add_argument("--gru-csv", required=True, type=Path)
    parser.add_argument("--audit", required=True, type=Path)
    parser.add_argument("--inventory", required=True, type=Path)
    parser.add_argument("--seed2-study", type=Path, default=None)
    parser.add_argument("--seed2-gru-csv", type=Path, default=None)
    parser.add_argument("--nd", type=int, default=3)
    args = parser.parse_args()

    z_study, g_study = args.zeek_study, args.gateway_study
    z = _load_metrics(z_study)
    g = _load_metrics(g_study)
    ab = _load_ablations(z_study)
    gru = {r["train_policy"]: r for r in csv.DictReader(args.gru_csv.open(encoding="utf-8"))}
    zres = json.loads((z_study / "results.json").read_text(encoding="utf-8"))
    gres = json.loads((g_study / "results.json").read_text(encoding="utf-8"))
    audit = json.loads(args.audit.read_text(encoding="utf-8"))
    inv = json.loads(args.inventory.read_text(encoding="utf-8"))

    failures = []
    checks = 0

    def chk(name, claimed, actual, nd=None):
        nonlocal checks
        checks += 1
        nd = args.nd if nd is None else nd
        try:
            ok = round(float(claimed), nd) == round(float(actual), nd)
        except (TypeError, ValueError):
            ok = str(claimed) == str(actual)
        if not ok:
            failures.append({"claim": name, "reported": claimed, "artifact_value": actual})

    # --- dataset and split -------------------------------------------------
    chk("episodes", 192, inv["counts"]["episodes"], 0)
    chk("gateway events", 3840, inv["counts"]["gateway_events"], 0)
    chk("pcap packets", 107628, inv["counts"]["pcap_packets"], 0)
    chk("zeek connections", 7688, inv["counts"]["zeek_conn_entries"], 0)
    chk("windows", 6336, zres["n_windows"], 0)
    chk("test episodes", 48, zres["test_episodes"], 0)
    chk("test incident episodes", 24, zres["test_incident_episodes"], 0)
    chk("test benign episodes", 24, zres["test_benign_episodes"], 0)
    chk("leakage audit passed", True, zres["leakage_audit_passed"])

    # --- sensor gate -------------------------------------------------------
    chk("evidence tag", "SENSOR_VALIDATED", audit["evidence_tag"])
    chk("bidirectional fraction", 1.0, audit["checks"]["C5"]["bidirectional_fraction"])
    chk("ambiguous joins", 0, audit["checks"]["C6"]["ambiguous_timestamp_matches"], 0)
    chk("checksum validation ignored", False, audit["checksum_validation_ignored"])
    chk("repair consistency", True, audit["zeek"]["repair_consistency"]["counts_match"])
    chk("zeek conn entries", 7688, audit["zeek"]["repaired_strict"][0]["conn_entries"], 0)

    # --- primary zeek table ------------------------------------------------
    for policy, model, cov, strict, adj, fpr, prauc, miss in [
        ("fixed", "rf", 0.958, 0.917, 0.664, 0.625, 0.863, 1),
        ("random", "rf", 0.833, 0.833, 0.567, 1.000, 0.844, 4),
        ("strategic", "rf", 1.000, 0.042, 0.627, 0.083, 1.000, 0),
        ("fixed", "rule", 0.333, 0.333, 0.116, 0.208, 0.749, 16),
    ]:
        row = z[(policy, model)]
        chk(f"{policy}/{model} coverage", cov, row["pre_milestone_coverage"])
        chk(f"{policy}/{model} strict coverage", strict, row["strict_first_alert_coverage"])
        chk(f"{policy}/{model} adjusted lead", adj, row["coverage_adjusted_mean_lead_s"])
        chk(f"{policy}/{model} false positive rate", fpr, row["false_positive_episode_rate"])
        chk(f"{policy}/{model} PR-AUC", prauc, row["episode_pr_auc"])
        chk(f"{policy}/{model} missed", miss, row["missed_incidents"], 0)
    chk("strategic/rf pre-onset alarms", 23, z[("strategic", "rf")]["pre_onset_warning_episodes"], 0)
    chk("fixed/rf pre-onset alarms", 1, z[("fixed", "rf")]["pre_onset_warning_episodes"], 0)
    chk("strategic/rf window TP", 261, z[("strategic", "rf")]["window_tp"], 0)
    chk("strategic/rf window FP", 25, z[("strategic", "rf")]["window_fp"], 0)
    chk("strategic/rf window TN", 839, z[("strategic", "rf")]["window_tn"], 0)
    chk("strategic/rf window FN", 459, z[("strategic", "rf")]["window_fn"], 0)

    # --- strata ------------------------------------------------------------
    for policy, seen, unseen in [("fixed", 1.000, 0.917), ("random", 1.000, 0.667),
                                 ("strategic", 1.000, 1.000)]:
        strata = zres["methods"][policy]["models"]["rf"]["strata"]
        chk(f"{policy}/rf seen coverage", seen, strata["seen_scenario_families"]["warning"]["pre_milestone_coverage"])
        chk(f"{policy}/rf unseen coverage", unseen, strata["unseen_scenario_family"]["warning"]["pre_milestone_coverage"])

    # --- gateway source ----------------------------------------------------
    chk("gateway strategic/rf coverage", 0.625, g[("strategic", "rf")]["pre_milestone_coverage"])
    chk("gateway random/rf coverage", 0.667, g[("random", "rf")]["pre_milestone_coverage"])
    chk("gateway strategic/rf unseen coverage", 0.25,
        gres["methods"]["strategic"]["models"]["rf"]["strata"]["unseen_scenario_family"]["warning"]["pre_milestone_coverage"])

    # --- GRU ---------------------------------------------------------------
    for policy, cov, strict, adj, fpr, prauc in [
        ("fixed", 0.875, 0.875, 0.353, 0.375, 0.933),
        ("random", 0.833, 0.833, 0.440, 0.042, 0.965),
        ("strategic", 0.500, 0.500, 0.199, 0.000, 0.869),
    ]:
        row = gru[policy]
        chk(f"gru {policy} coverage", cov, row["pre_milestone_coverage"])
        chk(f"gru {policy} strict coverage", strict, row["strict_first_alert_coverage"])
        chk(f"gru {policy} adjusted lead", adj, row["coverage_adjusted_mean_lead_s"])
        chk(f"gru {policy} false positive rate", fpr, row["false_positive_episode_rate"])
        chk(f"gru {policy} PR-AUC", prauc, row["episode_pr_auc"])

    # --- ablations ---------------------------------------------------------
    chk("fixed/rule no-temporal coverage", 0.000, ab[("fixed", "rule", "no_temporal_features")]["pre_milestone_coverage"])
    chk("fixed/rf no-temporal coverage", 0.875, ab[("fixed", "rf", "no_temporal_features")]["pre_milestone_coverage"])
    chk("random/rf no-temporal coverage", 0.667, ab[("random", "rf", "no_temporal_features")]["pre_milestone_coverage"])
    chk("strategic/rf no-temporal coverage", 1.000, ab[("strategic", "rf", "no_temporal_features")]["pre_milestone_coverage"])
    chk("fixed/rf persistence-2 coverage", 0.667, ab[("fixed", "rf", "persistence_2")]["pre_milestone_coverage"])
    chk("fixed/rf persistence-2 false positive rate", 0.125, ab[("fixed", "rf", "persistence_2")]["false_positive_episode_rate"])
    chk("random/rf persistence-2 coverage", 0.500, ab[("random", "rf", "persistence_2")]["pre_milestone_coverage"])
    chk("random/rf persistence-2 false positive rate", 0.000, ab[("random", "rf", "persistence_2")]["false_positive_episode_rate"])
    chk("strategic/rf persistence-2 coverage", 0.625, ab[("strategic", "rf", "persistence_2")]["pre_milestone_coverage"])
    chk("fixed/rf persistence-2 strict coverage", 0.917, ab[("fixed", "rf", "persistence_2")]["strict_first_alert_coverage"])

    # --- second seed replication -------------------------------------------
    if args.seed2_study:
        z2 = _load_metrics(args.seed2_study)
        res2 = json.loads((args.seed2_study / "results.json").read_text(encoding="utf-8"))
        gru2 = {r["train_policy"]: r for r in csv.DictReader(args.seed2_gru_csv.open(encoding="utf-8"))}
        chk("seed2 episodes", 192, res2["n_episodes"], 0)
        chk("seed2 test episodes", 48, res2["test_episodes"], 0)
        for policy, cov, strict, fpr, preonset in [
            ("fixed", 0.917, 0.917, 0.167, 0),
            ("random", 0.542, 0.542, 0.042, 0),
            ("strategic", 0.875, 0.875, 0.208, 0),
        ]:
            row = z2[(policy, "rf")]
            chk(f"seed2 {policy}/rf coverage", cov, row["pre_milestone_coverage"])
            chk(f"seed2 {policy}/rf strict coverage", strict, row["strict_first_alert_coverage"])
            chk(f"seed2 {policy}/rf false positive rate", fpr, row["false_positive_episode_rate"])
            chk(f"seed2 {policy}/rf pre-onset alarms", preonset, row["pre_onset_warning_episodes"], 0)
        for policy, cov, fpr in [("fixed", 1.000, 0.333), ("random", 0.917, 0.250),
                                 ("strategic", 0.750, 0.042)]:
            row = gru2[policy]
            chk(f"seed2 gru {policy} coverage", cov, row["pre_milestone_coverage"])
            chk(f"seed2 gru {policy} false positive rate", fpr, row["false_positive_episode_rate"])
            chk(f"seed2 gru {policy} pre-onset alarms", 0, row["pre_onset_warning_episodes"], 0)

    result = {"checks_performed": checks, "mismatches": failures,
              "status": "PASS" if not failures else "FAIL"}
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if not failures else 1)


if __name__ == "__main__":
    main()
