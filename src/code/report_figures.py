"""Report figures generated directly from the saved study metrics.

No figure is hand-edited and no number is invented: every panel is drawn from
`results.json` / `metrics.csv` produced by `src.code.study`, and the exact
source data is written next to each figure so the plot can be reproduced.
"""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch

POLICY_LABEL = {"fixed": "fixed", "random": "random", "strategic": "strategic"}
MODEL_LABEL = {"rule": "rule/rate", "isolation_forest": "Isolation Forest", "rf": "Random Forest"}
STRATUM_LABEL = {"all_test_episodes": "all test episodes",
                 "seen_scenario_families": "seen scenario families",
                 "unseen_scenario_family": "unseen family (slow_ramp)"}


def _load(results_path: Path):
    report = json.loads(results_path.read_text(encoding="utf-8"))
    metrics = []
    csv_path = results_path.parent / "metrics.csv"
    if csv_path.is_file():
        with csv_path.open(encoding="utf-8") as fp:
            metrics = list(csv.DictReader(fp))
    return report, metrics


def _write_data(output: Path, name: str, payload) -> Path:
    path = output / f"{name}.data.json"
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _caption(fig, run_id, tag, extra):
    fig.text(0.01, 0.005, f"run={run_id} | evidence={tag} | {extra}", fontsize=7, ha="left", va="bottom")


def fig_dataset_composition(report, inventory, output: Path) -> str:
    counts = inventory["counts"]
    policies = list(counts["episodes_by_policy"].keys())
    benign = [counts["episodes_by_policy"].get(p, 0) - counts["episodes_by_condition"].get("benign", 0)
              for p in policies]
    fig, axes = plt.subplots(1, 2, figsize=(11, 4.2))
    ax = axes[0]
    inc = [counts["episodes_by_policy"][p] - b for p, b in zip(policies, benign)]
    ax.bar(policies, benign, label="benign", color="#5B8FF9")
    ax.bar(policies, inc, bottom=benign, label="incident", color="#F6BD16")
    ax.set_ylabel("episodes")
    ax.set_title("Episodes by collection policy")
    ax.legend()
    ax = axes[1]
    prof = counts["episodes_by_profile"]
    names = sorted(prof)
    ax.bar(names, [prof[n] for n in names], color="#5AD8A6")
    ax.set_ylabel("episodes")
    ax.set_title("Episodes by scenario profile")
    ax.tick_params(axis="x", labelrotation=30)
    fig.tight_layout()
    _caption(fig, report["run_id"], report["evidence_tag"],
             f"episodes={counts['episodes']} requests={counts['requests_in_manifest']} "
             f"gateway_events={counts['gateway_events']}")
    path = output / "fig01_dataset_composition.png"
    fig.savefig(path, dpi=160, bbox_inches="tight")
    plt.close(fig)
    _write_data(output, "fig01_dataset_composition", counts)
    return str(path)


def fig_pr_curves(report, output: Path) -> str:
    fig, axes = plt.subplots(1, 3, figsize=(13, 4.2))
    for ax, kind in zip(axes, ("rule", "isolation_forest", "rf")):
        drew = False
        for policy, entry in report["methods"].items():
            info = entry["models"].get(kind, {})
            curve = info.get("pr_curve_episode")
            if not curve:
                continue
            ax.step(curve["recall"], curve["precision"], where="post",
                    label=f"{POLICY_LABEL.get(policy, policy)} (AP={curve['average_precision']:.3f})")
            drew = True
        ax.set_xlabel("recall")
        ax.set_ylabel("precision")
        ax.set_title(f"{MODEL_LABEL.get(kind, kind)} - episode-level PR")
        ax.set_xlim(0, 1)
        ax.set_ylim(0, 1.02)
        ax.grid(alpha=.25)
        if drew:
            ax.legend(fontsize=7)
        else:
            ax.text(.5, .5, "no valid class support", ha="center", va="center", transform=ax.transAxes)
    fig.tight_layout()
    _caption(fig, report["run_id"], report["evidence_tag"],
             f"source_sensor={report['source_sensor']} test_episodes={report['test_episodes']}")
    path = output / "fig02_pr_curves.png"
    fig.savefig(path, dpi=160, bbox_inches="tight")
    plt.close(fig)
    _write_data(output, "fig02_pr_curves",
                {p: {m: e["models"][m].get("pr_curve_episode") for m in e["models"]}
                 for p, e in report["methods"].items()})
    return str(path)


def fig_warning_coverage(report, output: Path) -> str:
    labels, coverage, fpr, cov_lo, cov_hi = [], [], [], [], []
    for policy, entry in report["methods"].items():
        for kind, info in entry["models"].items():
            if info.get("status") != "evaluated":
                continue
            w = info["warning"]
            if w.get("pre_milestone_coverage") is None:
                continue
            labels.append(f"{POLICY_LABEL.get(policy, policy)}\n{MODEL_LABEL.get(kind, kind)}")
            coverage.append(w["pre_milestone_coverage"])
            fpr.append(w["false_positive_episode_rate"] or 0.0)
            ci = (info.get("early_warning_bootstrap_ci_95pct") or {}).get("pre_milestone_coverage")
            cov_lo.append(ci[0] if ci else np.nan)
            cov_hi.append(ci[1] if ci else np.nan)
    fig, ax = plt.subplots(figsize=(max(8, len(labels) * 1.25), 4.6))
    x = np.arange(len(labels))
    ax.bar(x - .2, coverage, .38, label="pre-milestone warning coverage", color="#5B8FF9")
    ax.bar(x + .2, fpr, .38, label="false-positive episode rate", color="#F6BD16")
    err = np.vstack([np.clip(np.array(cov_lo) - np.array(coverage), 0, None),
                      np.clip(np.array(cov_hi) - np.array(coverage), 0, None)])
    ax.errorbar(x - .2, coverage, yerr=err, fmt="none", ecolor="#333333", capsize=3, linewidth=1)
    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=7)
    ax.set_ylim(0, 1.02)
    ax.set_ylabel("rate")
    ax.set_title("Valid early warning versus false alarms on the frozen test set")
    ax.legend(fontsize=8)
    ax.grid(axis="y", alpha=.25)
    fig.tight_layout()
    _caption(fig, report["run_id"], report["evidence_tag"],
             f"source_sensor={report['source_sensor']} "
             f"test_incident_episodes={report['test_incident_episodes']} "
             f"test_benign_episodes={report['test_benign_episodes']} error bars=episode bootstrap 95% CI")
    path = output / "fig03_warning_coverage.png"
    fig.savefig(path, dpi=160, bbox_inches="tight")
    plt.close(fig)
    _write_data(output, "fig03_warning_coverage",
                {"labels": labels, "coverage": coverage, "false_positive_episode_rate": fpr,
                 "coverage_ci95_low": cov_lo, "coverage_ci95_high": cov_hi})
    return str(path)


def fig_policy_comparison(report, output: Path) -> str:
    policies = list(report["methods"].keys())
    kinds = sorted({k for e in report["methods"].values() for k in e["models"]})
    measures = [("coverage_adjusted_mean_lead_s", "coverage-adjusted mean lead (s)"),
                ("pre_milestone_coverage", "pre-milestone warning coverage"),
                ("strict_first_alert_coverage", "strict first-alert coverage"),
                ("false_positive_episode_rate", "false-positive episode rate")]
    fig, axes = plt.subplots(1, 4, figsize=(17.5, 4.3))
    payload = {}
    for ax, (key, title) in zip(axes, measures):
        width = 0.8 / max(1, len(kinds))
        for i, kind in enumerate(kinds):
            values, los, his = [], [], []
            for policy in policies:
                info = report["methods"][policy]["models"].get(kind, {})
                w = info.get("warning", {})
                value = w.get(key)
                values.append(np.nan if value is None else float(value))
                ci = (info.get("early_warning_bootstrap_ci_95pct") or {}).get(key)
                los.append(float(ci[0]) if ci else np.nan)
                his.append(float(ci[1]) if ci else np.nan)
            positions = np.arange(len(policies)) + (i - (len(kinds) - 1) / 2) * width
            ax.bar(positions, values, width, label=MODEL_LABEL.get(kind, kind))
            if not np.all(np.isnan(los)):
                err = np.vstack([np.clip(np.array(los) - np.array(values), 0, None),
                                 np.clip(np.array(his) - np.array(values), 0, None)])
                ax.errorbar(positions, values, yerr=err, fmt="none", ecolor="#333333", capsize=2, linewidth=.8)
            payload.setdefault(key, {})[kind] = {"values": values, "ci_low": los, "ci_high": his}
        ax.set_xticks(np.arange(len(policies)))
        ax.set_xticklabels([POLICY_LABEL.get(p, p) for p in policies])
        ax.set_title(title)
        ax.grid(axis="y", alpha=.25)
    axes[0].legend(fontsize=8)
    fig.tight_layout()
    _caption(fig, report["run_id"], report["evidence_tag"],
             f"source_sensor={report['source_sensor']} training policy on x-axis, error bars=episode bootstrap 95% CI")
    path = output / "fig04_policy_comparison.png"
    fig.savefig(path, dpi=160, bbox_inches="tight")
    plt.close(fig)
    _write_data(output, "fig04_policy_comparison", payload)
    return str(path)


def fig_error_analysis(report, output: Path) -> str:
    labels, early, late, missed, false_alarm = [], [], [], [], []
    for policy, entry in report["methods"].items():
        for kind, info in entry["models"].items():
            if info.get("status") != "evaluated":
                continue
            w = info["warning"]
            labels.append(f"{POLICY_LABEL.get(policy, policy)}/{MODEL_LABEL.get(kind, kind)}")
            early.append(w["n_incidents"] - w["late_incidents"] - w["missed_incidents"])
            late.append(w["late_incidents"])
            missed.append(w["missed_incidents"])
            false_alarm.append(round((w["false_positive_episode_rate"] or 0) * w["n_benign"]))
    fig, ax = plt.subplots(figsize=(max(8, len(labels) * 1.1), 4.4))
    x = np.arange(len(labels))
    ax.bar(x, early, .6, label="valid early warning", color="#5AD8A6")
    ax.bar(x, late, .6, bottom=early, label="late detection", color="#F6BD16")
    bottom = [e + l for e, l in zip(early, late)]
    ax.bar(x, missed, .6, bottom=bottom, label="missed", color="#E8684A")
    bottom = [b + m for b, m in zip(bottom, missed)]
    ax.bar(x, false_alarm, .6, bottom=bottom, label="false-alarm episodes", color="#945FB9")
    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=7, rotation=20, ha="right")
    ax.set_ylabel("episodes")
    ax.set_title("Outcome breakdown per trained policy and model")
    ax.legend(fontsize=8)
    fig.tight_layout()
    _caption(fig, report["run_id"], report["evidence_tag"],
             f"source_sensor={report['source_sensor']} incident episodes={report['test_incident_episodes']} "
             f"benign episodes={report['test_benign_episodes']}")
    path = output / "fig05_error_analysis.png"
    fig.savefig(path, dpi=160, bbox_inches="tight")
    plt.close(fig)
    _write_data(output, "fig05_error_analysis",
                {"labels": labels, "early_warning": early, "late_detection": late,
                 "missed": missed, "false_alarm_episodes": false_alarm})
    return str(path)


def fig_lead_time(report, output: Path) -> str:
    fig, ax = plt.subplots(figsize=(8.2, 4.4))
    payload = {}
    drew = False
    for policy, entry in report["methods"].items():
        for kind, info in entry["models"].items():
            if info.get("status") != "evaluated":
                continue
            leads = [r["lead_s"] for r in info.get("per_episode_warning", [])
                     if r["outcome"] == "early_warning" and r["lead_s"] is not None]
            if not leads:
                continue
            ax.scatter([POLICY_LABEL.get(policy, policy)] * len(leads), leads,
                       label=f"{POLICY_LABEL.get(policy, policy)}/{MODEL_LABEL.get(kind, kind)}",
                       alpha=.75)
            payload[f"{policy}/{kind}"] = leads
            drew = True
    ax.set_ylabel("lead time to milestone (s)")
    ax.set_title("Lead time of valid early warnings")
    ax.grid(alpha=.25)
    if drew:
        ax.legend(fontsize=8)
    else:
        ax.text(.5, .5, "no valid early warning was recorded", ha="center", va="center",
                transform=ax.transAxes)
    fig.tight_layout()
    _caption(fig, report["run_id"], report["evidence_tag"],
             f"source_sensor={report['source_sensor']} one point per warned incident episode")
    path = output / "fig06_lead_time.png"
    fig.savefig(path, dpi=160, bbox_inches="tight")
    plt.close(fig)
    _write_data(output, "fig06_lead_time", payload)
    return str(path)


def fig_architecture(report, inventory, output: Path) -> str:
    """Implementation and data-provenance diagram. Describes code, not measurements."""
    fig, ax = plt.subplots(figsize=(11, 6))
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 100)
    ax.axis("off")

    def box(x, y, w, h, text, color="#DCE9F5", fontsize=8):
        ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.4",
                                    linewidth=1.1, edgecolor="#33475B", facecolor=color))
        ax.text(x + w / 2, y + h / 2, text, ha="center", va="center", fontsize=fontsize, wrap=True)

    def arrow(x1, y1, x2, y2, label=""):
        ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle="-|>", mutation_scale=11,
                                     linewidth=1.1, color="#33475B"))
        if label:
            ax.text((x1 + x2) / 2, (y1 + y2) / 2 + 1.4, label, ha="center", fontsize=7, color="#33475B")

    box(3, 78, 22, 13, "scenario controller\nlab/staged_generate.py\npolicies fixed/random/strategic/test", "#E8F4E1")
    box(70, 78, 26, 13, "Docker lab (internal networks)\nclients -> gateway -> server_a/server_b\nTCP/8080, harmless HTTP", "#FFF3D6")
    arrow(25, 84.5, 70, 84.5, "HTTP requests")
    arrow(60, 84.5, 25, 74, "controller journal\nonset/escalation/milestone")
    box(3, 56, 26, 14, "sensors\n1. gateway event log (application layer)\n2. restricted tcpdump sidecar -> PCAP", "#F3E9F7")
    box(36, 56, 26, 14, "Zeek 9.0.1 offline read\nstrict checksums on a derived\nchecksum-repaired copy of the PCAP", "#E7F0FB")
    arrow(16, 70, 14, 56.5, "gateway_subset.jsonl")
    arrow(20, 62, 36, 63, "traffic_*.pcap")
    box(69, 56, 27, 14, "strict sensor gate\nsetup/staged_sensor_gate.py\nC1-C7 -> evidence tag", "#FFE7E7")
    arrow(62, 63, 69, 63, "conn.log")
    box(3, 33, 26, 14, "leakage-safe preprocessing\nepisode split BEFORE windowing\ncausal window features", "#E8F4E1")
    box(36, 33, 26, 14, "baselines (CPU)\nrule/rate, Isolation Forest,\nRandom Forest", "#FFF3D6")
    box(69, 33, 27, 14, "early warning\nonset <= t_alert < milestone\ncoverage-adjusted lead", "#F3E9F7")
    arrow(16, 50, 16, 47)
    arrow(29, 40, 36, 40)
    arrow(62, 40, 69, 40)
    box(3, 11, 44, 13, "frozen test set: policy=test episodes (seen + unseen families)\nvalidation episodes select the alert threshold only", "#F7F7F7")
    box(53, 11, 43, 13, "outputs: metrics.csv, results.json, figures, run_inventory.json,\nsensor_audit.json, leakage_audit.json", "#F7F7F7")
    arrow(25, 33, 25, 24.5)
    arrow(47, 17, 53, 17)
    ax.set_title("Phase 3 implementation and data provenance (describes the code, not a measurement)",
                 fontsize=10)
    _caption(fig, report["run_id"], report["evidence_tag"],
             f"source_sensor={report['source_sensor']} topology=two internal Docker segments")
    path = output / "fig07_architecture.png"
    fig.savefig(path, dpi=160, bbox_inches="tight")
    plt.close(fig)
    _write_data(output, "fig07_architecture", {
        "note": "implementation diagram generated from the actual repository layout",
        "run_id": report["run_id"], "evidence_tag": report["evidence_tag"]})
    return str(path)


def fig_sensor_evidence(report, inventory, output: Path) -> str:
    evidence = inventory["evidence"]
    checks = evidence.get("checks", {})
    labels = list(checks.keys())
    values = [1 if checks[c].get("passed") else 0 for c in labels]
    fig, ax = plt.subplots(figsize=(8.4, 3.6))
    ax.barh(labels, values, color=["#5AD8A6" if v else "#E8684A" for v in values])
    ax.set_xlim(0, 1.05)
    ax.set_xticks([0, 1])
    ax.set_xticklabels(["fail", "pass"])
    ax.set_xlabel("declared sensor check")
    ax.set_title(f"Strict sensor gate result: {evidence.get('tag')}")
    ax.invert_yaxis()
    for i, (c, v) in enumerate(zip(labels, values)):
        ax.text(1.01, i, checks[c].get("detail", "")[:110], va="center", fontsize=6.5)
    fig.tight_layout()
    _caption(fig, report["run_id"], evidence.get("tag", "UNKNOWN"),
             f"checksum_validation_ignored={evidence.get('checksum_validation_ignored')} "
             f"checksum_repaired={evidence.get('checksum_repaired')}")
    path = output / "fig08_sensor_evidence.png"
    fig.savefig(path, dpi=160, bbox_inches="tight")
    plt.close(fig)
    _write_data(output, "fig08_sensor_evidence", checks)
    return str(path)


def main():
    parser = argparse.ArgumentParser(description="Generate Phase 3 report figures from saved metrics")
    parser.add_argument("--results", required=True, type=Path, help="study results.json")
    parser.add_argument("--inventory", required=True, type=Path, help="run_inventory.json")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    report, _metrics = _load(args.results)
    inventory = json.loads(args.inventory.read_text(encoding="utf-8"))
    args.output.mkdir(parents=True, exist_ok=True)
    produced = [
        fig_dataset_composition(report, inventory, args.output),
        fig_pr_curves(report, args.output),
        fig_warning_coverage(report, args.output),
        fig_policy_comparison(report, args.output),
        fig_error_analysis(report, args.output),
        fig_lead_time(report, args.output),
        fig_architecture(report, inventory, args.output),
        fig_sensor_evidence(report, inventory, args.output),
    ]
    for path in produced:
        print(path)


if __name__ == "__main__":
    main()
