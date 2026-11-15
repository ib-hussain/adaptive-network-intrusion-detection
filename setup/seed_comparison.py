"""Compare two independent collection seeds under the identical protocol.

Both seeds must share the same scenario schema, round budget, window rule and
alert rule, otherwise the comparison is not like-for-like. The script refuses
to compare runs whose protocol differs.
"""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

METRICS = (
    ("pre_milestone_coverage", "warning coverage"),
    ("strict_first_alert_coverage", "strict first-alert coverage"),
    ("coverage_adjusted_mean_lead_s", "coverage-adjusted mean lead (s)"),
    ("false_positive_episode_rate", "false-positive episode rate"),
    ("false_alarms_per_benign_hour", "false alarms per benign hour"),
    ("pre_onset_warning_episodes", "pre-onset warning episodes"),
    ("missed_incidents", "missed incidents"),
)


def _rows(study: Path):
    out = {}
    with (study / "metrics.csv").open(encoding="utf-8") as fp:
        for row in csv.DictReader(fp):
            out[(row["train_policy"], row["model"])] = row
    return out


def _protocol(study: Path):
    report = json.loads((study / "results.json").read_text(encoding="utf-8"))
    return {
        "run_id": report["run_id"],
        "source_sensor": report["source_sensor"],
        "causal_labels": report["causal_labels"],
        "n_events_per_window": report["n_events_per_window"],
        "n_episodes": report["n_episodes"],
        "test_episodes": report["test_episodes"],
        "evidence_tag": report["evidence_tag"],
    }


def compare(study_a: Path, study_b: Path):
    pa, pb = _protocol(study_a), _protocol(study_b)
    for key in ("source_sensor", "causal_labels", "n_events_per_window",
                "n_episodes", "test_episodes"):
        if pa[key] != pb[key]:
            raise ValueError(f"Protocols differ on {key}: {pa[key]} vs {pb[key]} — refusing to compare")
    a, b = _rows(study_a), _rows(study_b)
    rows = []
    for key in sorted(set(a) | set(b)):
        if key not in a or key not in b:
            continue
        policy, model = key
        row = {"train_policy": policy, "model": model,
               "run_a": pa["run_id"], "run_b": pb["run_id"]}
        for field, label in METRICS:
            row[f"a_{field}"] = a[key].get(field)
            row[f"b_{field}"] = b[key].get(field)
            try:
                row[f"delta_{field}"] = round(float(b[key][field]) - float(a[key][field]), 6)
            except (TypeError, ValueError, KeyError):
                row[f"delta_{field}"] = ""
        rows.append(row)
    return rows, pa, pb


def draw_figure(rows, pa, pb, output: Path) -> str:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np
    metrics = [("pre_milestone_coverage", "warning coverage"),
               ("strict_first_alert_coverage", "strict first-alert coverage"),
               ("false_positive_episode_rate", "false-positive episode rate")]
    keys = sorted({(r["train_policy"], r["model"]) for r in rows})
    fig, axes = plt.subplots(1, 3, figsize=(15, 4.6))
    payload = {}
    for ax, (field, title) in zip(axes, metrics):
        x = np.arange(len(keys))
        a_vals, b_vals = [], []
        for key in keys:
            row = next(r for r in rows if (r["train_policy"], r["model"]) == key)
            a_vals.append(float(row[f"a_{field}"]))
            b_vals.append(float(row[f"b_{field}"]))
        ax.bar(x - .2, a_vals, .4, label=f"seed {pa['run_id'][-20:]} A", color="#5B8FF9")
        ax.bar(x + .2, b_vals, .4, label=f"seed B", color="#F6BD16")
        ax.set_xticks(x)
        ax.set_xticklabels([f"{p}/{m}" for p, m in keys], fontsize=6.5, rotation=35, ha="right")
        ax.set_title(title)
        ax.set_ylim(0, 1.05)
        ax.grid(axis="y", alpha=.25)
        payload[field] = {"keys": [f"{p}/{m}" for p, m in keys], "seed_a": a_vals, "seed_b": b_vals}
    axes[0].legend(fontsize=7)
    fig.tight_layout()
    fig.text(0.01, 0.005, f"A={pa['run_id']} | B={pb['run_id']} | both {pa['evidence_tag']} | "
                          f"{pa['n_episodes']} episodes each | same protocol", fontsize=7)
    path = output / "fig09_seed_comparison.png"
    fig.savefig(path, dpi=160, bbox_inches="tight")
    plt.close(fig)
    (output / "fig09_seed_comparison.data.json").write_text(
        json.dumps({"protocol_a": pa, "protocol_b": pb, "panels": payload}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8")
    return str(path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--study-a", required=True, type=Path)
    parser.add_argument("--study-b", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--figure-dir", type=Path, default=None)
    args = parser.parse_args()
    rows, pa, pb = compare(args.study_a, args.study_b)
    if args.output.exists():
        raise FileExistsError(f"Refusing to overwrite: {args.output}")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8", newline="") as fp:
        writer = csv.DictWriter(fp, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    print(f"Wrote {args.output} with {len(rows)} compared configurations")
    if args.figure_dir:
        print("wrote", draw_figure(rows, pa, pb, args.figure_dir))
    print(f"  A = {pa['run_id']} ({pa['evidence_tag']}, {pa['n_episodes']} episodes)")
    print(f"  B = {pb['run_id']} ({pb['evidence_tag']}, {pb['n_episodes']} episodes)")
    for row in rows:
        print(f"  {row['train_policy']:>10}/{row['model']:<17} "
              f"coverage {row['a_pre_milestone_coverage']} -> {row['b_pre_milestone_coverage']} | "
              f"strict {row['a_strict_first_alert_coverage']} -> {row['b_strict_first_alert_coverage']} | "
              f"fpr {row['a_false_positive_episode_rate']} -> {row['b_false_positive_episode_rate']}")


if __name__ == "__main__":
    main()
