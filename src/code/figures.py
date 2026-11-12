"""Plot actual measured results; no fabricated or placeholder experimental curves."""
import argparse
import json
from pathlib import Path
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


def draw(results_json, output_dir):
    report = json.loads(Path(results_json).read_text(encoding="utf-8"))
    labels, coverages, fps = [], [], []
    for policy, entry in report.get("methods", {}).items():
        for model, result in entry.get("models", {}).items():
            if result.get("status") != "evaluated":
                continue
            w = result["warning"]
            if w.get("pre_milestone_coverage") is None:
                continue
            labels.append(policy + " / " + model)
            coverages.append(w["pre_milestone_coverage"])
            fps.append(w["false_positive_episode_rate"])
    if not labels:
        raise ValueError("No evaluated models to plot")
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    for filename, data, title, ylabel in [
        ("early_warning_coverage.png", coverages, "Pre-milestone warning coverage", "Fraction of incident episodes"),
        ("false_positive_episode_rate.png", fps, "False-alarm episodes", "Fraction of benign episodes"),
    ]:
        fig, ax = plt.subplots(figsize=(max(7, len(labels) * 1.15), 4.2))
        ax.bar(labels, data)
        ax.set_ylim(0, 1)
        ax.set_title(title)
        ax.set_ylabel(ylabel)
        ax.tick_params(axis="x", labelrotation=35)
        fig.tight_layout()
        fig.savefig(output / filename, dpi=160)
        plt.close(fig)
    return [str(output / "early_warning_coverage.png"), str(output / "false_positive_episode_rate.png")]


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--results", required=True)
    p.add_argument("--output", required=True)
    a = p.parse_args()
    print("\n".join(draw(a.results, a.output)))

if __name__ == "__main__":
    main()
