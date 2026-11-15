"""Emit the claim-to-artifact map for the Phase 3 report.

Every row states one reported claim, the value that was reported, the file that
contains that value and the machine-readable field it came from. The script
reads the artefacts and fails loudly if a referenced field is missing, so the
map cannot drift away from the stored results.
"""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path


def build(report_dir: Path, run_id: str, zeek_study: Path, gateway_study: Path,
          audit: Path, inventory: Path, gru_csv: Path, literature: Path) -> list[dict]:
    z = json.loads((zeek_study / "results.json").read_text(encoding="utf-8"))
    g = json.loads((gateway_study / "results.json").read_text(encoding="utf-8"))
    a = json.loads(audit.read_text(encoding="utf-8"))
    inv = json.loads(inventory.read_text(encoding="utf-8"))
    zrows = {(r["train_policy"], r["model"]): r for r in
             csv.DictReader((zeek_study / "metrics.csv").open(encoding="utf-8"))}
    grows = {(r["train_policy"], r["model"]): r for r in
             csv.DictReader((gateway_study / "metrics.csv").open(encoding="utf-8"))}
    grows.update({(r["train_policy"], "gru_temporal_cpu"): r for r in
                  csv.DictReader(gru_csv.open(encoding="utf-8"))})
    arows = {(r["train_policy"], r["model"], r["ablation"]): r for r in
             csv.DictReader((zeek_study / "ablations.csv").open(encoding="utf-8"))}
    rows = []

    def add(section, claim, value, artefact, field):
        rows.append({"section": section, "claim": claim, "reported_value": value,
                     "artifact_path": artefact, "artifact_field": field})

    counts = inv["counts"]
    add("dataset", "Episodes collected", counts["episodes"], str(inventory), "counts.episodes")
    add("dataset", "Gateway events collected", counts["gateway_events"], str(inventory), "counts.gateway_events")
    add("dataset", "PCAP bytes", counts["pcap_bytes"], str(inventory), "counts.pcap_bytes")
    add("dataset", "PCAP packet records", counts["pcap_packets"], str(inventory), "counts.pcap_packets")
    add("dataset", "Zeek TCP connections", counts["zeek_conn_entries"], str(inventory), "counts.zeek_conn_entries")
    add("dataset", "Raw PCAP SHA256", inv["source_hashes"].get(
        [k for k in inv["source_hashes"] if k.endswith(".pcap")][0]), str(inventory), "source_hashes")
    add("split", "Frozen test episodes", z["test_episodes"], str(zeek_study / "results.json"), "test_episodes")
    add("split", "Test incident episodes", z["test_incident_episodes"], str(zeek_study / "results.json"), "test_incident_episodes")
    add("split", "Test benign episodes", z["test_benign_episodes"], str(zeek_study / "results.json"), "test_benign_episodes")
    add("split", "Total feature windows", z["n_windows"], str(zeek_study / "results.json"), "n_windows")
    add("sensor", "Evidence tag", a["evidence_tag"], str(audit), "evidence_tag")
    add("sensor", "Bidirectional connection fraction", a["checks"]["C5"]["bidirectional_fraction"], str(audit), "checks.C5.bidirectional_fraction")
    add("sensor", "Ambiguous timestamp joins", a["checks"]["C6"]["ambiguous_timestamp_matches"], str(audit), "checks.C6.ambiguous_timestamp_matches")
    add("sensor", "Checksum validation ignored", a["checksum_validation_ignored"], str(audit), "checksum_validation_ignored")
    add("sensor", "Checksum repaired derived copy used", a["checksum_repaired"], str(audit), "checksum_repaired")
    add("sensor", "Repaired-strict vs checksum-ignored connection count agreement",
        a["zeek"]["repair_consistency"]["counts_match"], str(audit), "zeek.repair_consistency.counts_match")
    add("leakage", "All leakage checks passed", z["leakage_audit_passed"],
        str(zeek_study / "dataset/leakage_audit.json"), "all_passed")

    for (policy, model), r in sorted(zrows.items()):
        add("results_zeek", f"{policy}/{model} warning coverage", r["pre_milestone_coverage"],
            str(zeek_study / "metrics.csv"), f"train_policy={policy},model={model},pre_milestone_coverage")
        add("results_zeek", f"{policy}/{model} strict first-alert coverage", r["strict_first_alert_coverage"],
            str(zeek_study / "metrics.csv"), f"train_policy={policy},model={model},strict_first_alert_coverage")
        add("results_zeek", f"{policy}/{model} coverage-adjusted mean lead (s)",
            r["coverage_adjusted_mean_lead_s"], str(zeek_study / "metrics.csv"),
            f"train_policy={policy},model={model},coverage_adjusted_mean_lead_s")
        add("results_zeek", f"{policy}/{model} false-positive episode rate",
            r["false_positive_episode_rate"], str(zeek_study / "metrics.csv"),
            f"train_policy={policy},model={model},false_positive_episode_rate")
        add("results_zeek", f"{policy}/{model} false alarms per benign hour",
            r["false_alarms_per_benign_hour"], str(zeek_study / "metrics.csv"),
            f"train_policy={policy},model={model},false_alarms_per_benign_hour")
        add("results_zeek", f"{policy}/{model} pre-onset warning episodes",
            r["pre_onset_warning_episodes"], str(zeek_study / "metrics.csv"),
            f"train_policy={policy},model={model},pre_onset_warning_episodes")
        add("results_zeek", f"{policy}/{model} episode PR-AUC", r["episode_pr_auc"],
            str(zeek_study / "metrics.csv"), f"train_policy={policy},model={model},episode_pr_auc")
    for (policy, model), r in sorted(grows.items()):
        add("results_gateway" if model != "gru_temporal_cpu" else "results_gru",
            f"{policy}/{model} warning coverage", r["pre_milestone_coverage"],
            str(gateway_study / "metrics.csv") if model != "gru_temporal_cpu" else str(gru_csv),
            f"train_policy={policy},model={model},pre_milestone_coverage")
    for (policy, model, ablation), r in sorted(arows.items()):
        add("ablations", f"{policy}/{model} {ablation} coverage", r["pre_milestone_coverage"],
            str(zeek_study / "ablations.csv"),
            f"train_policy={policy},model={model},ablation={ablation},pre_milestone_coverage")
        add("ablations", f"{policy}/{model} {ablation} false-positive episode rate",
            r["false_positive_episode_rate"], str(zeek_study / "ablations.csv"),
            f"train_policy={policy},model={model},ablation={ablation},false_positive_episode_rate")
    add("literature", "Unique references compared", sum(1 for _ in csv.DictReader(literature.open())),
        str(literature), "rows")
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report-dir", required=True, type=Path)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--zeek-study", required=True, type=Path)
    parser.add_argument("--gateway-study", required=True, type=Path)
    parser.add_argument("--audit", required=True, type=Path)
    parser.add_argument("--inventory", required=True, type=Path)
    parser.add_argument("--gru-csv", required=True, type=Path)
    parser.add_argument("--literature", required=True, type=Path)
    args = parser.parse_args()
    rows = build(args.report_dir, args.run_id, args.zeek_study, args.gateway_study,
                 args.audit, args.inventory, args.gru_csv, args.literature)
    out = args.report_dir / "claim_artifact_table.csv"
    if out.exists():
        raise FileExistsError(f"Refusing to overwrite: {out}")
    with out.open("x", encoding="utf-8", newline="") as fp:
        writer = csv.DictWriter(fp, fieldnames=["section", "claim", "reported_value",
                                                "artifact_path", "artifact_field"])
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    print(f"Wrote {out} with {len(rows)} mapped claims")


if __name__ == "__main__":
    main()
