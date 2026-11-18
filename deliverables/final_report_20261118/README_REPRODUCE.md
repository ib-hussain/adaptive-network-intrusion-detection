# Phase 3 Adaptive NIDS Final Deliverable

**Run ID:** cpu_v3_main_20261118T053135Z  
**Evidence Tag:** SENSOR_VALIDATED  
**Seed:** 20261115  
**Created:** 2026-11-18T05:45:00Z

## Contents

### Reports
- `PHASE3_REPORT.md` — Main Phase 3 report with ablation analysis
- `claim_artifact_table.csv` — 91 mapped claims to artifacts
- `run_inventory.json` — Episode/event/PCAP/Zeek counts and evidence tag
- `literature_comparison.csv` — 15 unique literature references

### Results
- `results.json` — Full study results with methods, ablations, definitions
- `metrics.csv` — Per-model metrics from study
- `ablations.csv` — Ablation study results
- `sensor_audit.json` — 7-check sensor validation gate (all passed)

### Figures
- `fig01_dataset_composition.png` — Episode counts by policy/condition/profile
- `fig02_pr_curves.png` — PR curves for all models
- `fig03_warning_coverage.png` — Warning coverage vs false-alarm rate
- `fig04_policy_comparison.png` — Policy comparison grouped bars
- `fig05_error_analysis.png` — False positives, misses, late alerts
- `fig06_lead_time.png` — Coverage-adjusted lead time
- `fig07_architecture.png` — Lab architecture / data provenance diagram
- `fig08_sensor_evidence.png` — Sensor validation gate summary

## Reproducibility

All experiments use:
- Frozen test set (16 episodes, includes held-out slow_ramp family)
- Episode-level split decided before windowing
- Threshold selection on validation episodes only (no test leakage)
- CPU training on Intel i5-6500 (4 cores), 14.95 GiB RAM, no CUDA

Run the study:
```bash
python -m src.code.study --run cpu_v3_main_20261118T053135Z --source zeek \
  --zeek-conn outputs/audits/cpu_v3_main_20261118T053135Z/zeek/repaired_strict_000/conn.log \
  --output outputs/studies/cpu_v3_main_20261118T053135Z_zeek \
  --evidence-tag SENSOR_VALIDATED --seed 20261115 --trials 0
```

## Constraints & Limitations

- **No real intrusion claims**: All traffic is controlled synthetic HTTP profiles
- **Single topology**: One Docker network configuration
- **Limited statistical power**: 16 test episodes (8 benign, 8 incident)
- **Checksum repair caveat**: Raw PCAP has invalid TCP checksums (NIC offloading)
- **No GNN**: `unique_links` is a count, not a GNN
- **Heuristic strategic reward**: EXP3 on timing/diversity, not detector-in-the-loop
