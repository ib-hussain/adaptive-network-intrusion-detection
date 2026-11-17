"""Create final deliverable package in deliverables/final_report/"""
import json
import csv
import shutil
from pathlib import Path
from datetime import datetime, timezone

DELIVERABLE_DIR = Path("deliverables/final_report_20261117")
DELIVERABLE_DIR.mkdir(parents=True, exist_ok=True)

# Copy key results
print("Copying results...")

# 1. Copy Phase 3 report
src_report = Path("outputs/reports/cpu_v3_main_v2_20261115T164430Z/PHASE3_REPORT.md")
dst_report = DELIVERABLE_DIR / "PHASE3_REPORT.md"
shutil.copy2(src_report, dst_report)
print(f"  Copied {src_report} -> {dst_report}")

# 2. Copy comprehensive experiment results
src_comp = Path("outputs/comprehensive_experiment_20261117/comprehensive_results.json")
dst_comp = DELIVERABLE_DIR / "comprehensive_results.json"
shutil.copy2(src_comp, dst_comp)
print(f"  Copied {src_comp} -> {dst_comp}")

# 3. Copy graph ablation CSV
src_abl = Path("outputs/studies/cpu_v3_main_v2_20261115T164430Z_zeek_20261115T165446Z/ablations_graph.csv")
dst_abl = DELIVERABLE_DIR / "ablations_graph.csv"
shutil.copy2(src_abl, dst_abl)
print(f"  Copied {src_abl} -> {dst_abl}")

# 4. Copy GNN evaluation results
src_gnn = Path("outputs/gnn_evaluation/gnn_evaluation.json")
dst_gnn = DELIVERABLE_DIR / "gnn_evaluation.json"
shutil.copy2(src_gnn, dst_gnn)
print(f"  Copied {src_gnn} -> {dst_gnn}")

# 5. Copy original study results
src_results = Path("outputs/studies/cpu_v3_main_v2_20261115T164430Z_zeek_20261115T165446Z/results.json")
dst_results = DELIVERABLE_DIR / "study_results.json"
shutil.copy2(src_results, dst_results)
print(f"  Copied {src_results} -> {dst_results}")

# 6. Copy metrics and other CSVs
for csv_name in ["metrics.csv", "ablations.csv"]:
    src = Path(f"outputs/studies/cpu_v3_main_v2_20261115T164430Z_zeek_20261115T165446Z/{csv_name}")
    if src.exists():
        dst = DELIVERABLE_DIR / csv_name
        shutil.copy2(src, dst)
        print(f"  Copied {src} -> {dst}")

# 7. Copy figures if any
src_figs = Path("outputs/reports/cpu_v3_main_v2_20261115T164430Z/figures")
if src_figs.exists():
    dst_figs = DELIVERABLE_DIR / "figures"
    shutil.copytree(src_figs, dst_figs, dirs_exist_ok=True)
    print(f"  Copied figures")

# 8. Create a summary manifest
manifest = {
    "deliverable_created": datetime.now(timezone.utc).isoformat(),
    "run_id": "cpu_v3_main_v2_20261115T164430Z",
    "evidence_tag": "SENSOR_VALIDATED",
    "seed": 20261115,
    "replication_seed": 20261116,
    "files": {
        "PHASE3_REPORT.md": "Main Phase 3 report with graph ablation section",
        "comprehensive_results.json": "Comprehensive experiment results (RF HPO, GNN, ablations)",
        "ablations_graph.csv": "Ablation study with graph_features ablation (30 rows)",
        "gnn_evaluation.json": "GNN baseline results (GraphSAGE PR-AUC=0.825, GAT PR-AUC=0.720)",
        "study_results.json": "Original study results with all baselines",
        "metrics.csv": "Per-model metrics from study",
        "ablations.csv": "Original ablations (no_temporal_features, persistence_2)",
    },
    "key_results": {
        "random_forest": {"test_pr_auc": 0.8737, "test_roc_auc": 0.8634},
        "graph_sage_window": {"test_pr_auc": 0.4545, "test_roc_auc": 0.5000},
        "gat_window": {"test_pr_auc": 0.4827, "test_roc_auc": 0.5326},
        "graph_sage_small": {"test_pr_auc": 0.8250, "test_roc_auc": None},
        "gat_small": {"test_pr_auc": 0.7197, "test_roc_auc": None},
        "ablation_graph_reduced": {"rf_pr_auc": 0.8580, "if_pr_auc": 0.6508},
        "ablation_temporal_reduced": {"rf_pr_auc": 0.6619, "if_pr_auc": 0.4035},
        "ablation_full": {"rf_pr_auc": 0.8742, "if_pr_auc": 0.6108},
    },
    "policy_results": {
        "fixed": {"coverage": 0.958, "strict_coverage": 0.917, "fpr": 0.625},
        "random": {"coverage": 0.833, "strict_coverage": 0.833, "fpr": 1.000},
        "strategic": {"coverage": 1.000, "strict_coverage": 0.042, "fpr": 0.083},
    }
}

with open(DELIVERABLE_DIR / "deliverable_manifest.json", "w") as f:
    json.dump(manifest, f, indent=2)
print(f"  Created deliverable_manifest.json")

# 9. Create reproducibility README
readme = f"""# Phase 3 Adaptive NIDS Final Deliverable

**Run ID:** cpu_v3_main_v2_20261115T164430Z  
**Evidence Tag:** SENSOR_VALIDATED  
**Seeds:** 20261115 (primary), 20261116 (replication)  
**Created:** {datetime.now(timezone.utc).isoformat()}

## Contents

### Reports
- `PHASE3_REPORT.md` — Main Phase 3 report with graph ablation analysis (Section 7)

### Results
- `study_results.json` — Original study results (RF, IF, Rule, GRU baselines)
- `comprehensive_results.json` — Extended experiments (RF HPO 30 trials, GNN, ablations)
- `metrics.csv` — Per-model metrics from study
- `ablations.csv` — Original ablations (no_temporal_features, persistence_2)
- `ablations_graph.csv` — Extended ablations including graph_features (30 rows)

### GNN Baselines
- `gnn_evaluation.json` — GraphSAGE PR-AUC 0.8250, GAT PR-AUC 0.7197 (200-window subset)
- GNN trained on window-graph representations with PyTorch Geometric

### Key Findings

1. **Policy Comparison** (frozen test, matched budget):
   - Fixed: High coverage (0.958) but noisy (FPR 0.625)
   - Random: Balanced (0.833 coverage, FPR 1.000)
   - Strategic: Lowest FPR (0.083) but pre-onset alarms (strict coverage 0.042)

2. **Ablation Studies**:
   - Temporal features removal: RF PR-AUC 0.874 → 0.662 (24% drop)
   - Graph features removal: RF PR-AUC 0.874 → 0.858 (2% drop)
   - Persistence-2 rule: Cuts coverage and FPR sharply, strict coverage unchanged

3. **GNN Baselines**:
   - GraphSAGE on window graphs: PR-AUC 0.455 (full), 0.825 (200-window subset)
   - GAT on window graphs: PR-AUC 0.483 (full), 0.720 (200-window subset)
   - Zeek-based graph construction attempted but episode timing alignment unavailable

4. **Sensor Validity**: Both seeds pass 7/7 checks (100% bidirectional visibility, 0 ambiguous joins)

## Reproducibility

All experiments use:
- Frozen test set (24 episodes, includes held-out slow_ramp family)
- Episode-level split decided before windowing
- Threshold selection on validation episodes only (no test leakage)
- CPU training (RF, IF) and GPU training (GNN) on RTX 4000 Ada

Run the study driver:
```bash
python -m src.code.study --run cpu_v3_main_v2_20261115T164430Z --source zeek \\
  --output outputs/studies/new_run --evidence-tag SENSOR_VALIDATED --seed 20261115
```

Run comprehensive experiment:
```bash
python run_comprehensive_experiment.py
```

## Constraints & Limitations

- **No real intrusion claims**: All traffic is controlled synthetic HTTP profiles
- **Single topology**: One Docker network configuration
- **Limited statistical power**: 24 incident episodes per configuration
- **GNN graphs**: Constructed from window features, not raw packet topology
- **No cross-topology generalization**: Two subnet names ≠ two topologies

## Artifacts Preserved

Raw PCAPs, Zeek logs, scenario manifests, and model checkpoints are in `outputs/` and `src/data/raw/` (excluded from Git per policy).
"""

with open(DELIVERABLE_DIR / "README_REPRODUCE.md", "w") as f:
    f.write(readme)
print(f"  Created README_REPRODUCE.md")

# 10. Create SHA256 sums
import hashlib
print("\nGenerating SHA256SUMS.txt...")
with open(DELIVERABLE_DIR / "SHA256SUMS.txt", "w") as f:
    for file_path in sorted(DELIVERABLE_DIR.glob("*")):
        if file_path.is_file():
            with open(file_path, "rb") as bf:
                sha256 = hashlib.sha256(bf.read()).hexdigest()
            f.write(f"{sha256}  {file_path.name}\n")
    # Also hash files in subdirectories
    for subdir in ["figures"]:
        subdir_path = DELIVERABLE_DIR / subdir
        if subdir_path.exists():
            for file_path in sorted(subdir_path.rglob("*")):
                if file_path.is_file():
                    with open(file_path, "rb") as bf:
                        sha256 = hashlib.sha256(bf.read()).hexdigest()
                    rel_path = file_path.relative_to(DELIVERABLE_DIR)
                    f.write(f"{sha256}  {rel_path}\n")

print(f"  Created SHA256SUMS.txt")

print(f"\n✅ Deliverable package created at: {DELIVERABLE_DIR}")
print(f"Files:")
for f in sorted(DELIVERABLE_DIR.rglob("*")):
    if f.is_file():
        size = f.stat().st_size
        print(f"  {f.relative_to(DELIVERABLE_DIR)} ({size} bytes)")

