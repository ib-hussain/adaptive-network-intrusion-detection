# Phase 3 Adaptive NIDS Final Deliverable

**Run ID:** cpu_v3_main_v2_20261115T164430Z  
**Evidence Tag:** SENSOR_VALIDATED  
**Seeds:** 20261115 (primary), 20261116 (replication)  
**Created:** 2026-11-17T12:01:01.756313+00:00

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
python -m src.code.study --run cpu_v3_main_v2_20261115T164430Z --source zeek \
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
