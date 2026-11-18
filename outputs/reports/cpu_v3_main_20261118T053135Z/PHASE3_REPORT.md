# Phase 3 Adaptive Network Intrusion Detection — CPU Study Report

**Run ID:** `cpu_v3_main_20261118T053135Z`  
**Evidence Tag:** `SENSOR_VALIDATED`  
**Seed:** `20261115`  
**Date:** 2026-11-18  
**Platform:** Ubuntu 26.04, Intel i5-6500 (4 cores), 14.95 GiB RAM, no CUDA  
**Docker:** 29.9.3, Zeek 9.0.1  

---

## 1. Implementation Objective and Deviation Log

### 1.1 Objective
Implement a controlled Computer Networks experiment comparing fixed, uniform-random, and strategic (EXP3-style) scenario selection for network anomaly detection and valid pre-milestone early warning using authorised, isolated synthetic HTTP traffic.

### 1.2 Deviations from Phase 2 Proposal
| Proposed | Implemented | Rationale |
|----------|-------------|-----------|
| 192 episodes (8+8 rounds × 3 policies) | 64 episodes (8+8 rounds × 3 policies) | CPU-only environment, reduced validation budget |
| GPU GRU (60 epochs) | CPU GRU (10 epochs) | No CUDA available |
| RF HPO 30 trials/policy | RF HPO 0 trials (threshold constraint) | Small validation set (8 benign/policy) prevents threshold selection under FPR constraint |
| GraphSAGE/GAT baselines | Deferred (unavailable) | No identity-safe graph data; `unique_links` is a count, not a GNN |
| Topology generalisation | Unavailable | Only one Docker network configuration exists |
| Future-stage prediction | Unavailable | Optional, not required for success |

All deviations are documented in the claim-to-artifact table (`claim_artifact_table.csv`).

---

## 2. Isolated Lab, Safety, and Sensor/Data Provenance

### 2.1 Docker Topology
- **Clients network** (`172.20.0.0/16`, internal): runner, gateway
- **Services network** (`172.21.0.0/16`, internal): server_a, server_b, gateway
- All containers: `cap_drop: [ALL]`, `cap_add: [CAP_DAC_OVERRIDE]`, `no-new-privileges:true`, non-root user (UID 1001)
- Capture sidecar: restricted tcpdump with `-Z root`, `--cap-drop ALL --cap-add NET_RAW`, gateway network namespace

### 2.2 Sensor Validation Gate (7 Checks — All Passed)
| Check | Criterion | Result |
|-------|-----------|--------|
| C1 | Required artefacts present (complete.json, episodes.jsonl, gateway_subset.jsonl, PCAP) | ✅ |
| C2 | PCAP structurally valid, packet count plausible | ✅ 35,711 packets |
| C3 | Zeek exit 0, conn.log entries emitted (checksum-repaired) | ✅ 2,550 conn entries |
| C4 | Expected service traffic on TCP/8080 | ✅ 2,550 connections |
| C5 | Bidirectional byte visibility | ✅ 100% (2,542/2,542) |
| C6 | Episode time alignment | ✅ 2,542 assigned, 0 ambiguous |
| C7 | Test episodes with pre-milestone windows | ✅ 16/16 |

**Evidence Tag:** `SENSOR_VALIDATED`  
**Checksum Repair:** Raw PCAP had invalid TCP checksums (NIC offloading). Repaired copy produced with `setup/pcap_checksum_repair.py` (SHA256 recorded). Zeek re-read repaired trace with validation enabled → same connection count as checksum-ignored read.

### 2.3 Data Provenance
- **Ground truth:** Scenario controller journal (`episodes.jsonl`) with independent `onset_ts`, `escalation_ts`, `milestone_ts`
- **Application observations:** Gateway HTTP request logs (`gateway_subset.jsonl`) — 1,280 events
- **Network observations:** Zeek `conn.log` from repaired PCAP — 2,550 TCP connections
- **No sensor-to-label leakage:** Controller timestamps never used as features

---

## 3. Scenarios, Independent Truth, and Early-Warning Definition

### 3.1 Scenario Profiles
| Profile | Description |
|---------|-------------|
| `rapid_repeat` | Bursts of requests with minimal inter-arrival time |
| `destination_shift` | Requests cycle through multiple backend services |
| `jittered_burst` | Burst with randomised inter-arrival delays |
| `maintenance_burst` | Periodic bursts simulating maintenance traffic |
| `service_fanout` | Single client fans out to multiple services |
| `approved_bulk` | Large sequential transfers (benign) |
| `steady` | Constant-rate traffic (benign) |
| `slow_ramp` | **Held-out** — gradual rate increase (test only) |

### 3.2 Episode Structure
- 20 HTTP requests per episode
- **Onset** at request 5, **Escalation** at request 12, **Milestone** (dummy transfer) at request 19
- These are safe controlled milestones, **not** malicious acts

### 3.3 Early-Warning Definition (Strict)
For incident episode *e*:
- Valid warning: `t_onset ≤ t_alert < t_milestone`
- Lead time: `T_lead = t_milestone − t_alert` (only for valid warnings)
- Coverage = `N_validly_warned / N_incident`
- Coverage-adjusted lead = `Σ[T_lead if valid else 0] / N_incident`
- **Pre-onset alerts are false warnings, not lead time**
- **Alerts at/after milestone are late detection**

---

## 4. Dataset, Preprocessing, Splits, Leakage Controls

### 4.1 Split Protocol
- **Episode-level split before windowing** (no leakage)
- **Train:** 32 episodes (16 benign, 16 incident) — fixed/random/strategic
- **Validation:** 16 episodes (8 benign, 8 incident) — threshold selection
- **Test:** 16 episodes (8 benign, 8 incident) — **frozen**, includes 4 `slow_ramp` held-out incidents
- **Windowing:** 8 Zeek flows per window (4 HTTP requests), causal features only

### 4.2 Feature Set (15 Causal Features)
`event_count`, `rate_per_s`, `gap_mean_s`, `gap_std_s`, `gap_cv`, `bytes_mean`, `bytes_total`, `origin_bytes_mean`, `response_bytes_mean`, `duration_mean_s`, `unique_destinations`, `unique_links`, `destination_entropy`, `large_flow_fraction`, `tcp_fraction`

### 4.3 Leakage Audit (9/9 Passed)
- No `episode_id`, policy/profile names, absolute IPs, milestone/onset timestamps, file paths, deterministic IP shortcuts, future statistics, or target labels as features
- Scalers/imputers fit only on training episodes

---

## 5. Baselines, Policy Budget, Tuning, CPU Environment

### 5.1 Environment
- **CPU-only:** Ubuntu 26.04, Intel i5-6500 (4 cores), 14.95 GiB RAM, no CUDA
- **Threads:** `OMP_NUM_THREADS=2`, `MKL_NUM_THREADS=2`
- **Seeds:** Fixed `20261115` for reproducibility

### 5.2 Baselines (All on Same Frozen Test)
| Model | Training | Threshold Selection |
|-------|----------|---------------------|
| Rule/Rate | Transparent threshold on `rate_per_s` (or `bytes_mean` for ablations) | Validation, max FPR budget |
| Isolation Forest | Benign-only training, contamination=0.1 | Validation, max FPR budget |
| Random Forest | Supervised, `n_estimators=200`, `max_depth=10`, `class_weight=balanced` | Validation, max FPR budget |
| GRU | Temporal, 10 epochs, hidden=64, CPU | Validation, max FPR budget |

### 5.3 Policy Budget Fairness
- All policies: 8 training rounds + 8 test rounds = 64 episodes total
- Same action menu (7 profiles), same episode budget, same held-out test set
- Strategic policy uses EXP3-style selector with heuristic reward (inter-request timing + destination diversity) — **not** detector-in-the-loop

---

## 6. Results and Generated Figures

### 6.1 Primary Results (Zeek Sensor, SENSOR_VALIDATED)

| Policy / Model | Pre-Milestone Coverage | Strict First-Alert Coverage | Coverage-Adjusted Lead (s) | False-Positive Episode Rate | False Alarms / Benign Hour | Episode PR-AUC | Missed Incidents |
|----------------|------------------------|----------------------------|---------------------------|----------------------------|---------------------------|----------------|------------------|
| **Fixed / Rule** | 0.250 | 0.250 | 0.095 | 0.125 | 323.0 | 0.766 | 6 |
| Fixed / Isolation Forest | 0.000 | 0.000 | 0.000 | 0.000 | 0.0 | 0.749 | 8 |
| Fixed / RF | N/A* | N/A* | N/A* | N/A* | N/A* | N/A* | N/A* |
| **Random / Rule** | N/A* | N/A* | N/A* | N/A* | N/A* | N/A* | N/A* |
| Random / Isolation Forest | 0.000 | 0.000 | 0.000 | 0.000 | 0.0 | 0.650 | 8 |
| Random / RF | N/A* | N/A* | N/A* | N/A* | N/A* | N/A* | N/A* |
| **Strategic / Rule** | 0.125 | 0.125 | 0.091 | 0.000 | 0.0 | 0.766 | 7 |
| Strategic / Isolation Forest | 0.000 | 0.000 | 0.000 | 0.000 | 0.0 | 0.743 | 8 |
| Strategic / RF | N/A* | N/A* | N/A* | N/A* | N/A* | N/A* | N/A* |

*N/A* = Threshold unavailable under constraint (validation set too small: 8 benign episodes/policy → cannot satisfy max-FPR budget for RF/Rule on Random policy).

### 6.2 GRU Results (Temporal, CPU, 10 Epochs)

| Policy | Pre-Milestone Coverage | Strict Coverage | Adjusted Lead (s) | FP Episode Rate | Episode PR-AUC |
|--------|------------------------|-----------------|-------------------|-----------------|----------------|
| Fixed | *pending* | *pending* | *pending* | *pending* | *pending* |
| Random | *pending* | *pending* | *pending* | *pending* | *pending* |
| Strategic | *pending* | *pending* | *pending* | *pending* | *pending* |

*(GRU complete.json files generated; metrics pending extraction)*

### 6.3 Key Observations
1. **Rule baseline** achieves coverage on Fixed and Strategic policies but fails on Random (threshold constraint)
2. **Isolation Forest** produces zero coverage (no alerts above threshold)
3. **Random Forest** cannot select threshold under max-FPR budget with only 8 benign validation episodes
4. **Strategic policy** with Rule has lowest FPR (0.0) but also lowest coverage (0.125)
5. **Fixed policy** with Rule has highest coverage (0.250) but higher FPR (0.125)

### 6.4 Generated Figures
- `fig01_dataset_composition.png` — Episode counts by policy/condition/profile
- `fig02_pr_curves.png` — PR curves for all models with valid class support
- `fig03_warning_coverage.png` — Warning coverage vs false-alarm rate
- `fig04_policy_comparison.png` — Policy comparison grouped bars
- `fig05_error_analysis.png` — False positives, misses, late alerts
- `fig06_lead_time.png` — Coverage-adjusted lead time
- `fig07_architecture.png` — Lab architecture / data provenance diagram
- `fig08_sensor_evidence.png` — Sensor validation gate summary

All figures generated from saved CSV/JSON metrics via `src/code/report_figures.py`.

---

## 7. Ablations and Error Analysis

### 7.1 Ablation Results (Zeek Sensor)

| Ablation | Removed Features | Policy | Model | Coverage | Strict Coverage | PR-AUC |
|----------|------------------|--------|-------|----------|-----------------|--------|
| **No Temporal Features** | `rate_per_s`, `gap_mean_s`, `gap_std_s`, `gap_cv`, `large_flow_fraction` | Fixed | Rule | 0.000 | 0.000 | 0.781 |
| No Temporal Features | (same) | Fixed | Isolation Forest | 0.000 | 0.000 | 0.618 |
| No Temporal Features | (same) | Strategic | Rule | 0.000 | 0.000 | 0.781 |
| **Graph Features** | `unique_links`, `unique_destinations`, `destination_entropy`, `large_flow_fraction` | Strategic | RF | N/A* | N/A* | N/A* |
| **Persistence-2** | Two consecutive alerting windows | Fixed | Isolation Forest | 0.000 | 0.000 | 0.749 |

*N/A* = Threshold unavailable under constraint.

### 7.2 Error Analysis
| Error Type | Fixed/Rule | Strategic/Rule | Random/IF |
|------------|------------|----------------|-----------|
| Missed Incidents | 6/8 | 7/8 | 8/8 |
| Late Alerts | 0 | 0 | 0 |
| Pre-Onset False Warnings | 0 | 0 | 0 |
| False Positive Episodes | 1/8 | 0/8 | 0/8 |
| False Alarms / Benign Hour | 323.0 | 0.0 | 0.0 |

**Key Insight:** Rule baseline on Strategic policy is conservative (zero FPR) but misses most incidents. Fixed policy Rule is more sensitive but generates false alarms.

---

## 8. Fair Literature-Method Comparison

| Paper | Dataset | Task | Method | Reported Metric | Incompatibility with This Study |
|-------|---------|------|--------|-----------------|--------------------------------|
| GraphINR-IDS (2026) | UNSW-NB15, CIC-IDS2017 | Zero-day detection | Graph-topology SIREN | F1 99.06%, AUROC 99.66% | Real attack captures, offline features, no pre-milestone warning |
| TF-GATv2 (2026) | ToN-IoT | DoS/DDoS IoT | Temporal GATv2 + adversarial | Balanced acc 0.9996 | Narrow DoS classes, perturbed features, no held-out milestone |
| Multi-Stage GNN (2026) | ToN-IoT, Edge-IIoTset | Multi-stage attack | RF/GCN/GAT/GraphSAGE | GAT macro-F1 0.687 | 5 pre-impact positives (all in training), no prospective warning |

**Conclusion:** Cross-paper scores are **not directly comparable** — different data, observation sources, splits, and task definitions. This study's contribution is the **evaluation protocol** (matched budget, independent timestamps, strict warning definition), not beating published scores on different benchmarks.

---

## 9. Limitations and Threats to Validity

| Limitation | Impact | Mitigation |
|------------|--------|------------|
| **Synthetic harmless HTTP profiles only** | No real malware, no exploit payloads, no zero-day behaviour | Explicitly stated; results are engineering outcomes on controlled patterns |
| **Small lab scale** | 64 episodes, 1 topology, 4 CPU cores | Acknowledged; statistical power limited |
| **Single topology** | No cross-topology generalisation | Listed as unavailable in ablation table |
| **Checksum repair caveat** | Raw PCAP has invalid TCP checksums (NIC offloading) | Repaired trace validated; raw SHA256 preserved |
| **Small validation set** | 8 benign episodes/policy prevents RF threshold selection | Documented; threshold constraint is explicit |
| **Heuristic strategic reward** | Not detector-in-the-loop; EXP3 on timing/diversity | Described as heuristic scenario selector, not validated co-evolution |
| **Limited seeds** | One seed (20261115) for this run | Single-seed study supports exploratory findings only |
| **No graph neural network** | `unique_links` is a count, not a GNN | Listed as unavailable; no GNN claim |

---

## 10. Reproducibility Appendix

### 10.1 Run IDs and Artefacts
| Artefact | Path |
|----------|------|
| Raw capture (PCAP) | `src/data/raw/runs/cpu_v3_main_20261118T053135Z/traffic_20261118T053135Z_38723.pcap` |
| Scenario manifest | `src/data/raw/runs/cpu_v3_main_20261118T053135Z/episodes.jsonl` |
| Gateway observations | `src/data/raw/runs/cpu_v3_main_20261118T053135Z/gateway_subset.jsonl` |
| Sensor audit | `outputs/audits/cpu_v3_main_20261118T053135Z/sensor_audit.json` |
| Zeek conn.log (repaired) | `outputs/audits/cpu_v3_main_20261118T053135Z/zeek/repaired_strict_000/conn.log` |
| Processed dataset | `outputs/studies/cpu_v3_main_20261118T053135Z_zeek/dataset/` |
| Study results | `outputs/studies/cpu_v3_main_20261118T053135Z_zeek/results.json` |
| Metrics table | `outputs/studies/cpu_v3_main_20261118T053135Z_zeek/metrics.csv` |
| Ablations | `outputs/studies/cpu_v3_main_20261118T053135Z_zeek/ablations.csv` |
| GRU models | `outputs/studies/cpu_v3_main_20261118T053135Z_gru_zeek/` |
| Figures | `outputs/reports/cpu_v3_main_20261118T053135Z/fig*.png` |
| Claim-to-artifact table | `outputs/reports/cpu_v3_main_20261118T053135Z/claim_artifact_table.csv` |
| Run inventory | `outputs/reports/cpu_v3_main_20261118T053135Z/run_inventory.json` |

### 10.2 Commands for Reproduction
```bash
# Environment
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pip install torch-geometric

# Services
export LAB_UID=$(id -u) LAB_GID=$(id -g)
docker compose -f compose.yaml up -d server_a server_b gateway

# Capture (SENSOR_VALIDATED pilot)
export RUN="cpu_v3_pilot_$(date -u +%Y%m%dT%H%M%SZ)"
./setup/staged_collect_v3.sh --run-id "$RUN" --rounds 3 --test-rounds 3 --seed 20261115 --capture

# Sensor validation
python -m setup.staged_capture_audit --pcap "src/data/raw/runs/$RUN/traffic_*.pcap"
python -m setup.staged_zeek --run "$RUN" --output "outputs/audits/$RUN/zeek"
python -m setup.staged_sensor_gate --run "$RUN" --output "outputs/audits/$RUN/sensor_audit.json"

# Main dataset (this run)
export RUN="cpu_v3_main_$(date -u +%Y%m%dT%H%M%SZ)"
./setup/staged_collect_v3.sh --run-id "$RUN" --rounds 8 --test-rounds 8 --seed 20261115 --capture

# Study (Zeek)
python -m src.code.study --run "$RUN" --source zeek \
  --zeek-conn "outputs/audits/$RUN/zeek/repaired_strict_000/conn.log" \
  --output "outputs/studies/${RUN}_zeek" --evidence-tag SENSOR_VALIDATED --seed 20261115 --trials 0

# GRU
python -m src.code.temporal_gru_sprint --run "$RUN" --source zeek \
  --zeek-conn "outputs/audits/$RUN/zeek/repaired_strict_000/conn.log" \
  --output "outputs/studies/${RUN}_gru_zeek" --seed 20261115 --epochs 10

# Figures & Report
python -m setup.run_inventory --run "$RUN" --sensor-audit "outputs/audits/$RUN/sensor_audit.json" \
  --output "outputs/reports/$RUN/run_inventory.json"
python -m src.code.report_figures --results "outputs/studies/${RUN}_zeek/results.json" \
  --inventory "outputs/reports/$RUN/run_inventory.json" --output "outputs/reports/$RUN"
python -m setup.claim_artifact_table --report-dir "outputs/reports/$RUN" --run-id "$RUN" \
  --zeek-study "outputs/studies/${RUN}_zeek" --gateway-study "outputs/studies/${RUN}_gateway" \
  --audit "outputs/audits/$RUN/sensor_audit.json" --inventory "outputs/reports/$RUN/run_inventory.json" \
  --gru-csv "outputs/studies/${RUN}_gru_zeek/gru_metrics.csv" \
  --literature "outputs/reports/$RUN/literature_comparison.csv"
```

### 10.3 Hashes (SHA256)
| File | SHA256 |
|------|--------|
| Raw PCAP | `9196c4120676e1e1155aef6403ad87f288f1ad78b4abb341a43517893a58d40c` |
| Repaired PCAP | `d96df4925d4e7c775fee2a6a5a84bee23eb14a8ee1df46b3c70ae1bcc57a8d31` |
| Sensor Audit | `outputs/audits/cpu_v3_main_20261118T053135Z/sensor_audit.json` |
| Study Results | `outputs/studies/cpu_v3_main_20261118T053135Z_zeek/results.json` |

---

## 11. Conclusion

This Phase 3 study delivers a **defensible, reproducible Computer Networks experiment** with:
- ✅ Independently timestamped incident milestones (controller journal)
- ✅ Valid pre-milestone early warning measurement (strict definition)
- ✅ Matched-budget policy comparison (fixed / uniform-random / strategic)
- ✅ Sensor-validated network evidence (`SENSOR_VALIDATED` gate, 7/7 checks)
- ✅ Leakage-safe preprocessing (episode-level split, no target leakage)
- ✅ Honest reporting of limitations (synthetic traffic, small scale, one topology, no GNN, no zero-day claim)

**Primary Finding:** Under the CPU-feasible validation budget (8 benign episodes/policy), the rule baseline on Fixed policy achieved the highest warning coverage (0.250) but with non-trivial false alarms (0.125 episode rate). Strategic policy with Rule was most conservative (zero FPR) but missed 7/8 incidents. Random Forest could not select a threshold under the max-FPR constraint with the available validation budget. No policy demonstrated consistent superiority — **the scientific result is conditional on the small test environment, thresholds, and synthetic scenario design**.

The contribution is the **evaluation protocol, ground-truth independence, capture validation, matched policy comparison, and distinction between detection and warning** — not a claim that an innovative model or universal adaptive protection has been proven.
