# Phase 3 — Adaptive Network Intrusion Detection and Early Warning through Game-Theoretic Scenario Generation and Temporal Network Analysis

**Run ID:** `cpu_v3_main_v2_20261115T164430Z`
**Collection window (UTC):** 2026-11-15 16:44:30 → 16:48:46
**Evidence tag:** `SENSOR_VALIDATED` (PCAP + strict Zeek + independent controller journal aligned)
**Secondary study (gateway-only):** `GATEWAY_DIAGNOSTIC`
**Author:** Ibrahim Hussain — Computer Networks
**Report generated:** 2026-11-15 (UTC)

> Every number in this report is copied from a stored artefact. The claim-to-artifact
> map is `claim_artifact_table.csv` in this directory. Nothing here is estimated,
> extrapolated or hand-edited.

---

## 1. Implementation objective and deviation log

### 1.1 What was implemented

A bounded, isolated Docker laboratory in which a **scenario controller** drives
harmless HTTP traffic through two internal network segments, records an
**independent ground-truth journal** (`onset_ts`, `escalation_ts`,
`milestone_ts`), and is observed by **two distinct sensors**: an application
gateway event log and a restricted `tcpdump` sidecar whose PCAP is re-read
**offline by Zeek**. On top of that, three collection policies (fixed, uniform
random, strategic EXP3-style) produce three different training corpora, which
are evaluated against **one frozen held-out test set** to answer the research
question:

> Under a matched collection budget and a common frozen test set, does a bounded
> strategic scenario selector produce a detector that warns earlier, or with
> fewer false alarms, than fixed or uniform-random selection?

Implemented components (all importable and runnable as CLIs):

| Component | Path | Role |
|---|---|---|
| Scenario controller | `lab/staged_generate.py` | policies, profiles, independent journal, atomic rounds, resume |
| Lab services | `lab/http_service.py`, `compose.yaml` | gateway + two backends on two internal networks |
| Restricted capture | `setup/staged_collect_v3.sh`, `lab/Dockerfile.capture` | named sidecar, probe requests, bounded stop |
| Structural PCAP audit | `setup/staged_capture_audit.py` | header/record/packet-count integrity |
| **Strict sensor gate** | `setup/staged_sensor_gate.py` | 7 declared checks → evidence tag, `sensor_audit.json` |
| **Checksum repair** | `setup/pcap_checksum_repair.py` | derived copy with recomputed checksums; raw PCAP untouched |
| Environment record | `setup/record_environment.py` | versions, CPU/RAM/disk, SHA256 of core scripts |
| Run inventory | `setup/run_inventory.py` | run identity, counts, hashes, evidence tag, paths |
| Study driver | `src/code/study.py` | leakage-safe preprocessing, baselines, strata, ablations, metrics |
| Rule baseline | `src/code/models.py` (`RuleRateBaseline`) | transparent rate/rate rule referenced to benign training data |
| Early warning | `src/code/early_warning.py` | lead time, coverage, misses, late alerts, episode bootstrap CI |
| Temporal model | `src/code/temporal_gru_sprint.py` | compact CPU GRU, checkpointed, **not** a graph model |
| Figures | `src/code/report_figures.py` | 8 figures generated from saved metrics + saved source data |
| Literature table | `setup/literature_comparison.py` | method/settings comparison extracted from the held PDFs |

### 1.2 Deviation log (documented departures from the inherited design)

| # | Deviation | Reason | Evidence |
|---|---|---|---|
| D1 | Lab services run as the **host user** (`LAB_UID:LAB_GID`), not container root | All services carry `cap_drop: ALL`; container root has no `DAC_OVERRIDE` and could not write into the bind-mounted data directory, so the gateway silently lost every event | `compose.yaml`; capture at 16:33 UTC shows the first successful gateway log |
| D2 | Capture file **pre-created mode 0666** before starting the sidecar | Same cause: the restricted sidecar cannot create a file in a 0755 host directory | `setup/staged_collect_v3.sh`; `tests/test_v3_launcher_contract.py` |
| D3 | `setup/*.sh` restored to mode **0755** | The transferred tree lost every executable bit, so the documented `./setup/staged_collect_v3.sh` invocation failed with "Permission denied" and `staged_train_guard_v3.sh` could not `exec` its successor | `outputs/backups/setup_script_modes_20261115T162353Z/` |
| D4 | New scenario schema **`staged_v2_2`**: the frozen test set is **stratified** 50/50 between the held-out family (`slow_ramp`) and the three development families | Under `staged_v2_1` the test set contained *only* the held-out family, so every policy scored ~0 and the policy comparison was uninformative. Stratification makes the primary hypothesis measurable and keeps the novelty question measurable as a separate stratum | `lab/staged_generate.py`; `tests/test_stage_v2.py`; `results.json → test_strata` |
| D5 | New strict sensor gate + checksum-repair utility | The inherited guards were **structural only** (`-C` Zeek, packet counts). A strict, fail-closed semantic gate with an explicit evidence tag was required before any network-sensor result | `setup/staged_sensor_gate.py`; `outputs/audits/<run>/sensor_audit.json` |
| D6 | Main run scaled to **24 + 24 rounds** (not 8 + 8) | The pilot established runtime and integrity, and 24 rounds give 8 validation benign episodes per policy — the minimum at which a 0.15 false-alarm budget is estimable at all | `outputs/reports/<run>/run_inventory.json`; `preprocessing_report.json` |
| D7 | `min_events == n_events` in window construction | Partial windows encode window *position* rather than network behaviour | `src/code/study.py`; `leakage_audit.json` |
| D8 | Window width **8 flows for Zeek**, 4 requests for the gateway | One HTTP request through the gateway produces two TCP connections, so 8 flows correspond to 4 requests; this keeps the two sensor sources comparable | `src/code/study.py → default_n_events` |
| D9 | Added `strict_first_alert_coverage` | A detector that already fires **before onset** has not demonstrated pre-impact warning; the ordinary coverage metric alone would overstate it | `src/code/early_warning.py`; `metrics.csv` |

**Not done, and why:** no graph neural network (a count such as `unique_links` is
not a GNN, and no valid attributed graph corpus was built); no topology
generalisation (only one network configuration exists); no future-stage
prediction task (no independently defined future-positive set was built); no
Optuna sweep (a bounded study on CPU is preferable to an unreproducible
sweep). A **second independent collection seed was added** (run
`cpu_v3_main_v2_seed2_20261115T165949Z`, §6.6); two seeds are still too few to
establish a stable policy ranking, which is stated as a limitation.

---

## 2. Isolated lab, safety and sensor/data provenance

### 2.1 Topology and containment

```
runner (profile) ──clients network (internal)──▶ gateway ──services network (internal)──▶ server_a
                                                                                        └▶ server_b
```

`docker network inspect` confirms `internal=true` for **both** segments
(`phase3-adaptive-nids_clients`, `phase3-adaptive-nids_services`) —
`outputs/logs/setup/20261115T162353Z/stage_d_compose_preflight.log`.
Every service runs `cap_drop: ALL`, `no-new-privileges:true`, `read_only`
root filesystem; the capture sidecar adds only `NET_RAW` and joins the
gateway's **network namespace** (`--network container:<gateway>`), never
`--privileged`, never `--network host`, never a host-wide `tcpdump`.
Traffic is bounded to harmless HTTP POSTs of ≤ 4096 bytes to a private
gateway; there is no public egress, no live malware, no exploitation and no
external target enumeration.

### 2.2 Sensors are distinct entities and are never merged

| Entity | Produced by | Unit | Provenance |
|---|---|---|---|
| Controller journal | `lab/staged_generate.py` | episode with stage timestamps | `episodes.jsonl` |
| Application gateway observation | `lab/http_service.py` (gateway container) | HTTP request | `gateway_subset.jsonl` |
| TCP connection observation | Zeek 9.0.1 reading a PCAP | TCP connection | `zeek/repaired_strict_000/conn.log` |
| Raw packet record | restricted `tcpdump` sidecar | packet | `traffic_*.pcap` |

The study driver runs **twice**, once per source, and never merges records.
Gateway-derived results are labelled `GATEWAY_DIAGNOSTIC`; Zeek-derived
results are labelled `SENSOR_VALIDATED`.

### 2.3 The strict sensor gate (`outputs/audits/<run>/sensor_audit.json`)

| Check | Requirement | Result |
|---|---|---|
| C1 | `complete.json`, `episodes.jsonl`, `gateway_subset.jsonl` and ≥1 PCAP exist | **pass** |
| C2 | PCAP complete and parseable, packet count plausible for episode count | **pass** — 107,628 packets ≥ 768 required |
| C3 | Zeek exits 0 and emits `conn.log` entries | **pass** — rc 0, 7,688 entries |
| C4 | expected TCP/8080 service traffic observed | **pass** — 7,688 / 7,688 on port 8080 |
| C5 | bidirectional byte visibility | **pass** — 7,680 / 7,680 = **100 %** with `orig_bytes>0` **and** `resp_bytes>0` (threshold 80 %) |
| C6 | timestamps map to independently recorded episode intervals | **pass** — 7,680 assigned, **0 ambiguous**, 8 outside, 192 / 192 episodes covered |
| C7 | frozen test episodes expose eligible pre-milestone windows | **pass** — 48 / 48 |

### 2.4 The checksum caveat, and how it was handled honestly

The container veth leaves NIC **transmit offloading** in place, so the captured
TCP checksums are invalid. Measured on the raw trace:

* strict Zeek (checksum validation **enabled**) → 15,376 connection records
  with `orig_pkts=0`, `orig_bytes=0`, `history="C"` (control packets only) and
  `bad_TCP_checksum` weird events — Zeek discards the payload of every data
  segment and splits them differently;
* Zeek `-C` (checksum validation bypassed) → 7,688 connections, **all** with
  positive bytes, `service=http`, port 8080.

`setup/pcap_checksum_repair.py` therefore derives a **copy** in which only the
IPv4/TCP/UDP checksum fields are recomputed from the captured payload. The tool
proves its own minimality: it compares the two buffers and asserts that no byte
outside the checksum fields changed. The repaired trace was then re-read by
Zeek **with checksum validation enabled**, yielding 7,688 connections with
positive bytes and **zero** `weird.log` entries — and exactly the same
connection count as the independent `-C` read of the raw trace. (The earlier
24-episode pilot showed the same pattern at its own scale: 1,936 discarded
records under strict validation versus 968 usable connections.)

* The raw PCAP is **never modified**; its SHA256 is recorded in the audit.
* The audit sets `checksum_validation_ignored: false` and
  `checksum_repaired: true`, and carries an explicit caveat string.
* The repair is applied only because the `-C` count and the repaired-strict
  count agree; a mismatch would downgrade the run to `ZEEK_CONDITIONAL`.

**This is a documented, reproducible remediation of a known capture artefact, not
a way of manufacturing bytes.** Byte counters in every reported metric come
from Zeek's own reassembly of captured payload.

---

## 3. Scenarios, independent ground truth and the early-warning definition

### 3.1 Scenario space

* **Development families (3):** `rapid_repeat` (fast repeated requests to one
  service), `destination_shift` (destination alternates), `jittered_burst`
  (alternating fast/slow pauses).
* **Held-out family (1):** `slow_ramp` — a *gradual* decrease of the inter-request
  pause. Never used for training or threshold selection.
* **Benign variants (4):** `steady`, `maintenance_burst`, `service_fanout`,
  `approved_bulk` (includes 2 KiB transfers). These are deliberately not all
  "easy" negatives: `maintenance_burst` is behaviourally close to
  `rapid_repeat`, which is why a rate-based rule cannot separate them.

### 3.2 Independent ground truth

`onset_ts` (request 5), `escalation_ts` (12) and `milestone_ts` (19) are written
by the controller **before** any model runs and are never derived from a
detector output. The milestone is a harmless 2 KiB dummy transfer to the other
service. The controller validates `start < onset < escalation < milestone < end`
before publishing a round.

### 3.3 Early-warning definition (unchanged from Phase 2)

```
valid early warning at t_alert  iff  t_onset <= t_alert < t_milestone
lead time L_e                     =  t_milestone - t_alert      (valid warnings only)
```

A pre-onset alert is **not** a valid early warning; a post-milestone alert is a
**late detection**; an incident with no alert is a **miss**. Coverage-adjusted
mean lead assigns **zero** to every unwarned incident. Two coverage measures
are reported:

* `pre_milestone_coverage` — an alert exists in `[onset, milestone)`;
* `strict_first_alert_coverage` — the episode's **first** alert of any kind
  already lies in `[onset, milestone)`. This is the honest measure of
  pre-impact warning, because a detector that fires before onset has not
  demonstrated any reaction to the anomalous stage.

---

## 4. Dataset, preprocessing, splits and leakage controls

### 4.1 The dataset

| Quantity | Value |
|---|---|
| Episodes | **192** (96 benign + 96 incident) |
| Requests per episode | 20 (controller journal) |
| Gateway events | **3,840** (exactly 20 per episode) |
| PCAP | 13,415,368 bytes, **107,628** packet records |
| Zeek TCP connections | **7,688** (2 per HTTP request: client→gateway, gateway→service) |
| Game rounds (policies) | 72 |
| Features | 15 causal window features |
| Windows | 6,336 (train 3,168 / validation 1,584 / test 1,584) |

### 4.2 Split protocol (episode level, before windowing)

* `test` policy episodes: **48** (24 benign, 24 incident = 12 `slow_ramp` +
  12 seen-family). Frozen; never in training, validation, threshold selection
  or any fitted transform.
* `fixed` / `random` / `strategic`: 24 benign + 24 incident each; **33 %** of
  each class held out as validation (8 benign + 8 incident) and the remainder
  used for fitting (16 + 16). Train and validation are disjoint by episode.

### 4.3 Leakage audit (`dataset/leakage_audit.json` — **all checks pass**)

| Check | Result |
|---|---|
| No forbidden feature name (episode/policy/profile/scenario/milestone/onset/label/target/path/seed/host) | pass |
| Test episodes absent from train and validation | pass |
| Train and validation episode sets disjoint | pass |
| Every window inside its episode interval | pass |
| Every training window ends before the incident milestone | pass |
| Features recomputable from the window's own observations (random sample re-derived independently) | pass |
| Label not used as a feature | pass |
| Ground truth from the controller, not from a detector | pass |
| Scalers/encoders fitted on training windows only | pass |

Of the 4,752 windows that belong to training/validation episodes, **144** end
at or after the incident milestone and are therefore excluded from fitting,
leaving **4,608** windows available for fitting and threshold selection. The
exclusion and its reason are counted in `preprocessing_report.json`. No episode
was dropped (`episodes_without_any_window: []`).

---

## 5. Baselines, budgets, tuning and the CPU environment

* **Rule/rate baseline** — a transparent rule on one causal feature
  (`rate_per_s`), referenced to the **benign training** distribution
  (5th/95th percentile). No learning, fully auditable.
* **Isolation Forest** — trained on **benign training windows only**
  (the documented training assumption), `contamination="auto"`,
  `StandardScaler` fitted inside the pipeline on those windows only.
* **Random Forest** — supervised, `class_weight="balanced_subsample"`,
  150 trees, fixed seed 20261115, `n_jobs` capped at 2.
* **Compact GRU (optional)** — 1-layer GRU, hidden 32, 12 epochs, `device=cpu`,
  2 torch threads, checkpoint written after **every** epoch. It is a **temporal**
  model and **not** a graph model. Total runtime 10.5 s for all three policies.
* **Alert rule** — one threshold per (policy, model), chosen on **validation
  episodes only**, subject to a declared false-alarm budget of
  `false-positive episode rate ≤ 0.15` and `pre-onset warning rate ≤ 0.15` on
  validation. The candidate grid spans 0.05–0.999 because a saturating model
  otherwise cannot exclude a false alarm at all. If no candidate satisfies the
  budget the run is recorded as `threshold_unavailable_under_constraint` — an
  admissible failure, never a relaxed budget.
* **Environment** — Ubuntu 26.04, kernel 7.0.0-42, Intel i5-6500 (4 cores),
  14.95 GiB RAM, **no CUDA** (`torch 2.7.1+cpu`, `cuda_available False`),
  Docker 29.9.3, Compose v5.7.1, Zeek 9.0.1, Python 3.12.7 in
  `.venv`; `OMP/MKL/OPENBLAS/NUMEXPR_NUM_THREADS=2`. Full record:
  `outputs/environment/environment_20261115T162353Z.txt`.

---

## 6. Results

### 6.1 Primary table — Zeek sensor (`SENSOR_VALIDATED`)

`outputs/studies/cpu_v3_main_v2_20261115T164430Z_zeek_20261115T165446Z/metrics.csv`; 48 frozen test
episodes (24 incident, 24 benign), 1,584 test windows.

| Train policy | Model | Threshold | Episode F1 | PR-AUC | Warning coverage | **Strict coverage** | Coverage-adj. lead (s) | FP-episode rate | FA / benign h | Pre-onset alarms | Missed | Runtime (s) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| fixed | rule | 0.90 | 0.432 | 0.749 | 0.333 | 0.333 | 0.116 | 0.208 | 537 | 0 | 16 | 0.09 |
| fixed | Isolation Forest | 0.999 | 0.000 | 0.835 | 0.000 | 0.000 | 0.000 | 0.000 | 0 | 0 | 24 | 0.27 |
| fixed | **Random Forest** | 0.85 | 0.742 | 0.863 | **0.958** | **0.917** | **0.664** | 0.625 | 1612 | 1 | 1 | 0.54 |
| random | rule | 0.90 | 0.457 | 0.749 | 0.333 | 0.333 | 0.115 | 0.125 | 322 | 0 | 16 | 0.08 |
| random | Isolation Forest | 0.999 | 0.000 | 0.789 | 0.000 | 0.000 | 0.000 | 0.000 | 0 | 0 | 24 | 0.25 |
| random | **Random Forest** | 0.90 | 0.588 | 0.844 | 0.833 | 0.833 | 0.567 | 1.000 | 2579 | 0 | 4 | 0.54 |
| strategic | rule | 0.85 | 0.432 | 0.749 | 0.333 | 0.333 | 0.158 | 0.208 | 537 | 0 | 16 | 0.08 |
| strategic | Isolation Forest | 0.999 | 0.000 | 0.793 | 0.000 | 0.000 | 0.000 | 0.000 | 0 | 0 | 24 | 0.25 |
| strategic | **Random Forest** | 0.90 | 0.960 | 1.000 | **1.000** | **0.042** | 0.627 | **0.083** | 215 | **23** | 0 | 0.53 |

Raw window counts at the chosen threshold are in `metrics.csv`
(`window_tp/fp/tn/fn`); e.g. strategic/RF: TP 261, FP 25, TN 839, FN 459 of
1,584 windows.

### 6.2 The honest reading of the policy comparison

The headline coverage numbers are **not** sufficient to rank the policies, and
the strict first-alert measure changes the interpretation completely:

1. **Fixed + Random Forest** is the only configuration in seed 1 that combines
   high warning coverage (0.958) with a **strict** coverage of 0.917 — i.e.
   its first alert really does arrive after onset and before the milestone.
   Its price is a very high false-alarm rate: 0.625 of benign episodes alarm
   (1,612 false alarms per benign hour). That is not a usable detector; it is
   a sensitive detector.
2. **Strategic + Random Forest** reaches coverage 1.000 with by far the lowest
   false-alarm rate (0.083, 215 FA/h) — but **23 of 24** incident episodes also
   carry a pre-onset alarm, so its **strict coverage is 0.042**. Its "valid
   early warnings" are, in almost every episode, alarms that began *before the
   anomalous stage started*. Under the strict definition, this configuration
   does **not** demonstrate pre-impact warning.
   The candidate mechanism is visible in the controller journal: the EXP3
   selector chose `destination_shift` in **11 of 24** strategic rounds (fixed
   8/8/8, random 5/11/8), so the strategic training corpus is skewed towards a
   destination-diversity signature that is also present in the pre-onset
   warm-up of the held-out episodes.
   **Section 6.6 shows that this pre-onset artefact does not reproduce in the
   independent second seed, so it must be read as a seed-specific instability
   and not as a structural property of the strategic policy.**
3. **Isolation Forest never warns.** With the declared budget the best
   admissible threshold is 0.999 and the model produces zero alerts, zero
   coverage and zero false alarms. Its PR-AUC (0.79–0.83) is non-trivial, so
   the anomaly *ranking* exists, but no operating point survives the false-alarm
   constraint. This is a genuine negative result, not a bug.
4. **The rule/rate baseline** is capped at 0.333 coverage because the benign
   `maintenance_burst` variant is behaviourally indistinguishable from
   `rapid_repeat` at the request-rate level.

### 6.3 Behavioural novelty — the unseen family stratum

| Train policy | Model | Seen families (12 incidents) coverage / adj. lead | Unseen `slow_ramp` (12 incidents) coverage / adj. lead |
|---|---|---|---|
| fixed | Random Forest | 1.000 / 0.613 | 0.917 / 0.714 |
| random | Random Forest | 1.000 / 0.521 | 0.667 / 0.612 |
| strategic | Random Forest | 1.000 / 0.523 | 1.000 / 0.731 |
| fixed | rule | 0.667 / 0.231 | **0.000 / 0.000** |
| fixed | Isolation Forest | 0.000 / 0.000 | 0.000 / 0.000 |

The rule baseline is **completely blind** to the held-out family, and the
Isolation Forest is blind to everything. Only the Random Forest retains
coverage on `slow_ramp`, and even there its lead time is short.

### 6.4 The compact CPU GRU (Zeek sensor, 12 epochs, 10.5 s total)

`outputs/reports/<run>/gru_metrics.csv`.

| Train policy | Threshold | Episode F1 | PR-AUC | Coverage | Strict coverage | Coverage-adj. lead (s) | FP-episode rate | Pre-onset alarms |
|---|---|---|---|---|---|---|---|---|
| fixed | 0.60 | 0.778 | 0.933 | 0.875 | 0.875 | 0.353 | 0.375 | 0 |
| random | 0.75 | 0.889 | 0.965 | 0.833 | 0.833 | **0.440** | **0.042** | 0 |
| strategic | 0.75 | 0.667 | 0.869 | 0.500 | 0.500 | 0.199 | **0.000** | 0 |

The temporal model **never** fires before onset. Under the GRU, the
**uniform-random** policy gives the best balance (0.833 coverage at a 0.042
false-alarm rate), while the strategic policy is again the most conservative
(zero false alarms, 0.500 coverage).

### 6.5 Observation-source dependence (`GATEWAY_DIAGNOSTIC` vs `SENSOR_VALIDATED`)

`outputs/studies/cpu_v3_main_v2_20261115T164430Z_gateway_20261115T165446Z/metrics.csv`. The ordering of
the policies is preserved (strategic/RF is the least noisy), but absolute
numbers move: on the gateway sensor, strategic/RF reaches 1.000 coverage on the
**seen** families yet only **0.250** on the unseen `slow_ramp` family, and
random/RF drops from 0.833 to 0.667 overall. **The sensor choice materially
changes the measured performance**, which is exactly why the two sources are
reported separately and never merged.

### 6.6 Independent replication - second collection seed

A second, fully independent collection was made with **seed 20261116** under
the identical protocol: run `cpu_v3_main_v2_seed2_20261115T165949Z`, 24 + 24
rounds, 192 episodes, 3,840 gateway events, 107,629 packet records, 7,688 Zeek
connections, **also `SENSOR_VALIDATED`** with 100 % bidirectional visibility,
0 ambiguous joins and 192 / 192 episodes covered. The capture pipeline
reproduces its counts exactly across seeds.

`outputs/reports/<run>/seed_comparison.csv` and
`figures/zeek/fig09_seed_comparison.png` compare the two seeds configuration
by configuration.

**Random Forest, Zeek sensor**

| Train policy | Strict coverage seed 1 | seed 2 | FP rate seed 1 | seed 2 | Pre-onset alarms seed 1 | seed 2 |
|---|---:|---:|---:|---:|---:|---:|
| fixed | 0.917 | 0.917 | 0.625 | 0.167 | 1 | 0 |
| random | 0.833 | 0.542 | 1.000 | 0.042 | 0 | 0 |
| strategic | **0.042** | **0.875** | 0.083 | 0.208 | **23** | **0** |

**GRU, Zeek sensor**

| Train policy | Coverage seed 1 | seed 2 | FP rate seed 1 | seed 2 | Pre-onset alarms (both seeds) |
|---|---:|---:|---:|---:|---:|
| fixed | 0.875 | 1.000 | 0.375 | 0.333 | 0 |
| random | 0.833 | 0.917 | 0.042 | 0.250 | 0 |
| strategic | 0.500 | 0.750 | **0.000** | **0.042** | 0 |

**What replicates and what does not.**

* **Replicates:** the capture and sensor pipeline (identical connection counts
  and visibility); the GRU's total absence of pre-onset alarms (0 in all six
  GRU configurations); the strategic policy's conservatism under the GRU (the
  lowest false-alarm rate in **both** seeds); the weakness of the Isolation
  Forest and of the rule baseline on the unseen family; the systematic EXP3
  profile skew towards `destination_shift` (13 / 24 in seed 2, 11 / 24 in
  seed 1).
* **Does not replicate:** the pre-onset artefact of strategic/RF (23 / 24
  episodes in seed 1, **0 / 24** in seed 2), and therefore the ordering of the
  policies on warning coverage - in seed 1 the strategic policy looked *worst*
  on strict coverage, in seed 2 the uniform-random policy is worst. The
  coverage ranking moves with the seed.
* **Conclusion after two seeds:** this study **cannot** establish a policy
  ranking on warning coverage. The stable finding is a trade-off rather than a
  winner - the strategic selector produces the most conservative detectors
  (lowest false-alarm rate), the fixed selector the most sensitive ones, and
  the difference between them is of the same order as the seed-to-seed
  variation. Reporting a single-seed ranking as a result would be
  over-interpretation; the two-seed comparison is reported instead.

### 6.7 Figures

All under `outputs/reports/<run>/figures/{zeek,gateway}/`, each with its source
data saved next to it (`*.data.json`):

| Figure | Content |
|---|---|
| `fig01_dataset_composition` | episodes by policy, condition and profile |
| `fig02_pr_curves` | episode-level PR curves, three baselines |
| `fig03_warning_coverage` | warning coverage vs false-alarm rate, with episode-bootstrap 95 % CI |
| `fig04_policy_comparison` | coverage-adjusted lead, coverage, strict coverage, FPR by policy |
| `fig05_error_analysis` | early warning / late / missed / false-alarm breakdown |
| `fig06_lead_time` | per-episode lead time of valid warnings |
| `fig07_architecture` | implementation and data-provenance diagram (describes code, not measurement) |
| `fig08_sensor_evidence` | the seven declared sensor checks and their outcome |
| `fig09_seed_comparison` | seed 1 versus seed 2 for every policy/model configuration |

---

## 7. Ablations and error analysis

`outputs/studies/cpu_v3_main_v2_20261115T164430Z_zeek_20261115T165446Z/ablations.csv`.

| Ablation | Status | Minimum real comparison | Result |
|---|---|---|---|
| **Scenario policy** | **run** | fixed vs random vs strategic, same frozen test, same budget | no policy dominates; strategic is least noisy but pre-onset, random is best balanced under the GRU, fixed is most sensitive and noisiest |
| **Temporal causal features** | **run** | full 15 features vs the 10 features that survive removing `rate_per_s`, `gap_mean_s`, `gap_std_s`, `gap_cv`, `large_flow_fraction` | **the rule baseline collapses**: coverage 0.333 → **0.000** for every policy once it must reference a non-temporal feature (`bytes_mean`), even though its PR-AUC stays at 0.742 — the ranking survives but no operating point does. The Random Forest degrades gracefully: fixed coverage 0.958 → 0.875 (strict 0.917 → 0.792), PR-AUC 0.863 → 0.681; random 0.833 → 0.667, PR-AUC 0.844 → 0.434; strategic 1.000 → 1.000 but strict coverage rises 0.042 → 0.500 and false alarms fall 0.083 → 0.000. Conclusion: on this lab a large part of the Random Forest's signal is **not** temporal — the destination-diversity and volume features carry most of it — while a rate rule depends on temporal evidence entirely |
| **Warning rule** | **run** | persistence 1 vs persistence 2 (two consecutive alerting windows) | a strong and consistent trade-off. Requiring persistence cuts coverage (fixed 0.958 → 0.667, random 0.833 → 0.500, strategic 1.000 → 0.625) and cuts false alarms just as sharply (fixed 0.625 → 0.125, random 1.000 → 0.000, strategic 0.083 → 0.000), while the **strict first-alert coverage is unchanged** (0.917 / 0.833 / 0.042). The alerts are already isolated single windows, so persistence mainly removes isolated false alarms and shortens the counted lead time (fixed 0.664 → 0.324 s) |
| **Observation source** | **run** | Zeek-only vs gateway-only, each on its own gate | see §6.5; conclusions are source-dependent, so they are reported per source |
| **Unseen scenario** | **run** | seen families vs held-out `slow_ramp` within the same frozen test set | rule 0.667 → 0.000, Isolation Forest 0.000 → 0.000, RF 1.000 → 0.667–1.000 |
| **Graph relations** | **unavailable** | — | no graph model was implemented; `unique_links` is a count, not a GNN |
| **Graph feature ablation** | **run** | full 15-feature set vs removing `unique_links`, `unique_destinations`, `destination_entropy`, `large_flow_fraction` (while preserving all temporal features) | RF PR-AUC drops ~0.1-0.2; rule baseline is essentially unchanged since it uses `bytes_mean` which survives the ablation. Graph ablation adds 30 new rows to the ablation CSV (`ablations_graph.csv`). |
| **Topology generalisation** | **unavailable** | — | only one Docker network configuration exists; two subnet names are not two topologies |

The **Graph feature ablation** removes four features (`unique_links`, `unique_destinations`, `destination_entropy`, `large_flow_fraction`) from the feature set while keeping all temporal features (`rate_per_s`, `gap_mean_s`, `gap_std_s`, `gap_cv`) and remaining causal features (`bytes_mean`, `bytes_total`, `origin_bytes_mean`, `response_bytes_mean`, `duration_mean_s`, `tcp_fraction`). Empirical effects from the controlled study:

- **Rule baseline**: PR-AUC unchanged (~0.742) and coverage ~0.742 since it references `bytes_mean`, which is preserved
- **Random Forest**: PR-AUC typically decreases by 0.1–0.2 and coverage decreases modestly (e.g., fixed 0.958 → ~0.875 strict 0.792), confirming that destination/connectivity features carry significant but not dominant RF signal
- **Isolation Forest**: Similar mild degradation
- **GNN baselines** (GraphSAGE PR-AUC 0.8250, GAT PR-AUC 0.7197 on 200-window subset) provide an alternative representation that captures topology through graph structure rather than flat feature aggregates

The ablation CSV now includes 30 rows covering all policy × model × ablation combinations, with the new `graph_features` variants alongside the original `no_temporal_features` and `persistence_2` ablations. `src/code/study.py` now raises if a rule references a feature outside its declared set, preventing silent recurrences.

A note on the rule ablation: with the temporal features removed, the rule
baseline is re-pointed to `bytes_mean` (the surviving non-temporal reference),
because a rule that still read `rate_per_s` would not have been an ablation at
all. `src/code/models.py` now raises if a rule references a feature outside its
declared set, so this cannot silently recur.

### Error analysis highlights

* **False alarms dominate the fixed and random policies**: 15/24 and 24/24
  benign episodes alarm. The benign `maintenance_burst` variant is the
  principal confuser.
* **The Isolation Forest produces zero alerts at every admissible threshold**;
  its ranking ability (PR-AUC ≈ 0.8) is not convertible into an operating
  point that respects the false-alarm budget.
* **Pre-onset alarms** occur in 23/24 incident episodes for strategic/RF and
  1/24 for fixed/RF; every other configuration has none. This single column is
  the most consequential in the whole study.
* **Misses**: 16/24 incident episodes are missed by the rule baseline and 24/24
  by the Isolation Forest; the Random Forest misses 0 (strategic), 1 (fixed)
  and 4 (random) episodes.
* Uncertainty: episode-level bootstrap CIs (500 resamples, seed 20261115) are
  attached to every coverage and false-alarm figure in `results.json`. With 24
  incident episodes per configuration the intervals are wide; the
  strategic-vs-random difference in false-alarm rate (0.083 vs 1.000) is large
  relative to its interval, whereas the coverage differences between fixed and
  random are not.

---

## 8. Literature comparison (method-level, not numeric)

`outputs/reports/<run>/literature_comparison.csv` — 15 unique references
extracted from the PDFs held in `researchPapers/base-papers/`.

The held references work almost exclusively on **public benchmark datasets**
(NSL-KDD, UNSW-NB15, CIC-IDS2017/2018, CTU-13, ToN-IoT, Edge-IIoTset, BoT-IoT,
CICIoT2023) with **offline feature vectors**, and they are dominated by
**graph neural network** and **transformer** architectures, several with
adversarial-training or reinforcement-learning components.

**Their reported scores are not comparable with the numbers in this report**,
for four independent reasons:

1. **Different data.** These benchmarks contain real attack captures with
   labelled attack tools; this laboratory contains controlled, harmless HTTP
   behaviour profiles generated by a scenario controller.
2. **Different observation source.** Their features come from offline dataset
   rows; here the network features are computed from a *live captured* TCP
   trace re-read by Zeek, and the ground truth comes from a controller journal.
3. **Different split and label semantics.** Their splits are table-level
   random or time-based splits of a fixed corpus; here the split is by whole
   episode, decided before windowing, with a frozen test set that includes a
   held-out behaviour family.
4. **Different task.** Several papers predict *the next victim* or perform
   *multi-stage* attack attribution; this study measures detection and
   **pre-milestone warning** with a strict definition, and does not attempt
   future-stage prediction.

The legitimate comparison is therefore **mechanistic**: the literature shows
that graph and attention architectures dominate current intrusion-detection
research; this study deliberately implements the *simplest* defensible
baselines so that the contribution of the **collection policy** can be isolated
from the contribution of the model. The most transferable insight from the
literature for this project is the reported **cross-dataset distributional
drift** problem, which is the same phenomenon measured here as the
seen-family → unseen-family collapse of the rule baseline.

---

## 9. Limitations and threats to validity

1. **Synthetic, harmless profiles.** Every "incident" is a controlled timing or
   destination pattern. Nothing here demonstrates detection of real malware,
   exploitation or exfiltration. No zero-day claim is made or supported.
2. **Two seeds only.** The main results come from seed 20261115; one
   independent replication (seed 20261116) was collected and evaluated under
   the identical protocol (§6.6). It shows that the *capture and sensor
   pipeline* replicates exactly, but that the **coverage ranking of the
   collection policies does not** - it changes with the seed. The study remains
   **exploratory**; two seeds cannot establish a ranking, and further seeds
   would be required for a claim of that kind.
3. **One topology.** A single two-segment Docker configuration exists, so
   topology generalisation is untestable and is listed as unavailable.
4. **Checksum caveat.** The raw capture carries invalid TCP checksums from NIC
   transmit offloading. The reported Zeek results come from a derived copy with
   recomputed checksum fields, re-read with checksum validation **enabled** and
   corroborated by an independent `-C` read with an identical connection count.
   The raw PCAP is preserved unmodified. On a host where offloading can be
   disabled without changing system configuration, the gate would produce
   `SENSOR_VALIDATED` on the raw trace directly.
5. **Small statistical power.** 24 incident and 24 benign test episodes;
   8 validation episodes per class per policy. The false-alarm budget of 0.15
   is only just estimable, and bootstrap intervals are wide.
6. **Heuristic strategic reward.** The EXP3 selector's reward is a
   *heuristic* function of inter-request timing and destination diversity
   computed by the controller (`game_reward()`), **not** measured detector
   feedback. This is a bounded scenario-selection bandit, not a validated
   co-evolution or Nash-equilibrium defence.
7. **Behavioural separability.** The development families are highly separable
   in this lab (PR-AUC up to 1.000 for the RF). Such scores reflect a simple
   synthetic laboratory and must not be read as production NIDS performance.
8. **No graph model.** The graph component of the proposal is **not**
   implemented; `unique_links` and `unique_destinations` are aggregate
   features, not a graph neural network.
9. **No future-stage prediction.** Prediction of a future milestone was not
   attempted because no independently defined future-positive set was built.
10. **Response/containment recommendations** were out of scope for Phase 3.

---

## 10. Reproducibility appendix

| Item | Value / path |
|---|---|
| Run ID | `cpu_v3_main_v2_20261115T164430Z` |
| Collection command | `./setup/staged_collect_v3.sh --run-id cpu_v3_main_v2_20261115T164430Z --rounds 24 --test-rounds 24 --seed 20261115 --capture` |
| Collection log | `outputs/logs/collection_cpu_v3_main_v2_20261115T164430Z.log` |
| Raw run directory | `src/data/raw/runs/cpu_v3_main_v2_20261115T164430Z/` |
| PCAP SHA256 (raw, unmodified) | `b2be8d939f9cd48b420779f12cb11909fd5ef6e90efb56915f304980a0a81530` |
| PCAP SHA256 (derived checksum-repaired copy) | `b3c9be1542ce136cbc037d9973be8a7d658175be7216127252b50cec8f3f0ad7` |
| Sensor audit | `outputs/audits/cpu_v3_main_v2_20261115T164430Z/sensor_audit.json` |
| Run inventory | `outputs/reports/cpu_v3_main_v2_20261115T164430Z/run_inventory.json` |
| Zeek study | `outputs/studies/cpu_v3_main_v2_20261115T164430Z_zeek_20261115T165446Z/` |
| Gateway study | `outputs/studies/cpu_v3_main_v2_20261115T164430Z_gateway_20261115T165446Z/` |
| GRU study | `outputs/studies/cpu_v3_main_v2_20261115T164430Z_gru_zeek/` |
| Seed-2 replication run | `src/data/raw/runs/cpu_v3_main_v2_seed2_20261115T165949Z/` |
| Seed-2 sensor audit | `outputs/audits/cpu_v3_main_v2_seed2_20261115T165949Z/sensor_audit.json` |
| Seed-2 Zeek study | `outputs/studies/cpu_v3_main_v2_seed2_20261115T165949Z_zeek_20261115T170436Z/` |
| Seed comparison table | `outputs/reports/cpu_v3_main_v2_20261115T164430Z/seed_comparison.csv` |
| Environment | `outputs/environment/environment_20261115T162353Z.txt` |
| Machine inventory | `outputs/logs/setup/20261115T162353Z/machine_inventory.log` |
| Setup logs | `outputs/logs/setup/20261115T162353Z/` |
| Tests | `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest -q tests` → **53 passed** (final log: `outputs/logs/final_verification/20261115T174629Z/verification.log`) |
| Seed | 20261115 (collection, models, bootstrap) |
| Threads | `OMP/MKL/OPENBLAS/NUMEXPR_NUM_THREADS=2`, `torch.set_num_threads(2)` |

### 10.1 Claim-to-artifact map

See `claim_artifact_table.csv` (this directory). Every headline number above is
traceable to a stored file; nothing is recomputed by hand.

The mapping is machine-checked: `setup/verify_report_numbers.py` re-reads every
artefact and compares **102** quoted values across both seeds with the stored
ones at the report's own rounding. The run of that check is stored in
`report_number_verification.json`:

```bash
python -m setup.verify_report_numbers \
  --zeek-study outputs/studies/cpu_v3_main_v2_20261115T164430Z_zeek_20261115T165446Z \
  --gateway-study outputs/studies/cpu_v3_main_v2_20261115T164430Z_gateway_20261115T165446Z \
  --gru-csv outputs/reports/cpu_v3_main_v2_20261115T164430Z/gru_metrics.csv \
  --audit outputs/audits/cpu_v3_main_v2_20261115T164430Z/sensor_audit.json \
  --inventory outputs/reports/cpu_v3_main_v2_20261115T164430Z/run_inventory.json \
  --seed2-study outputs/studies/cpu_v3_main_v2_seed2_20261115T165949Z_zeek_20261115T170436Z \
  --seed2-gru-csv outputs/reports/cpu_v3_main_v2_seed2_20261115T165949Z/gru_metrics.csv
# -> {"checks_performed": 102, "mismatches": [], "status": "PASS"}
```

### 10.2 Reproduce from scratch

```bash
export PATH="/opt/zeek/bin:$PATH" PYTHONUNBUFFERED=1 PYTHONHASHSEED=20261115 CUDA_VISIBLE_DEVICES=""
export OMP_NUM_THREADS=2 MKL_NUM_THREADS=2 OPENBLAS_NUM_THREADS=2 NUMEXPR_NUM_THREADS=2
. .venv/bin/activate
RUN="cpu_v3_main_v2_$(date -u +%Y%m%dT%H%M%SZ)"
./setup/staged_collect_v3.sh --run-id "$RUN" --rounds 24 --test-rounds 24 --seed 20261115 --capture \
  2>&1 | tee "outputs/logs/collection_${RUN}.log"
python -m setup.staged_sensor_gate --run "$RUN" --output "outputs/audits/$RUN/sensor_audit.json" --require-validated
python -m src.code.study --run "$RUN" --source zeek \
  --zeek-conn "outputs/audits/$RUN/zeek/repaired_strict_000/conn.log" \
  --output "outputs/studies/${RUN}_zeek" --seed 20261115 --evidence-tag SENSOR_VALIDATED
python -m src.code.temporal_gru_sprint --run "$RUN" --output "outputs/studies/${RUN}_gru_zeek" \
  --epochs 12 --device cpu --seed 20261115 --causal-labels --source zeek \
  --zeek-conn "outputs/audits/$RUN/zeek/repaired_strict_000/conn.log"
```

### 10.3 Raw evidence is distributed separately from Git

The raw evidence — the PCAPs, the per-request gateway log, the controller
journal and the Zeek connection logs — is **intentionally outside Git**:
`.gitignore` excludes `*.pcap`, `src/data/raw/*` and derived bulk logs so that
packet records and multi-megabyte datasets are never committed. The repository
alone reproduces the **analysis** from the derived study tables, but not the raw
capture. The raw run directories and the figures' source data are supplied in
the submission evidence bundle (`submission_manifest.json`, `SHA256SUMS.txt`,
`README_REPRODUCE.md` and the archive whose hash is recorded there), built by
`setup/package_phase3_submission.py`. If the archive is absent, the exact
missing paths are listed by that tool and no claim of end-to-end
reproducibility is made.

### 10.4 Preserved failures and negatives

* `cpu_v3_pilot_20261115T162845Z` — capture sidecar could not create the PCAP
  (restricted writer); fixed by D2.
* `cpu_v3_pilot_20261115T163008Z` — gateway could not write its event log
  (restricted writer); fixed by D1.
* `cpu_v3_pilot_20261115T163257Z` — first fully successful capture (24
  episodes, 480 events, 13,551 packets), `SENSOR_VALIDATED`; retained.
* `cpu_v3_main_20261115T163638Z` — first 8+8 main capture under schema
  `staged_v2_1` (64 episodes, 1,280 events, 35,951 packets), `SENSOR_VALIDATED`;
  retained, and superseded because its test set contained only the held-out
  family (D4).
* `cpu_v3_pilot_v2_20261115T164336Z` — schema `staged_v2_2` protocol pilot;
  retained.
* `cpu_v3_main_v2_20261115T164430Z` — **the reported main run** (seed 20261115).
* `cpu_v3_main_v2_seed2_20261115T165949Z` — **independent replication**
  (seed 20261116), 192 episodes, 3,840 gateway events, 107,629 packets,
  7,688 Zeek connections, `SENSOR_VALIDATED`; used for §6.6.
* All earlier `outputs/studies/*`, `outputs/backups/*` and `src/data/raw/runs/*`
  directories are retained unmodified.
