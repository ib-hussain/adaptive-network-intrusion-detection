# MEMORY.md — Adaptive Network Intrusion Detection: Phase 3 continuity record

**Snapshot date:** 15 November 2026.  
**Purpose:** persistent project context for the next agent/operator. Read this with `AGENTS.md`, `SKILLS.md`, and `INSTRUCTIONS.md` before changing code or making claims. This file records what is known, what remains only a diagnostic result, and what must be reproduced on the current CPU-only machine.

## 1. Project identity and research commitment

- **Owner:** Ibrahim Hussain. This is the Computer Networks semester research project, separate from all other coursework/projects in the wider workspace.
- **Working title:** *Adaptive Network Intrusion Detection and Early Warning through Game-Theoretic Scenario Generation and Temporal Network Analysis*.
- **Core question:** under equal collection budgets and a frozen common test set, can fixed, uniform-random, or finite strategic (EXP3-style) selection of safe, controlled network scenarios improve (a) incident detection and (b) genuinely pre-milestone early warning of held-out multi-stage communication behaviour?
- **Central discipline:** network behaviour: directed host-to-host communication, flow volume/direction, timing, bursts, protocol/service interactions, topology/segment changes, PCAP and Zeek visibility. ML assists the network experiment; it must not become a generic security application.
- **Required outputs:** detection and early warning. Response/containment recommendations and next-stage prediction are optional and must be evaluated separately.

### Early-warning definition (do not alter retrospectively)

For each incident episode `e`, define independently in the scenario journal: scenario onset `t0,e`, later milestone `tm,e`, and model first alert `ta,e`.

```text
valid early alert iff t0,e <= ta,e < tm,e, using only observations available by ta,e
lead time L_e = tm,e - ta,e, only for valid alerts
```

Report warning coverage over **all** incident episodes, mean/median lead conditional on a valid alert, coverage-adjusted lead (zero for misses), false-positive episodes, false alarms per benign hour, precision/recall/F1/PR-AUC where applicable, compute time, and uncertainty. A pre-onset alert is false/invalid; post-milestone detection is late. Do not report prediction when the held-out future-positive set is empty.

### Scope and safety boundaries

The lab uses isolated Docker containers and harmless synthetic HTTP/network traffic. It excludes real malware, live exploitation, self-propagation, attacks outside the private lab, exposed vulnerable services, Kubernetes, autonomous zero-day discovery, multi-LLM coordination, and a production SIEM/dashboard. “Zero-day-like” may only mean a held-out non-destructive laboratory *behavioural pattern*, never a real zero-day claim. Docker containers share a kernel and must not be treated as safe malware isolation.

## 2. Academic integrity and evidence rules

All reported numbers, plots, PCAP facts, Zeek facts, screenshots, command outputs and citations must be traceable to real inputs and reproducible commands. Never fabricate, backdate, edit, relabel, or selectively present results/figures/evidence. Do not turn a failed or inconclusive run into a successful one. Preserve failures with their logs and say exactly what they establish.

Permitted and useful work under a deadline:

- use a smaller CPU-feasible experimental design;
- use clearly labelled pilot/diagnostic results;
- repair and rerun experiments;
- leave an incomplete method as an explicit limitation;
- create diagrams that represent the implemented architecture, not claimed measurement;
- compare literature methodologically rather than claiming numerical superiority on incompatible datasets.

The Phase 3 rubric expects implementation, dataset/preprocessing/splits, baseline metrics, graphical results, comparable research context and limitations, ablations, analysis/discussion, and reproducibility. Every substantive claim needs a source artifact, command, run ID and timestamp.

## 3. Current machine: target configuration

The new local machine reported on 15 November is CPU-only:

| Component | Reported state | Consequence |
|---|---|---|
| OS | Ubuntu 26.04, kernel 7.0.0-42-generic | Do not copy assumptions from university Ubuntu 24.04 verbatim. |
| CPU | Intel i5-6500, 4 cores, 3.60 GHz | Use modest parallelism, normally 2 workers/threads. |
| RAM | 14.95 GiB, ~4 GiB initially used | Avoid large in-memory graphs, huge Optuna studies, and concurrent training/capture. |
| GPU | Intel HD 530 only; no CUDA | All work must run on CPU; never select CUDA automatically. |
| Docker | 29.9.3 | Verify daemon access, Compose config and private networks. |
| Zeek | 9.0.1 | Validate it on a fresh PCAP, not merely `--version`. |
| Storage | 227 GiB root ~67% used; second 171.9 GiB ext4 nearly empty | Locate the large volume before collection; monitor Docker root separately. |

Suggested CPU environment:

```bash
export PYTHONUNBUFFERED=1 PYTHONHASHSEED=20261115
export OMP_NUM_THREADS=2 MKL_NUM_THREADS=2 OPENBLAS_NUM_THREADS=2 NUMEXPR_NUM_THREADS=2
export CUDA_VISIBLE_DEVICES="" TOKENIZERS_PARALLELISM=false
```

## 4. Repository and inputs

The transferred archive was originally extracted as a source tree rather than a
Git checkout. It is **now a normal Git repository** on `master` with a linear
history; use `git rev-parse HEAD` for the current commit, and continue to keep
file hashes, dated backups (`outputs/backups/`), logs and run IDs for evidence
continuity. Raw evidence (PCAPs, `src/data/raw/*`, checkpoints) is intentionally
Git-ignored and belongs in the submission bundle, not in Git. The root contains:

| Location | Role |
|---|---|
| `compose.yaml` | bounded network lab topology |
| `setup/` | collection, capture audit, Zeek parsing, training and status scripts |
| `src/code/` | game, ingestion, causal features, early warning, models, pipeline and figures |
| `src/data/raw/runs/<run_id>/` | manifests, journals, gateway logs, PCAPs and raw collection evidence |
| `src/data/processed/` | derived features; never overwrite raw evidence |
| `outputs/` | models, HPO, tables, figures, audits and run summaries |
| `tests/` | focused regression tests |
| `researchPapers/` | Phase 1/2 literature and methodology context |
| `AGENTS.md`, `SKILLS.md` | repository-specific constraints |

Raw data was deliberately absent from the transfer archive in some historical snapshots. Do not expect old PCAPs or raw run folders to exist. Treat copied PDFs/reports as history, not replacement evidence for a fresh local run.

## 5. Research history that must remain distinguishable

### Phase 1 and Phase 2 commitments

The project pivoted away from an earlier AIOps/root-cause-localisation concept. Phase 3 must evaluate the new network-centric proposal: bounded scenario controller, fixed/random/strategic collection policies, isolated clients/gateway/services, independent ground-truth journal, PCAP plus Zeek and application-gateway observations, causal episode-safe features, matched baseline models, frozen common test episodes, early-warning metrics, costs and ablations.

Phase 1/2 papers and related code links are methodological references only. Do not claim an exact replication or direct numerical superiority unless the same data/splits/protocol genuinely match.

### V3 capture: corrected historical account

The old handover stated that the V3 capture hotfix was unverified. That is stale. Later records show that `setup/staged_collect_v3.sh` was corrected to invoke tcpdump with `-Z root` while retaining narrow capabilities (`--cap-drop ALL`, `--cap-add NET_RAW`, `no-new-privileges`). This addressed tcpdump's forbidden UID/GID change in the restricted container.

Run `staged_v3_check_02` subsequently completed as a **limited structural pilot**:

| Fact | Historical observation | What it supports |
|---|---:|---|
| Episodes | 24 | bounded collector loop ran |
| Gateway events | 480 | traffic/application events were generated |
| PCAP bytes | ~1.696 MB | capture had packet content, unlike a 24-byte header failure |
| Packet records | 13,550 | structural PCAP existence |
| Zeek audit | 960/984 connections assigned across all 24 episodes | parser association coverage |
| Test episodes | each had >=3 events | basic hold-out representation |

This does **not** establish sensor-valid network evidence. The historical Zeek parsing used `zeek -C`; checksum validation was disabled. The association audit alone did not prove reliable bidirectional byte visibility, correct service-direction attribution, or realistic attack semantics. Existing models from this tiny pilot are diagnostic only, not a final comparative study.

### Other V3 defects/limitations

- `setup/staged_train_guard_v3.sh` historically checked only basic PCAP structure.
- `setup/staged_train_start.sh` generated a Zeek worker that gated on window coverage (>=0.90) and missing test episodes, but not robust byte/direction/bidirection criteria.
- `setup/staged_zeek.py` always invoked `zeek -C` and recorded a caution that it does not prove bidirectional visibility/realistic attacks.
- The stronger checks in `setup/sprint_zeek_eval.py` were not necessarily on the V3 training path.

Any future run should receive a stricter evidence tag before it can feed the main results. See Section 7.

### Earlier V2 and initial software checks

- `staged_v2_main_01` was incomplete: probes passed but `docker compose run` ended with code 124 before full collection. It is not a final dataset.
- Early laptop/WSL CPU smoke checks reportedly exercised 32 episodes/384 requests and 13 tests. That verifies earlier software behaviour only; it is not a new-machine verification and not empirical network evidence.
- A historical CUDA GRU ran 80 epochs in an earlier environment. Do not treat it as reproducible on this host or as final until documented/re-run appropriately on CPU.

### OrgLab add-on: lower priority, not a shortcut

`orglab/` expands the lab to roughly 20–50 employee containers and application-derived edge graphs. Its `tcpdump -Z root` fix later allowed PCAP creation, but `org20_pilot_02` (48 episodes, 1,152 events, 32,383 PCAP packets) and a smoke run failed Zeek semantic validation: zero bidirectional coverage, zero bytes/only OTH control connections. Later runs hit Docker address-pool exhaustion because cleanup stopped Compose services but left networks. No valid OrgLab model run exists.

Treat OrgLab as an optional extension only after the compact V3 pipeline is sensor-validated. It is not a Zeek-native graph model; it is a gateway/application edge graph. Never make that distinction disappear in the report.

## 6. Required experimental design

### Comparable policies and data splits

- Policies: fixed, uniform random and strategic/EXP3 where implemented.
- Equalise policy action budget, collection episode budget, traffic parameters and compute budget.
- Split at **episode** level before windows/features. Keep each test episode completely unseen during train/HPO/threshold selection.
- Freeze a common held-out test set for every policy. Prefer holding out a scenario family and, if topology variants exist, a topology too.
- Fit scalers/encoders/imputation only on train. Tune thresholds/HPO only on train/validation. Never use test alerts as strategic-policy reward.
- Keep a manifest that maps every feature window to episode, policy, scenario, split, onset, milestone, source files and code/config hash.

### Baselines in practical order

1. transparent threshold/rate or rule baseline;
2. Isolation Forest/anomaly baseline, if supported by legitimate training assumptions;
3. Random Forest supervised baseline;
4. small CPU temporal model (GRU) only after tabular baselines work; fixed seed, small hidden size and early stopping;
5. graph method only if actual graph inputs, labels, splits and enough compute exist. Otherwise document it as a deferred design element rather than simulating an outcome.

The model comparison must use the same observation source, episode split, alert timing rule and test episodes. Note whether each model uses gateway logs, Zeek-derived flow features, PCAP-derived measurements, or a combination.

## 7. Evidence taxonomy and release gate

Attach a status tag to every run/table/figure:

| Tag | Meaning | May support final empirical claim? |
|---|---|---|
| `INVALID_CAPTURE` | empty/header-only/failed capture or missing ground truth | No |
| `GATEWAY_DIAGNOSTIC` | gateway/app logs only; useful software/traffic diagnostic | Only if labelled gateway-only |
| `PCAP_STRUCTURAL` | nonempty PCAP and packet count/size checks | Not sensor semantics alone |
| `ZEEK_CONDITIONAL` | Zeek parsed, but checksum/direction/byte evidence insufficient | Only with limitation, not core proof |
| `SENSOR_VALIDATED` | fresh PCAP/Zeek pass declared semantic checks and independent journal alignment | Yes, within stated lab scope |
| `RESEARCH_READY` | sensor-validated plus fixed split, provenance, baselines, audit and reproducible final bundle | Yes |

A main empirical result needs `RESEARCH_READY`. Minimum sensor checks should include: PCAP is non-empty and parseable; Zeek logs are nonempty; expected service/port appears; both directions/bytes are visible for an appropriate fraction of expected request-response flows; connections map to journal episodes; test episodes have eligible pre-milestone windows; and any use of `-C` is explicitly surfaced. If a check fails, quarantine the run from final training.

## 8. CPU-feasible target and time discipline

The goal is a defensible compact study, not scale. Recommended steps:

1. inspect and install/verify dependencies;
2. run focused tests and a one-episode capture/Zeek validation;
3. collect a small pilot (3 rounds plus 3 test rounds) and resolve data-contract issues;
4. collect one practical main dataset after validation: 8 rounds + 8 test rounds (64 episodes/1,280 requests if the current suite retains 8 episodes/round); increase only if time/storage permit;
5. build one immutable processed dataset and manifests;
6. run rule, IF and RF baselines with small, fixed HPO; run GRU only if time remains;
7. generate plots directly from final metrics tables; run specified ablations; write limitations honestly.

Set threads to two. Capture and train sequentially. Avoid large Optuna sweeps, long neural epochs, concurrent Docker batches, and recursive scans of `outputs/backups`. Use `python -m pytest -q tests` rather than repository-wide discovery if backup copies are present.

## 9. Reproducibility bundle required before submission

For every final run, preserve:

- immutable raw run directory with PCAPs/logs/journal/manifests;
- `environment.txt` (OS, Python, package versions, Docker/Compose, Zeek, CPU/RAM, relevant environment variables);
- exact invoked commands/config/seeds, start/end UTC timestamps and exit status;
- evidence audit JSON/CSV with taxonomy tag and pass/fail reasons;
- preprocessing summary: source rows, exclusions, missing-value handling, features, label definitions, split counts and leakage controls;
- `metrics.csv` with raw counts as well as rates; predictions/alerts keyed by episode/window;
- generated figure source data and scripts; no manually edited plots;
- final report table mapping each claim to artifact path/run ID;
- submission bundle produced by `setup/package_phase3_submission.py`
  (`submission_manifest.json`, `SHA256SUMS.txt`, `README_REPRODUCE.md`, ZIP);
- failures and limitations log.

## 10. Append-only current progress log

### 15 November 2026 — CPU-machine handover prepared

- New operator reported Ubuntu 26.04, Docker 29.9.3 and Zeek 9.0.1 on the i5-6500 CPU-only desktop; CUDA is unavailable.
- The prior documentation was identified as stale because it said the V3 capture hotfix had not been verified. This memory corrects that statement while preserving the V3 pilot's limited/conditional status.
- The project archive in this workspace is a transferred source tree, not a Git checkout. No fresh local collection, tests, model training or empirical claims were made while preparing this handover.
- The next operator must execute `INSTRUCTIONS.md` from the actual local repository and append outcomes here or in the designated progress log. Do not overwrite historical entries.

### 15 November 2026 — CPU Phase 3 executed on the local machine (VERIFIED)

**Status: a complete, sensor-validated Phase 3 study now exists on this machine.**
Primary run `cpu_v3_main_v2_20261115T164430Z`, evidence tag **`SENSOR_VALIDATED`**.
Report: `outputs/reports/cpu_v3_main_v2_20261115T164430Z/PHASE3_REPORT.md`.

**What was collected (all fresh, this machine, seed 20261115).**

| Run | Schema | Episodes | Gateway events | PCAP | Packets | Tag |
|---|---|---:|---:|---:|---:|---|
| `cpu_v3_pilot_20261115T162845Z` | v2_1 | 24 | 480 | — | — | failed (restricted writer) |
| `cpu_v3_pilot_20261115T163008Z` | v2_1 | 24 | 480 | — | — | failed (gateway could not write) |
| `cpu_v3_pilot_20261115T163257Z` | v2_1 | 24 | 480 | 1.70 MB | 13,551 | `SENSOR_VALIDATED` |
| `cpu_v3_main_20261115T163638Z` | v2_1 | 64 | 1,280 | 4.48 MB | 35,951 | `SENSOR_VALIDATED` (superseded: test set held only the unseen family) |
| `cpu_v3_pilot_v2_20261115T164336Z` | v2_2 | 24 | 480 | 1.70 MB | 13,545 | `SENSOR_VALIDATED` |
| **`cpu_v3_main_v2_20261115T164430Z`** | **v2_2** | **192** | **3,840** | **13.42 MB** | **107,628** | **`SENSOR_VALIDATED`** |

**Three real faults were found and fixed (each with a dated backup and a regression test).**

1. *Executable bit lost in transfer* — every `setup/*.sh` was mode 0644, so the
   documented `./setup/staged_collect_v3.sh` failed with "Permission denied" and
   `staged_train_guard_v3.sh` could not `exec` its successor. Modes restored to
   0755; evidence in `outputs/backups/setup_script_modes_20261115T162353Z/`.
2. *Restricted sidecar could not create the PCAP* — the capture container runs
   `cap_drop: ALL` (no `DAC_OVERRIDE`) and the bind-mounted run directory is
   0755 owned by the host user, so tcpdump failed with
   `/captures/....pcap: Permission denied`. Fixed by **pre-creating the capture
   file mode 0666** before `docker run`; container capabilities were NOT
   widened. Regression test added to `tests/test_v3_launcher_contract.py`.
3. *Lab services could not write their data* — the same `cap_drop: ALL` root
   cause silently discarded **every gateway event**. Fixed by running the
   services as the invoking host user (`LAB_UID:LAB_GID` in `compose.yaml`),
   which removes the need for any capability rather than adding one. This fault
   was invisible in the logs because the gateway wrote its event *after* sending
   the HTTP response.

**The `-Z root` hotfix is confirmed working.** The historical blocker
(`Couldn't change to 'tcpdump' uid=100 gid=101`) does not occur on this host.

**New artefacts (this session).**

* `setup/staged_sensor_gate.py` — strict 7-check gate writing `sensor_audit.json`
  with an evidence tag; fail-closed; never synthesises flows or bytes.
* `setup/pcap_checksum_repair.py` — derives a copy with recomputed checksums and
  *proves* that only checksum bytes changed. The container veth leaves NIC
  transmit offloading on, so the raw capture has invalid TCP checksums and
  strict Zeek discards all payload (`orig_pkts=0`). The repaired copy is re-read
  by Zeek **with checksum validation enabled**; it yields the same connection
  count as an independent `-C` read (7,688 = 7,688) and no `weird.log`.
* `setup/record_environment.py`, `setup/run_inventory.py`,
  `setup/literature_comparison.py` (15 unique references extracted from the held
  PDFs), `setup/claim_artifact_table.py`, `setup/verify_report_numbers.py`.
* `src/code/study.py` — leakage-safe preprocessing bundle, strata, baselines,
  ablations, `metrics.csv`; `src/code/report_figures.py` — 8 figures generated
  from saved metrics with the source data stored beside each.
* `src/code/models.py` — `RuleRateBaseline` (transparent rate rule).
* `src/code/early_warning.py` — added `strict_first_alert_coverage`: the
  episode's **first** alert must lie in `[onset, milestone)`. This metric
  changed the headline conclusion and is now reported everywhere.

**Protocol change (documented, versioned).** Scenario schema `staged_v2_2`
stratifies the frozen test set 50/50 between the held-out family (`slow_ramp`)
and the three development families. Under `staged_v2_1` the test set contained
*only* the held-out family, so every policy scored ~0 and the policy comparison
was uninformative. The old runs are preserved and were **not** retro-fitted.

**Headline verified findings (Zeek sensor, 48 frozen test episodes).**

| Train policy | Model | Coverage | Strict coverage | Coverage-adj. lead (s) | FP-episode rate | Pre-onset alarms |
|---|---|---:|---:|---:|---:|---:|
| fixed | RF | 0.958 | 0.917 | 0.664 | 0.625 | 1 |
| random | RF | 0.833 | 0.833 | 0.567 | 1.000 | 0 |
| strategic | RF | 1.000 | **0.042** | 0.627 | **0.083** | **23** |

* No policy dominates. `fixed`/`random` give genuine on-set warnings but a very
  high false-alarm rate; `strategic` is the quietest detector but its first
  alert precedes onset in 23 of 24 incident episodes, so under the strict
  definition it does **not** demonstrate pre-impact warning.
* Mechanism visible in the controller journal: the EXP3 selector chose
  `destination_shift` in 11/24 strategic rounds (fixed 8/8/8, random 5/11/8),
  skewing the strategic training corpus towards a signature that is also present
  in the pre-onset warm-up.
* The Isolation Forest **never warns** at any admissible threshold (coverage 0,
  FPR 0) although its PR-AUC is 0.79–0.83 — a genuine negative result.
* The rule/rate baseline reaches only 0.333 coverage and **0.000** on the
  unseen family.
* GRU (CPU, 12 epochs, 10.5 s): `random` is the best balance (coverage 0.833,
  FPR 0.042, no pre-onset alarms); the GRU never fires before onset.
* Source dependence is real: on the gateway sensor strategic/RF falls to 0.250
  coverage on the unseen family.

**Ablations actually run:** scenario policy; temporal causal features (removing
`rate_per_s`/`gap_*`/`large_flow_fraction` collapses the rule baseline to 0.000
coverage while the RF degrades gracefully); warning rule (persistence 2 cuts
coverage and false alarms together, and leaves strict coverage unchanged);
observation source (Zeek vs gateway, never merged); unseen scenario family.
**Unavailable and explicitly listed:** graph relations (no graph model exists —
`unique_links` is not a GNN) and topology generalisation (one configuration only).

### 15 November 2026 — Independent replication (second seed), also VERIFIED

Run **`cpu_v3_main_v2_seed2_20261115T165949Z`**, seed **20261116**, identical
protocol (24 + 24 rounds). 192 episodes, 3,840 gateway events, 107,629 packet
records, 7,688 Zeek connections, **`SENSOR_VALIDATED`** with 100 % bidirectional
visibility, 0 ambiguous joins, 192 / 192 episodes covered. The capture and
sensor pipeline reproduces its counts exactly.

**This changes the conclusion of the first seed, and the change is the most
important result of the session.**

| Zeek, Random Forest | strict coverage s1 | s2 | FP rate s1 | s2 | pre-onset alarms s1 | s2 |
|---|---:|---:|---:|---:|---:|---:|
| fixed | 0.917 | 0.917 | 0.625 | 0.167 | 1 | 0 |
| random | 0.833 | 0.542 | 1.000 | 0.042 | 0 | 0 |
| strategic | **0.042** | **0.875** | 0.083 | 0.208 | **23** | **0** |

* **Replicates:** the capture/sensor pipeline; the GRU's total absence of
  pre-onset alarms (0 in all six GRU configurations); the strategic policy's
  conservatism under the GRU (lowest FP rate in both seeds); the weakness of
  the Isolation Forest and the rule baseline on the unseen family; the
  systematic EXP3 skew towards `destination_shift` (13/24 in seed 2, 11/24 in
  seed 1).
* **Does not replicate:** the pre-onset artefact of strategic/RF (23/24
  episodes in seed 1, **0/24** in seed 2). It was a seed-specific instability,
  **not** a structural property of the strategic policy — even though the
  profile skew that was suspected as its cause is itself systematic.
* **Therefore:** with two seeds the study **cannot** establish a policy
  ranking on warning coverage; the ranking moves with the seed. The stable
  finding is a trade-off: the strategic selector yields the most conservative
  detectors, the fixed selector the most sensitive, and the difference is of
  the same order as the seed-to-seed variation. A single-seed ranking must
  not be reported as a result.

Artefacts: `outputs/reports/<run>/seed_comparison.csv`,
`figures/zeek/fig09_seed_comparison.png`, `outputs/reports/<run2>/run_inventory.json`,
`outputs/reports/<run2>/gru_metrics.csv`,
`outputs/studies/<run2>_zeek_20261115T170436Z/`.
The number check now covers **102** quoted values across both seeds.

**Verification.** `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest -q tests`
→ **53 passed** (45 at the first freeze, plus tests for the submission packagers).
`python -m setup.verify_report_numbers ...` → **102 checks, 0 mismatches, PASS** (`outputs/reports/<run>/report_number_verification.json`).
`claim_artifact_table.csv` maps 177 reported values to their artefacts.

**Still true and still to be respected.** The traffic is harmless and synthetic:
no malware, no exploitation, no exfiltration, no zero-day claim, no production
NIDS performance claim. Two seeds only. One topology only. The strategic reward
is a **heuristic** scenario-selection reward, not detector feedback and not a
Nash equilibrium. The `zeek -C` / checksum-offload caveat remains and is
surfaced in every sensor artefact.

### 15 November 2026 — Finalisation and submission packaging (VERIFIED)

The study was frozen and packaged for submission; no new collection or training
was performed.

* **Verification captured** under `outputs/logs/final_verification/<UTC>/`:
  `compileall` rc 0, `bash -n setup/*.sh` rc 0,
  `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest -q tests` → **53 passed**
  (log `outputs/logs/final_verification/20261115T174629Z/verification.log`),
  and `setup/verify_report_numbers.py` → **102 checks, 0 mismatches, PASS**.
* **Documentation reconciled.** `README.md` now describes a completed study and
  separates *reviewing existing evidence* from *reproducing from scratch*;
  the stale "implementation foundation" wording and the broken
  `docs/IMPLEMENTATION_PLAN.md` link are gone. `AGENTS.md` §12 carries the
  verified state instead of the obsolete capture blocker. This file and
  `INSTRUCTIONS.md` were brought in line with the final run IDs.
* **Report corrections** (each supported by a stored artefact, no metric
  changed): the §2.4 checksum demonstration now quotes the *main* run's
  numbers (15,376 strict records vs 7,688 usable connections) instead of the
  pilot's; the stale "no second seed" deviation text now points to §6.6; the
  number-verifier count is 102; the failed-pilot ID is corrected to
  `cpu_v3_pilot_20261115T162845Z`.
* **Evidence bundle** built by `setup/package_phase3_submission.py`, which fails
  closed if any required raw artefact is missing. It writes
  `submission_manifest.json`, `SHA256SUMS.txt` and `README_REPRODUCE.md`, and
  produces one ZIP **outside Git tracking** (PCAPs, journals, studies,
  figures, audits, environment and verification logs). Raw PCAPs and run
  directories remain uncommitted by design.

Remaining limitations are unchanged and are listed in §9 of the report: two
seeds, one topology, synthetic harmless traffic, checksum-repaired derived
PCAP, heuristic reward, and no graph model or topology generalisation.
