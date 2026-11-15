# INSTRUCTIONS.md — CPU-only Phase 3 execution runbook

**Audience:** OpenCode or another terminal agent operating this project on Ibrahim's new Ubuntu desktop.  
**Status:** active handover, 15 November 2026.  
**Read order:** `AGENTS.md` → `MEMORY.md` → `SKILLS.md` → this file → the live code and logs. The live tree and newly generated artefacts outrank historical claims.

## 0. Mission and non-negotiable contract

Deliver the strongest **defensible, reproducible, CPU-feasible** Phase 3 submission that can be completed on this local machine. The project compares bounded fixed, random and strategic scenario selection for network anomaly detection and valid pre-milestone warning. It must remain a Computer Networks experiment using authorised isolated synthetic traffic.

Never fabricate, edit, backdate or misrepresent results, figures, packet evidence, logs, screenshots, datasets, model outputs, citations or completion status. Never hide a failed gate. If a component cannot be completed in time, retain the real evidence, label it pilot/conditional/deferred, and explain the limitation. This is essential to a defensible submission.

Do not introduce real malware, offensive/external scanning, public services, Kubernetes, broad container privilege, a production dashboard, or unrelated frameworks. Do not use `docker system prune`, `docker compose down -v`, blanket process kills, hard Git resets, or deletion of data/PCAPs/backups. Preserve all previous runs, including failed ones.

## 1. What the Phase 3 assessment requires

The supplied *Phase 03 – Implementation* brief requires the following. Treat this table as the submission acceptance matrix.

| Requirement | Real deliverable/evidence | Gate |
|---|---|---|
| 1. Implement proposal; document departures | source modules, architecture/config, change log, explicit deviations | code imports and a small real run succeed |
| 2. Data, preprocessing, experimental setup | raw manifest/journal, source/sensor provenance, feature/split report | episode-level split before windows; no leakage |
| 3. Baseline evaluation and required metrics | raw predictions/metrics for rule, IF, RF; optional GRU | same frozen test and alert rule |
| 4. Graphical results | scripts plus CSV/JSON inputs for each plot | plots generated from final tables only |
| 5. Comparable existing research + limits | method/settings comparison table and limitations | no cross-dataset numeric superiority claim |
| 6. Ablation study | policy, causal features, threshold/persistence, source and graph status | each ablation actually re-run or marked unavailable |
| 7. Results analysis/discussion | errors, false alarms, misses, uncertainty, threats to validity | claims bounded by evidence |
| Reproducibility | environment, exact commands, seeds, hashes, outputs, run log | a fresh reader can identify inputs/steps |

The brief asks for full implementation/evaluation. A compact real study is better than invented scale. Do not claim a graph neural network, network-topology generalisation, real intrusion detection, zero-day discovery, predictive forecasting or publication-score comparison unless the required data and experimental proof exist.

## 2. Current target machine and CPU policy

Reported host: Ubuntu 26.04, kernel 7.0.0-42-generic; Intel i5-6500 (4 cores); 14.95 GiB RAM; Intel HD 530; no CUDA; Docker 29.9.3; Zeek 9.0.1. Root storage is ~67% used and a second ext4 volume is almost empty.

Use the large volume for raw PCAPs/artefacts only if it can be mounted/used without institution/system changes; otherwise monitor both `df -h` and Docker's actual root directory. Capture and training must not overlap. Restrict threads and use low-cost first passes:

```bash
export PYTHONUNBUFFERED=1 PYTHONHASHSEED=20261115 TOKENIZERS_PARALLELISM=false
export CUDA_VISIBLE_DEVICES=""
export OMP_NUM_THREADS=2 MKL_NUM_THREADS=2 OPENBLAS_NUM_THREADS=2 NUMEXPR_NUM_THREADS=2
```

Use fixed seed `20261115` for the first reproducible CPU run. Record any later seed and why it exists. Do not start 30-trial HPO plus an 80-epoch GRU on this host until basic collection/baselines have passed; the stock launcher starts several jobs in parallel and is not an appropriate first action on a four-core desktop.

## 3. Evidence model and status labels

Every raw run, table and figure must state one of these labels in metadata/caption:

| Label | Meaning | Permitted use |
|---|---|---|
| `INVALID_CAPTURE` | failed, empty, header-only or unaligned capture | failure analysis only |
| `GATEWAY_DIAGNOSTIC` | only application/gateway observations are usable | implementation result, explicitly gateway-only |
| `PCAP_STRUCTURAL` | nonempty and parseable PCAP | structural result, not semantic sensor validation |
| `ZEEK_CONDITIONAL` | Zeek parses but direction/bytes/checksum caveat remains | conditional diagnostic with caveat |
| `SENSOR_VALIDATED` | fresh PCAP/Zeek/episode alignment pass declared semantic checks | network-sensor results within lab scope |
| `RESEARCH_READY` | sensor-valid, frozen split, baselines, provenance, audit and repeatable bundle | final empirical result |

`staged_v3_check_02` is historical `PCAP_STRUCTURAL` / at best `ZEEK_CONDITIONAL`, not `RESEARCH_READY`: it had 24 episodes, 480 gateway events, ~1.696 MB PCAP and 13,550 records; Zeek associated 960/984 connections across all episodes, but ran with `zeek -C` and did not prove adequate bidirectional byte visibility. Old V2 was incomplete. OrgLab runs are currently invalid for network modelling because their Zeek semantic gate reported zero bidirectional coverage/zero bytes. Do not use any of these as newly collected CPU results.

## 4. Stage A — establish the actual local baseline (read-only first)

From the repository root, run the following and save its complete terminal output under a unique path such as `outputs/logs/setup/<UTC>/machine_inventory.log`. Do not assume this transferred source tree has `.git`; `git` output may legitimately say it is not a repository.

```bash
pwd
git rev-parse --show-toplevel 2>/dev/null || true
git status --short --branch 2>/dev/null || true
find . -maxdepth 2 -type f \( -name 'AGENTS.md' -o -name 'MEMORY.md' -o -name 'INSTRUCTIONS.md' -o -name 'compose.yaml' -o -name 'requirements.txt' \) -print | sort
python3 --version
nproc; free -h; df -h . /var/lib/docker 2>/dev/null || true
docker --version; docker compose version; docker info --format '{{.DockerRootDir}}' 2>/dev/null || true
docker ps -a
docker compose -f compose.yaml config --quiet
zeek --version
command -v tcpdump && tcpdump --version | head -2 || true
jobs -l
ps -eo pid,ppid,stat,etime,args | grep -E '[s]taged_collect|[t]cpdump|[d]ocker compose' || true
find src/data/raw/runs outputs -maxdepth 3 -type f \( -name 'complete.json' -o -name 'collector_status_v3.json' -o -name '*.pcap' -o -name '*.sqlite3' \) -printf '%p %s\n' 2>/dev/null | sort | head -200
```

Confirm Docker networks are internal after services start; confirm no unrecognised old capture/container is active. If Docker socket access fails, record the exact error and use the user's approved normal re-login/group route. Do not loosen socket permissions, alter the daemon, or use `sudo` as a workaround without permission.

Append a terse record:

```text
UTC | repo state/hash or no-Git source tree | Python/Docker/Zeek versions
CPU/RAM/disk/DockerRoot | CUDA false/true | active jobs/containers
old raw runs discovered | next safe action
```

## 5. Stage B — install a reproducible CPU environment

First inspect `requirements.txt`; it already uses `torch==2.7.1` without a CUDA suffix. Create a project-local virtual environment only if one is absent or unusable. Do not replace an existing environment without recording why.

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
python -m pip install -r requirements.txt
python - <<'PY'
import sys, torch, numpy, pandas, sklearn, optuna, matplotlib
print('python', sys.version)
print('torch', torch.__version__, 'cuda', torch.cuda.is_available())
print('numpy', numpy.__version__, 'pandas', pandas.__version__)
print('sklearn', sklearn.__version__, 'optuna', optuna.__version__)
PY
```

If the default PyTorch wheel is unexpectedly GPU-linked/unusable, install the matching official CPU wheel and record the exact command and version in `outputs/.../environment.txt`. Never pretend CUDA is available and never write results to an ambiguous global interpreter. Save `python -m pip freeze`, `docker version`, `docker compose version`, `zeek --version`, `uname -a`, `lscpu`, `free -h`, `df -h`, relevant environment variables and SHA256 of core scripts to `environment.txt`.

## 6. Stage C — source audit, tests and a small safe repair plan

Before touching source, create a dated backup of each proposed changed source file under `outputs/backups/<change_id>/` and save SHA256 checksums. Inspect interfaces before edits:

```bash
rg -n -- '--rounds|--test-rounds|CAPTURE|Zeek|zeek -C|window_coverage|orig_bytes|resp_bytes|device auto|tmux' setup lab src tests
sed -n '1,330p' setup/staged_collect_v3.sh
sed -n '1,170p' setup/staged_train_guard_v3.sh
sed -n '1,180p' setup/staged_train_start.sh
sed -n '1,220p' setup/staged_zeek.py
python -m compileall -q lab src setup tools
bash -n setup/*.sh
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest -q tests
```

Do not run unscoped `pytest` if copied backup trees make test modules collide. A passing test suite verifies software behaviour, not capture validity.

Required source observations as of this handover:

- `setup/staged_collect_v3.sh` accepts `--run-id`, `--rounds`, `--test-rounds`, `--seed`, `--capture|--no-capture` and `--resume`; it requires 3–150 rounds and captures via a named restricted Docker sidecar.
- The correct sidecar command includes `-Z root -i any -p -nn -s 0 -U`, retains `--cap-drop ALL --cap-add NET_RAW` and `no-new-privileges`, and captures only `tcp port 8080` in the gateway network namespace.
- The collector's packet gate is structural only. The training guard is structural too; it must not be treated as a full Zeek semantic gate.
- `setup/staged_zeek.py` invokes `zeek -C`. That may be appropriate for locally offloaded checksum captures but must be treated as a caveat, never a blanket proof of sensor quality.
- `setup/staged_train_start.sh` launches baseline/HPO/GRU/Zeek jobs concurrently and has GPU-era defaults (`30` trials, `80` epochs). On this host, run stages explicitly/sequentially or add a small documented CPU-sequential option with regression coverage; do not overload the machine.

### Mandatory strict sensor-gate improvement before main network results

Implement a small, tested validator (or safely extend an existing audit) that reads a completed fresh run and writes `sensor_audit.json`. It must fail closed before any **network-sensor** training when any requirement fails:

1. `complete.json`, `episodes.jsonl`, `gateway_subset.jsonl` and at least one closed PCAP exist;
2. PCAP is nonempty, record-complete and has a sensible packet count relative to episode count;
3. Zeek exits zero and emits `conn.log`/JSON entries;
4. expected TCP/8080 service traffic is observed;
5. a documented threshold of eligible episode connections has positive `orig_bytes` **and** positive `resp_bytes` or an equivalent, clearly justified bidirectional criterion;
6. timestamps map to the independently recorded episode intervals using a documented rule; ambiguous/missing mappings are counted;
7. frozen test episodes have enough pre-milestone Zeek windows; and
8. the output marks `checksum_validation_ignored: true` if `-C` was used.

The validator must write all counts, denominators, failures, PCAP SHA256 and command provenance. It may tag a run `ZEEK_CONDITIONAL` if checksum bypass remains; it may only tag `SENSOR_VALIDATED` where all criteria really pass. Never create synthetic Zeek flows or byte counters to satisfy the gate.

## 7. Stage D — preflight the isolated lab

Run all traffic only after the Compose configuration parses and the required services are known. The collector itself checks that the `clients` and `services` networks are internal and makes four harmless labelled probe requests before the experiment. Confirm it actually does so in code.

```bash
docker compose -f compose.yaml config --quiet
docker compose -f compose.yaml up -d server_a server_b gateway
docker network inspect phase3-adaptive-nids_clients phase3-adaptive-nids_services \
  --format '{{.Name}} internal={{.Internal}}' 
docker compose -f compose.yaml ps
docker compose -f compose.yaml logs --tail=80 gateway server_a server_b
```

If naming differs, inspect `docker compose config` rather than guessing. Stop only the exact project services you started when a recovery is necessary; do not delete volumes or unrelated networks. A capture error such as `Couldn't change to 'tcpdump' uid...` means check whether `-Z root` is actually in the restricted V3 invocation. Do not solve it with `--privileged`, `--network host`, extra broad capabilities, or a host-wide tcpdump.

## 8. Stage E — fresh capture pilot, then sensor validation

Use a new run ID; never overwrite old artefacts. The smallest accepted settings are 3 training rounds and 3 test rounds. This creates enough episodes to test the full contract without committing a long CPU job.

```bash
export RUN="cpu_v3_pilot_$(date -u +%Y%m%dT%H%M%SZ)"
./setup/staged_collect_v3.sh \
  --run-id "$RUN" --rounds 3 --test-rounds 3 --seed 20261115 --capture \
  2>&1 | tee "outputs/logs/collection_${RUN}.log"
```

During collection, observe the generated run log/status and do not launch training. If interrupted, inspect the named collector log, `collector_status_v3.json`, `generator_*.log`, exact capture container and raw files. Use the same settings plus `--resume` only when the collector confirms the saved `scenario_config.json` matches exactly. A committed application-only run cannot be retroactively converted into a packet-captured run: make a new run.

When the collector stops cleanly, run structural and semantic audits using the virtual environment:

```bash
. .venv/bin/activate
python -m setup.staged_capture_audit \
  --pcap "src/data/raw/runs/$RUN"/traffic_*.pcap --min-packets 4
python -m setup.staged_zeek --run "$RUN" --output "outputs/audits/$RUN/zeek"
# Run the newly implemented strict sensor validator here; it must write sensor_audit.json.
```

Do not use a shell glob with a tool that accepts only one PCAP if the collector produced multiple segments; enumerate them deliberately or use the existing run-aware audit. Review the audit: packet count, endpoint/port, Zeek return code, assigned episodes, test window coverage, and positive bytes in both directions. If it fails, preserve the pilot and fix the first failed invariant. It can still support a gateway-only implementation demonstration when honestly labelled; it cannot support final Zeek network-model metrics.

## 9. Stage F — collect one CPU-feasible main dataset only after the pilot gate passes

After a `SENSOR_VALIDATED` pilot (or an explicitly chosen gateway-only fallback), collect one fresh main run. Start with 8 + 8 rounds; do not increase until the pilot runtime, storage and integrity are known. With the current generator's historical structure this is roughly 64 episodes and 1,280 HTTP requests, but derive actual counts from the manifest rather than presenting this estimate as a fact.

```bash
export RUN="cpu_v3_main_$(date -u +%Y%m%dT%H%M%SZ)"
./setup/staged_collect_v3.sh \
  --run-id "$RUN" --rounds 8 --test-rounds 8 --seed 20261115 --capture \
  2>&1 | tee "outputs/logs/collection_${RUN}.log"
```

Immediately close/audit capture, run the strict sensor validator, and produce a `run_inventory.json` containing: run ID; timestamps; config hash; exact command; policy/scenario/condition/split counts; episode count; request/event/PCAP/Zeek counts; source hashes; final evidence tag; all warnings; and deterministic paths. Freeze this raw directory read-only by convention—derived data must go elsewhere.

If the sensor gate cannot pass in time, execute the same split/preprocessing/baseline protocol on `gateway_subset.jsonl`, label every result `GATEWAY_DIAGNOSTIC`, and make the lack of validated Zeek telemetry the principal limitation. Do not merge gateway and Zeek records or describe gateway HTTP records as independent packet sensors.

## 10. Stage G — leakage-safe preprocessing and split audit

Build one provenance-preserving processed dataset. The scenario controller—not the model—must provide onset and milestone. The split happens by complete episode **before** windows. Maintain a row-to-episode mapping.

Required outputs under a new `src/data/processed/<RUN>/<stamp>/` or `outputs/datasets/<RUN>/<stamp>/`:

- `feature_schema.json`: names, dtypes, units, source sensor and causal cutoff;
- `split_manifest.jsonl` or CSV: episode ID, policy, profile, condition, split, start/onset/milestone/end, source path/hash;
- `preprocessing_report.json`: input counts, exclusions and reasons, missing-value strategy, fit-only transformations, class counts by split and pre-milestone eligible windows;
- `windows.parquet`/CSV or equivalent derived data with `episode_id`, `window_end_ts`, label, source and no future-only columns;
- `leakage_audit.json`: prove no `episode_id`, policy/profile/scenario name, milestone/onset timestamp, file path, deterministic IP shortcut, future statistic or target label is a feature.

Fit encoders/scalers/imputation only on training episodes and serialise them with schema/hash. Validation chooses thresholds/persistence and any HPO; the `test` policy remains frozen for final evaluation. Confirm test set has genuine relevant positives before calculating PR-AUC or warning scores.

## 11. Stage H — baselines and measured early warning

Run the following in order, sequentially, with a shared configuration file, same input sensor, same episode split, same causal windows, same validation-selected alert rule and same final test. Save predictions/alerts keyed by episode/window, not only aggregated rates.

1. **Rule/rate baseline:** transparent threshold over a causal traffic feature. Its threshold must be selected/declared without test tuning.
2. **Isolation Forest:** document the training assumption (for example benign-only training) and contamination/threshold process.
3. **Random Forest:** supervised tabular classifier, fixed CPU seed and bounded `n_jobs=2`.
4. **Small CPU GRU (optional):** only if the first three complete, with fixed seed, compact hidden size, 10–20 epochs, early stopping, one job, `device=cpu`; record that it is temporal, not a graph model.
5. **Graph model (optional):** only if valid captured host/flow graph inputs and a fair graph-free comparator truly exist. A count such as `unique_links` is not a GNN. Do not force this under the deadline.

The existing `src.code.pipeline` and related scripts may be used after inspecting exact CLI options. Prefer a new small CPU wrapper/config if needed rather than changing semantics silently. Do not use the stock `staged_train_start.sh` default parallel job launch on this host. If adding CPU-sequential mode, include `--device cpu`, `--hpo-trials` max 5, `--gru-epochs` max 20, `n_jobs=2`, separate output directories and visible logs/exit codes.

For every model/policy, write `metrics.json` and a tabular export containing raw TP/FP/TN/FN counts, number of episodes, number of positive incident episodes, number of benign hours, threshold/persistence, feature/split/config hash, runtime and evidence tag. Metrics should include precision, recall, F1, PR-AUC where class support permits, ROC-AUC only with caveats, false-positive episodes, false alarms/benign-hour, misses, late alerts, valid-warning coverage, conditional mean/median lead and coverage-adjusted lead.

Do not present overlapping feature windows as independent samples for confidence intervals. Bootstrap by episode (or independent run/topology if available), and record the resampling seed and interval method. A small sample may yield wide or undefined intervals; report that plainly.

## 12. Stage I — fair policy experiment and ablations

Policies must have the same action menu, episodes/traffic budget, scenario configuration and held-out final test. Historical `game_reward()` is a heuristic scenario-selection reward, not measured detector feedback or a game-theoretic equilibrium; use that exact wording in the report unless code is genuinely redesigned/evaluated.

Run only ablations that are real and feasible; the required table must distinguish completed from unavailable experiments.

| Ablation | Minimum real comparison | Interpretation |
|---|---|---|
| Scenario policy | fixed vs random vs strategic, same frozen test/data budget | primary hypothesis |
| Temporal causal features | full causal set vs timing/burstiness removed | impact of temporal evidence |
| Warning rule | selected persistence/threshold vs a predeclared alternative | alert stability/false-alarm trade-off |
| Observation source | gateway-only vs Zeek only, only if both pass their own gates | source dependence, never implicit merging |
| Unseen scenario | held-out `test`/scenario family versus development data | limited behavioural novelty, not zero day |
| Graph relations | graph vs graph-free only if a real graph model runs | otherwise list as deferred |
| Topology generalisation | only with independently measured second topology | otherwise explicitly unavailable |

Avoid calling random action selection a repeated independent strategic experiment. A one-seed compact study supports exploratory findings only. If time permits, collect/re-evaluate at least one additional seed using the same protocol; otherwise report seed dependence as a limitation.

## 13. Stage J — figures and report evidence

Generate every plot via versioned code from saved CSV/JSON metrics. Store the exact data next to the figure and make captions include run ID, sensor/evidence label, episode counts and uncertainty where applicable. Recommended figures:

1. lab architecture/data-provenance diagram (implementation diagram, not a measured result);
2. run/split composition bar chart (episodes by policy/condition/profile);
3. PR curves or precision/recall/F1 comparison, only for models with valid class support;
4. warning coverage vs false-alarm rate and coverage-adjusted lead comparison;
5. policy/ablation table or grouped bars with episode-bootstrap intervals;
6. runtime/resource table; and
7. error-analysis table: false positives, misses, late alerts and excluded sensor episodes.

Never redraw or manually alter a figure to look better. A diagram may be designed manually only if it accurately describes code/config; it must not contain invented numerical observations.

For literature comparison, use a table with each paper's dataset, threat/task, split, observation source, method, reported metric and incompatibility. State that cross-paper scores are not directly comparable when data/topology/label/split differ. Compare mechanisms and limitations instead of claiming that this lab score beats published work.

## 14. Stage K — final written Phase 3 structure

Keep the final report concise and evidence-linked:

1. implementation objective and deviation log;
2. isolated lab, safety and sensor/data provenance;
3. scenarios, independent onset/milestone truth and early-warning definition;
4. dataset/preprocessing/splits/leakage controls;
5. baselines, policy budget, tuning and CPU environment;
6. results and generated figures/tables;
7. ablations and error analysis;
8. fair literature-method comparison;
9. limitations/threats to validity; and
10. reproducibility appendix: run IDs, paths, commands, seeds/hashes and environment.

Essential limitations likely to remain: synthetic harmless HTTP profiles; small lab scale; one defined topology unless another is actually measured; `zeek -C` checksum caveat if used; limited independent seeds; exploratory statistical power; heuristic strategic reward; and no real malware/zero-day proof. These are not defects to hide—they make the claims accurate.

## 15. Troubleshooting and recovery

| Symptom | Safe response |
|---|---|
| Docker permission/daemon unavailable | capture exact error; use approved re-login/context; do not change daemon/socket permissions |
| `Couldn't change to 'tcpdump' uid...` | verify `-Z root` is in the V3 restricted command; preserve minimal capabilities; inspect container log |
| PCAP is 24 bytes/zero records | tag `INVALID_CAPTURE`; stop training; retain files/logs; make a new run after root-cause fix |
| collector lock held | inspect jobs/process tree; a stopped job may retain `flock`; terminate only confirmed job, never delete lock blindly |
| runner exit 124 or hang | inspect `generator_*.log`, heartbeats, round files, named capture and disk; preserve state; use exact `--resume` only when settings match |
| Zeek has zero bytes/OTH only | treat sensor gate as failed; inspect capture namespace/filter and connection direction; never synthesize values |
| old run cannot be captured retroactively | preserve it as application-only; use new run ID for capture |
| Docker address-pool exhaustion (OrgLab) | keep OrgLab out of main path; inspect exact old networks and stop only project-owned stale networks with approval; no global prune |
| pytest sees duplicate modules from backups | run `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest -q tests` and avoid placing source-like backups where pytest recurses |
| no positive test class / PR-AUC undefined | do not compute/claim the metric; report split limitation and revise design only before freezing data |
| resource pressure | lower model size/epochs/trials, run stages sequentially and preserve partial evidence; never invent full-scale result |

## 16. Completion checklist and final handover format

Do not say “complete” until all applicable boxes have direct artifact paths.

```text
[ ] Read current docs and captured local machine inventory
[ ] Environment recorded; CPU path verified; focused code tests/syntax pass or exact failure logged
[ ] Isolated Docker topology and capture preflight verified
[ ] Fresh pilot has raw journal/PCAP/audit; evidence tag assigned
[ ] Strict Zeek sensor gate added/tested, or gateway-only fallback explicitly selected
[ ] Fresh main run has immutable raw manifest, hashes, split/provenance and status log
[ ] Causal preprocessing and leakage audit saved
[ ] Rule, IF and RF baselines use same frozen test and valid early-warning rule
[ ] Optional GRU/graph accurately labelled or explicitly deferred
[ ] Policy/feature/threshold ablations saved or shown as unavailable
[ ] Figures generated from stored metrics; captions include evidence status
[ ] Literature comparison and limitations are methodologically fair
[ ] Reproducibility bundle has environment, commands, seeds, hashes, raw/derived paths and failures
[ ] Final report claim-to-artifact table complete
```

The final operator report must contain:

```text
Run ID(s) and UTC timestamps
Evidence label per run and exact pass/fail gate outputs
Commands executed and environments/seed
Input/output/figure/report paths
Episode/request/PCAP/Zeek/pre-milestone-window counts
Baselines/ablations actually run and metrics with denominators
Tests/audits performed
Known limitations and failures retained
One exact next command if anything remains
```

If a long job must be stopped, close the named capture, let the collector record status, preserve logs/checkpoints, and provide a tested resume command. Never call an unobserved job successful.

---

## 17. Execution record — 15 November 2026 (append-only)

This queue was executed on the CPU-only machine. The active run is
**`cpu_v3_main_v2_20261115T164430Z`**, evidence tag **`SENSOR_VALIDATED`**.

| Stage | Outcome | Artefact |
|---|---|---|
| A machine/repo inventory | done | `outputs/logs/setup/20261115T162353Z/machine_inventory.log` |
| B CPU virtualenv + environment record | done | `.venv/` (torch 2.7.1+cpu, cuda False); `outputs/environment/environment_20261115T162353Z.txt` |
| C source audit, `bash -n`, `compileall`, focused pytest | done | 45 tests pass; `outputs/logs/setup/20261115T162353Z/stage_c_syntax_tests.log` |
| C strict sensor gate + checksum repair (new) | done | `setup/staged_sensor_gate.py`, `setup/pcap_checksum_repair.py`, 13 new tests |
| D Compose preflight, both networks internal | done | `outputs/logs/setup/20261115T162353Z/stage_d_compose_preflight.log` |
| E fresh V3 pilot + strict validation | done | `cpu_v3_pilot_v2_20261115T164336Z` |
| F main dataset (24 + 24 rounds) | done | `cpu_v3_main_v2_20261115T164430Z` (192 episodes, 3,840 events, 107,628 packets) |
| F run inventory | done | `outputs/reports/<run>/run_inventory.json` |
| G leakage-safe preprocessing, splits, leakage audit | done | `outputs/studies/<run>_zeek_*/dataset/` (9/9 leakage checks pass) |
| H rule / Isolation Forest / Random Forest baselines | done | `outputs/studies/<run>_zeek_*/metrics.csv` |
| H2 compact CPU GRU (optional) | done | `outputs/studies/<run>_gru_zeek/`, `outputs/reports/<run>/gru_metrics.csv` |
| I policy comparison + feasible ablations | done | `outputs/studies/<run>_zeek_*/ablations.csv` |
| J figures from saved metrics | done | `outputs/reports/<run>/figures/{zeek,gateway}/` (8 figures + source data each) |
| K report, claim-to-artifact table, limitations, reproducibility | done | `outputs/reports/<run>/PHASE3_REPORT.md`, `claim_artifact_table.csv` |
| Reproducibility verification | done | `python -m setup.verify_report_numbers` → 102 checks, 0 mismatches (both seeds) |
| Final verification (post-packaging) | done | 50 tests pass; log `outputs/logs/final_verification/20261115T174058Z/verification.log` |
| Submission packaging | done | `setup/package_phase3_submission.py`, `setup/build_submission_deliverables.py`, `deliverables/phase3_submission/` |
| Independent replication (second seed) | done | `cpu_v3_main_v2_seed2_20261115T165949Z`, also `SENSOR_VALIDATED`; `outputs/reports/<run>/seed_comparison.csv` |

**Deviations from this runbook** (all documented in the report, §1.2): the lab
services and the capture sidecar had to be made able to write into the
bind-mounted host data directory (services now run as the invoking host user;
the capture file is pre-created 0666) — container capabilities were **not**
widened; the scenario schema was versioned to `staged_v2_2` so the frozen test
set is stratified between the held-out and the development behaviour families;
the main run was scaled to 24 + 24 rounds so the false-alarm budget is
estimable on a non-trivial validation set.

**Not done, and listed as unavailable:** graph relations, topology
generalisation, and future-stage prediction. A second independent seed **was**
collected and evaluated; it shows that the capture and sensor pipeline
replicates exactly but that the **coverage ranking of the collection policies
does not** move-with-seed, so no policy ranking is claimed.
