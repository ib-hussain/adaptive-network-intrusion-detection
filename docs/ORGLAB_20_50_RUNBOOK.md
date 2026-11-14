# ORGLAB 20–50 employee network experiment — additive Phase 3 prototype

**Status: locally code-tested, NOT run on the university Docker daemon.** This patch adds a separate network lab; it does not replace `staged_collect_v3.sh`, the existing run journal, Zeek logs, HPO studies, or any checkpoint. The archived repository ZIP supplied with the request could not be mounted for content inspection in the execution container; integration against the live university checkout is **not verified**. Install only if the new paths below are absent, and inspect `git status` before/after.

## A. What has actually changed

- `orglab/composegen.py`: generates **20–50 actual employee containers** plus **3 service containers** (`docs`, `crm`, `mail`), a gateway, optional restricted capture sidecar and a short-lived controller. One reused Python base image is used for all employees. No host-published ports. Both flat two-segment and departmental five-segment variants use `internal: true` networks; no public egress is intended.
- `orglab/runtime.py`: a deterministic, bounded controller and an HTTP service/employee/gateway runtime. Four simulated departments have different ordinary service preferences. Training policies are **fixed, uniformly random and heuristic EXP3**; `slow_ramp` is held out as the common test family. An experiment episode has 24 real HTTP tasks, with independent onset at step 5, escalation at 14 and inert dummy-transfer milestone at 23. Every episode has the same *planned* total delay, payload-byte budget and request count. Actual network timing and per-episode sensor fidelity must still be audited.
- `orglab/audit.py` and `orglab/zeek_eval.py`: fail closed on header-only or corrupt PCAPs, incomplete episode/gateway counts, missing employee source IPs, and missing Zeek bidirectional connection coverage. Preflight's four probe requests are marked separately and excluded from episodes. No `-C` checksum bypass by default.
- `orglab/dataset.py`, `orglab/train.py`: per-episode causal application-gateway features, episode-disjoint fixed/random/strategic training and validation, **same frozen `test` episodes**, Random Forest + Isolation Forest, validation-only warning thresholds, sustained alerts, false alarms per benign hour, conditional and coverage-adjusted pre-milestone lead time.
- `orglab/graph_train.py`: two **actual directed mean-aggregation GraphSAGE layers** plus a causal GRU; trains with PyTorch on CUDA when available. An atomic full checkpoint is written every epoch; best validation checkpoint and inference weights are separate; optimizer/RNG and input hashes are verified on resume. This graph is derived from gateway-observed employee/gateway/service relations, **not directly from Zeek's `conn.log`**. Genuine Zeek-native topology modelling is still a separate task.
- `setup/orglab_run.sh`: guarded run, timestamped console log, visible collection progress and sidecar cleanup (only for its own Compose project). `setup/orglab_train_parallel.sh`: **6 CPU training jobs** (3 policies × RF/IsolationForest) plus **one sequential GPU worker** (three graph policies), all after packet collection closes, each with its own logs/exit codes/checkpoints. `setup/orglab_v3_diagnose.sh`: read-only diagnosis for the original Stage V3 main-run timeout.
- `tests/test_orglab.py`: Compose/security bounds, balanced budgets, PCAP failures, causal splits/labels, baseline training and a real CPU GraphSAGE–GRU interrupted-epoch resume regression test. All test fixtures are artificial and **never** submitted as research measurements.

## B. What to do first on the real university machine

Do not let the old laptop snapshot overwrite the university checkout. If another collector or GPU training job is running, inspect its PID, Docker container and run ID, and avoid competing timing-sensitive collection.

```bash
cd /home/fastlab/deepFakeDetection/adaptive-network-intrusion-detection
source .venv-cuda/bin/activate
export PATH="/opt/zeek/bin:$PATH" PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONUNBUFFERED=1
pwd; git status --short --branch; docker ps; nvidia-smi; df -h . /var/lib/docker
./setup/staged_v3_status.sh staged_v3_check_02
./setup/staged_v3_status.sh staged_v2_main_01
./setup/orglab_v3_diagnose.sh staged_v2_main_01
```

**Existing run `staged_v3_check_02` is already useful**: the latest supplied log reports 24 episodes, 480 gateway requests, 13,550 packets, 960 assigned Zeek connections, and completed baseline/HPO/GRU jobs. The later main-run attempt `staged_v2_main_01` exited 124 after four successful HTTP probes, but **did not establish a complete 96-episode capture**. Check current logs and `complete.json` before retrying, and investigate the exact timeout location; do not replace it with an `--no-capture` run and label it sensor-validated.

If the main run now has a verified complete PCAP, Zeek alignment and `complete.json`, the existing guarded launcher is:

```bash
./setup/staged_train_guard_v3.sh staged_v2_main_01 --hpo-trials 30 --gru-epochs 80
./setup/staged_status.sh
```

That is the original staged V3 pipeline (CPU baseline, CPU Optuna, CUDA GRU, Zeek evaluation), **not the new ORGLAB lab**. If capture remains incomplete, resume only after identifying the main-run timeout and verifying there is no active collector:

```bash
./setup/staged_collect_v3.sh --run-id staged_v2_main_01 --rounds 12 --test-rounds 12 --seed 20261115 --capture --resume
```

## C. Install the additive patch without overwriting newer university files

Transfer `Adaptive_NIDS_OrgLab_Addon.zip` to the university machine. Before extraction, check there are no conflicting `orglab/` or `setup/orglab_*` files. The archive contains no `.git`, user PCAP, model checkpoint, `.env`, or older `src/code/` file.

```bash
cd /home/fastlab/deepFakeDetection/adaptive-network-intrusion-detection
unzip -l ~/Downloads/Adaptive_NIDS_OrgLab_Addon.zip | head -80
unzip -n ~/Downloads/Adaptive_NIDS_OrgLab_Addon.zip -d .
chmod +x setup/orglab_*.sh
python -m compileall -q orglab
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest -q tests/test_orglab.py
bash -n setup/orglab_run.sh setup/orglab_train_parallel.sh setup/orglab_v3_diagnose.sh
python -m orglab.composegen --nodes 20 --topology departmental --output compose.orglab.20.departmental.json
```

The capture image (`debian:bookworm-slim` + tcpdump) must be built once. A permitted Docker image pull/package installation is necessary if those layers are not already cached. **Do not alter university Docker daemon, firewall, user privileges or kernel settings** to make it work. The runtime uses the current unprivileged user for all workers, gateway and controller; the capture sidecar uses `-Z root` within a minimal-capability container (NET_RAW only), without host networking or `--privileged`. Verify local lab policy before starting it.

## D. Run 20 employees, **then immediately launch independent CPU/GPU training**

This command creates a *new* isolated run ID with **48 episodes** (6 fixed rounds ×2, 6 random ×2, 6 strategic ×2, 6 test ×2), 1,152 non-probe HTTP tasks, plus exactly four preflight probes. It automatically closes the capture, performs PCAP and Zeek alignment audits, and only then runs 6 parallel CPU learners and three sequential CUDA GraphSAGE+GRU learners.

```bash
./setup/orglab_run.sh --run-id org20_pilot_01 --nodes 20 --topology departmental --rounds 6 --test-rounds 6 --seed 20261114 --step-seconds 0.6 --train
```

If the pilot passes, increase to **96 episodes and 2,304 actual HTTP tasks**, with a fresh run ID:

```bash
./setup/orglab_run.sh --run-id org20_main_01 --nodes 20 --topology departmental --rounds 12 --test-rounds 12 --seed 20261115 --step-seconds 0.8 --train
```

For a **separate flat-network topology holdout** with the same matched scenario budget (do not silently pool these runs):

```bash
./setup/orglab_run.sh --run-id org20_flat_01 --nodes 20 --topology flat --rounds 12 --test-rounds 12 --seed 20261115 --step-seconds 0.8 --train
```

Only after verifying resource usage and actual employee IP/Zeek coverage, increase to 50 employee containers:

```bash
./setup/orglab_run.sh --run-id org50_pilot_01 --nodes 50 --topology departmental --rounds 6 --test-rounds 6 --seed 20261116 --step-seconds 0.7 --train
```

**Resource scope:** 20 I/O-oriented employee containers are not equivalent to 20 fully utilised CPU cores. Workers each have a 0.20 CPU and 128 MiB memory *limit*, with three services, gateway and controller also capped. The capture image is shared across runs. Monitor `docker stats`, `nvidia-smi`, `df -h /var/lib/docker`, active collectors, Zeek conversion time and disk writes. No competing training is permitted during capture. Scaling is bounded to 50 and does not imply production realism or topology transfer by itself.

## E. Results, live monitoring and recovery

All data is local and private, under `outputs/orglab/RUN_ID/`. It includes `launcher.log`, `captures/orglab.pcap`, `episodes.jsonl`, `gateway_requests.jsonl`, atomic `rounds/`, `collection_complete.json`, `status.json`, `zeek/conn.log`, `zeek_audit.json` and `training/` with independent logs/results/models/epoch checkpoints. Outputs are not intended for Git or general publication. Keep packet captures and log contents private, and do not add Git LFS.

To check progress from a second shell:

```bash
RUN=org20_main_01
cat "outputs/orglab/$RUN/status.json" 2>/dev/null || true
tail -f "outputs/orglab/$RUN/launcher.log"
find "outputs/orglab/$RUN/training" -maxdepth 3 -type f 2>/dev/null | sort | tail -35
nvidia-smi; docker stats --no-stream
```

An interrupted ORGLAB **collection cannot resume within the same run ID**. Its partial capture, logs and paired round files are preserved; start a fresh run ID for a new independent run. This is stricter than the existing staged V3 resumption code. Graph training has an explicit, input-hash-verified `--resume`:

```bash
python -m orglab.graph_train --run-dir outputs/orglab/org20_main_01 --output outputs/orglab/org20_main_01/training/models/fixed_graphgru --policy fixed --epochs 60 --device auto --resume
```

Do not use `docker system prune`, `rm -rf outputs`, `docker compose down -v`, `git clean -fdx`, or remove active capture locks. `setup/orglab_run.sh` stops only its own Compose project containers, preserving volumes and source. Inspect `*.exitcode`, `training_summary.json`, and final sensor reports before claiming completion. Any `--allow-gateway-only` CPU diagnostic is **not** packet-level research evidence.

## F. Limitations and next scientific requirements

1. The EXP3 selector is still **heuristic**, not a detector-in-the-loop attacker–defender strategy; improving this needs a frozen reference model and prior-completed-episode feedback, with zero access to final test labels.
2. Gateway-observed graphs are genuine communication graphs but **not Zeek-native flow graphs**; compare against an independently validated Zeek edge schema and sensor visibility before claiming graph-temporal intrusion detection.
3. Flat versus departmental Compose topology gives two distinct configurations, but **cross-topology generalisation is not implemented** in the trainer; both conditions must be collected independently, and entire topology variants held out by a new explicit split/evaluation module.
4. The “incident” episodes are harmless unusual work patterns, not exploits or malware. No actual zero-day, attacker compromise, data theft, realistic enterprise protocol distribution or pre-impact intrusion guarantee is established.
5. Three service types and 24 task steps/episode are intentionally small. Increase legitimate workload diversity, independent episode counts, seeds, temporal observation duration, fault analysis, literature baselines, statistical confidence intervals and ablations before final research claims.
6. The historic `staged_v2_main_01` timeout must still be diagnosed on the **live university source**; this patch does not edit that script or assert it fixed the existing collection.

The project should report coverage-adjusted lead time and incident recall subject to a declared false-alarm budget, together with macro-F1, PR-AUC, precision, recall, false alarms/hour, per-episode errors, training cost and paired bootstrap confidence intervals. Negative or inconclusive results are valid.
