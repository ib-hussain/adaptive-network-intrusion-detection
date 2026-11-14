# INSTRUCTIONS.md — Active mission and execution runbook for OpenCode

> **Starting context:** 14 November 2026, after receiving the university log where Stage V3 capture failed because `tcpdump` attempted a forbidden UID/GID switch. The immediately preceding hotfix exists as a separate archive/script but **its deployment success has not yet been reported**. Your job is to **advance actual Phase 3 development autonomously, safely and measurably**. Do not merely describe what could be done: inspect, implement, run available tests, and save recoverable artefacts in the environment you can actually control. Follow [`AGENTS.md`](AGENTS.md), [`SKILLS.md`](SKILLS.md), and [`MEMORY.md`](MEMORY.md).

## Mission summary — read first

**Goal:** A reproducible **Computer Networks** semester research experiment comparing **fixed vs random vs strategic** controlled network-scenario generation for **detection** and **pre-milestone early warning** under matched budgets and a frozen independent test, with Zeek/PCAP network evidence, honest uncertainties and meaningful ablations.

**Non-negotiable:** no real malware, autonomous exploitation, self-propagation, external attacks, Kubernetes, large production dashboard or fake zero-day claims. Early-warning `T_lead` is valid only after independent onset and before independent milestone, with false alarms and recall controlled. All scripts must have **visible live progress + persistent timestamped logs + heartbeats and recoverability**.

**Current hard blocker:** V3 Docker capture sidecar instantly exits with:

```text
tcpdump: Couldn't change to 'tcpdump' uid=100 gid=101: Operation not permitted
```

A surgical hotfix adds `-Z root` to the **existing V3 sidecar `tcpdump` invocation** without changing its restricted Docker capabilities. **Do not assume it is deployed.** The last V3 pilot had **zero completed episodes**, and its PCAPs were **24-byte headers**. Do not train on them. Check live worktree and resolve capture, then proceed in stages.

---

## Phase A — first terminal session: read-only discovery (required)

Open Bash on the actual university machine. Change to the actual repository root if different:

```bash
cd /home/fastlab/deepFakeDetection/adaptive-network-intrusion-detection
pwd; git rev-parse --show-toplevel 2>/dev/null || true; git status --short --branch
source .venv-cuda/bin/activate
export PATH="/opt/zeek/bin:$PATH" PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONUNBUFFERED=1
python --version; python -c 'import torch; print("cuda",torch.cuda.is_available()); print(torch.cuda.get_device_name(0) if torch.cuda.is_available() else "CPU")'
nvidia-smi; df -h . /var/lib/docker 2>/dev/null || true
docker ps; docker compose -f compose.yaml config --quiet; zeek --version
jobs -l; ps -eo pid,ppid,stat,etime,args | grep -E '[s]taged_collect|[t]cpdump' || true
```

Do not start new jobs if an old process or capture is still active; identify process owner and exact output path first. Do not kill arbitrary PIDs. The past raw university captures, Optuna DBs and checkpoints must be preserved.

Next inspect the current code and progress state:

```bash
ls -l setup/staged_collect_v3.sh setup/staged_capture_audit.py setup/staged_v3_status.sh setup/staged_train_guard_v3.sh
grep -nE '"\$IMAGE"|cap-drop|NET_RAW|HEARTBEAT|CAPTURE_PREFLIGHT_FAILED' setup/staged_collect_v3.sh
./setup/staged_v3_status.sh staged_v3_check_02 || true
find src/data/raw/runs/staged_v3_check_02 src/data/raw/runs/staged_v2_main_01 -maxdepth 2 -type f -printf '%p %s\n' 2>/dev/null | sort | head -100
find outputs/model outputs/hpo outputs/sprints -maxdepth 4 -type f \( -name '*.sqlite3' -o -name 'complete.json' -o -name '*exitcode' \) -print | head -100
```

**Write a timestamped work log** stating verified machine capabilities, active processes, launcher version and missing input files. Treat the laptop `complete_repo_upto_now.zip` as an older **149-entry snapshot**, not the university source of truth.

### Required first report (short but concrete)

```text
UTC timestamp | repo commit/dirty state | host/GPU/disk
V3 -Z root present? yes/no | any live capture? yes/no | Docker/Zeek accessible?
RUN staged_v3_check_02: completed episodes=?, PCAP packets=?, last error=?
RUN staged_v2_main_01: completed episodes=?, valid PCAP=?, last status=?
Next bounded action and recovery path
```

---

## Phase B — resolve V3 tcpdump capture (priority P0)

### B1. Source patch checks

In the active `setup/staged_collect_v3.sh`, the relevant capture command should contain the image invocation:

```bash
"$IMAGE" -Z root -i any -p -nn -s 0 -U -w "/captures/$CAP_FILE" 'tcp port 8080'
```

The pre-hotfix version omitted `-Z root`. If it is already present, **do not re-patch**. If absent, first inspect exact surrounding lines and ensure this is the expected **V3** script (with `--cap-drop ALL --cap-add NET_RAW`, `--network "container:$GATEWAY_CID"`, `--security-opt no-new-privileges:true`, the capture preflight, and heartbeat). If the archived hotfix is available on this machine, its historical command was:

```bash
bash Phase3_TCPDump_Privilege_Hotfix/fix_tcpdump_privileges.sh "$PWD"
```

**Use that command only if that file actually exists and matches this launcher**. Otherwise make the **smallest exactly equivalent edit after a dated source backup**, preserve all security controls and test it. Do not broaden privilege or enable external networking. Running `tcpdump` as root inside this capability-limited capture container still needs institutional authorisation. The purpose is to avoid tcpdump's automatic `uid=100/gid=101` switch; this is **not proof that it will capture traffic on the actual host**.

### B2. Verify local syntax, tests and capture readiness

```bash
bash -n setup/staged_collect_v3.sh
python -m pytest -q tests/test_staged_capture_audit.py tests/test_v3_launcher_contract.py
./setup/preflight.sh
docker ps --filter label=phase3.staged.capture=1
```

Before launching any capture: check all bridge/namespace routes and no overlapping host `tcpdump` or named sidecar. Ignore the old Compose `orphan` warning unless `docker ps -a` shows a real conflict; **never blindly `--remove-orphans`**. The V3 wrapper uses a host-mounted run directory for PCAPs and named Docker capture with an HTTP probe. Ensure file permissions let the capture image write to that directory and logs are saved.

### B3. Resume existing *empty* V3 pilot with its original config

Only after checking that `staged_v3_check_02` has `scenario_config.json` and **no committed round bundle**:

```bash
./setup/staged_collect_v3.sh --run-id staged_v3_check_02 --rounds 3 --test-rounds 3 --seed 20261114 --capture --resume
```

In a **second terminal** (same repo, no second collector):

```bash
./setup/staged_v3_status.sh staged_v3_check_02 --follow
```

**Pass criteria for the capture probe:** the 4 labelled HTTP probes succeed, the sidecar stays running, the PCAP contains actual packet records (not 24 bytes), and the wrapper explicitly prints `Capture preflight passed: actual packet records observed`. After generation, all 24 episode bundles are committed, gateway subset extracted, capture process stopped, closed PCAP validated and collector status is `COLLECTION_COMPLETE`. The generator is expected to record **24 episodes x 20 = 480** experimental HTTP requests; four preflight probe requests are **not** experiment examples.

If probe fails: **stop** the research collection, retain failed PCAP/logs, inspect `capture_container_*.log`, `collector_v3_*.log`, interface, Docker namespace/capabilities and bind-mount permissions. Do not bypass the gate with `--no-capture` and then report Zeek network findings. Add a targeted regression test for each cause.

### B4. Scientific sensor checks after capture

A packet-count gate is **necessary but not sufficient**. Run the available capture audit and Zeek processing (inspect `--help` first) and verify:

- all recorded packets belong to the authorised lab, with client-to-gateway and gateway-to-service directions visible;
- PCAP file is closed; packet lengths/header are valid; no unsupported linktype/truncated frames;
- each complete `episode_id` has the expected independent controller metadata, 20 gateway records and time-consistent Zeek connections; the preflight probe is excluded;
- `conn.log` contains meaningful origin and response bytes, correct timestamps, no silent duplication or unaligned episodes;
- checksum offload warnings are investigated; `zeek -C` only if justified and documented;
- sensor and label signals are not the same derived observation.

Store a **run-specific audit JSON** with `capture_valid`, `packet_count`, `episode_coverage`, `unmatched_packets/connections`, byte-direction coverage, `zeek_returncode`, and detailed faults. Keep original PCAP/checksums. Do not make claims from partially validated sensors.

---

## Phase C — complete the staged main experiment (priority P1)

`staged_v2_main_01` was initialised with **12 rounds per policy + 12 test rounds**, seed **20261115**, 96 total episodes, 1,920 requests planned. It failed capture preflight with **zero documented committed rounds**. Inspect the actual round directory first; do not assume it is empty just because the older transcript was.

After **Phase B capture + Zeek alignment passes**, and after resource constraints are satisfactory:

```bash
./setup/staged_collect_v3.sh --run-id staged_v2_main_01 --rounds 12 --test-rounds 12 --seed 20261115 --capture --resume
```

Follow progress in another terminal:

```bash
./setup/staged_v3_status.sh staged_v2_main_01 --follow
```

**Preservation:** each atomic round bundle represents a completed benign + controlled incident episode; `--resume` must use the original exact seed/config and replay prior strategic state. If power is interrupted, do not purge `rounds/`, `scenario_config.json`, `gateway_requests.jsonl`, capture segments or metadata. An incomplete round must not be counted. If a PCAP segment captures only part of a run, mark it explicitly; do not attribute old episode observations to a later empty capture. If the run has a `complete.json` but invalid capture, use a **new run ID** for a genuine captured repeat; its historical packets cannot be recreated.

**Large-run gate:** only claim completion after 96 complete episodes, 1,920 observed gateway requests, correct split counts, packet-bearing PCAP(s), Zeek per-episode alignment, all capture workers stopped, numerical/schema validation and persistent status marked success. Keep real progress/heartbeat visible to the owner throughout.

---

## Phase D — start independent compute tasks in parallel (priority P2)

Once the main dataset is validated, run the already provided **gated** four-worker launcher:

```bash
./setup/staged_train_guard_v3.sh staged_v2_main_01 --hpo-trials 30 --gru-epochs 80
```

Check:

```bash
./setup/staged_status.sh
tmux ls || true
nvidia-smi
```

This launcher is expected to create separate `tmux` sessions and run-specific logs for:

1. **CPU baseline:** Random Forest and Isolation Forest on causal features, with per-policy independent validation and frozen common test.
2. **CPU Optuna HPO:** 30 validation trials per policy, persistent SQLite; use TPE and fit-only preprocessing.
3. **GPU GRU:** epoch checkpointed temporal model, with `--device auto` selecting CUDA. The GRU is **not a GNN**.
4. **Independent Zeek audit/evaluation:** only with valid captured sensor coverage, and never silently equate HTTP requests with Zeek TCP connections.

Prevent simultaneous writes to the same SQLite DB/checkpoint directory. Restrict CPU thread counts; one large GPU job at a time. **Do not run training concurrently with packet collection** because load affects the measured gaps/timing. If the `tmux` sessions finish, verify saved `*.exitcode`, `complete.json`, DB rows, model exports, valid metrics and logs; don't assume absence from `tmux ls` means success. If an item fails, preserve its logs, identify root cause and restart only that worker.

The earlier 90 HPO trials and 60-epoch GRU runs belong to an easier **32-episode pilot**. They are evidence of pipeline execution, **not** the Stage V3 result and **not** real cyberattack generalisation evidence. Do not keep tuning the old tiny dataset to chase 1.0 PR-AUC.

---

## Phase E — upgrade scientific validity (priority P3; develop while collection is blocked)

The basic V2 system is a foundation, **not the full Phase 2 methodology**. The following developments are essential before describing it as a network intrusion detection and early-warning study:

### E1. Strengthen the *network* experiment

- Add independent, bounded benign workload classes (periodic healthchecks, approved bulk transfer, service discovery, rate/burst variations) so the model cannot classify every busy episode as an incident.
- Add meaningful multi-host communication and **at least a second independently configured topology** if claiming topology transfer; do not treat the two existing Docker segments as two independent experimental topologies.
- Vary traffic conditions, background load and previously unseen behaviour across independent seeds. Record exact scenario start/onset/escalation/dummy-transfer times. Do not run actual malware or arbitrary exploit scripts.
- Instrument authorised network protocol evidence (Zeek `conn.log`, optionally HTTP/DNS logs) independently of generation. Record sensor/capture failure as a distinct outcome.
- Ensure no trivial label leakage through payload length, known endpoint, identical request index or absolute timestamps. The current dummy milestone is a large **2048-byte** final request by design; **test whether earlier alerts rely on pre-milestone behaviour rather than simply recognising this transfer.**

### E2. Repair the actual strategic research question

The current Stage V2 `game_reward()` uses the scripted `rate` and `spread` heuristics on observed request timing/destinations, **not the trained detector's alert/lead-time performance**. To test adaptive attacker–defender feedback, define a legal, finite observation/action schedule in which the policy chooses *only* harmless scenarios, receives measured feedback from **prior completed training/validation episodes**, and never sees final test episodes. Persist action probabilities/rewards and enforce matched budgets. Keep a transparent **heuristic EXP3** as its own baseline if this extension is too costly. Do not call a heuristic selector a demonstrated Nash equilibrium or active-defence hardening.

### E3. Build genuinely graph-temporal detection

- Construct directed host/service graph snapshots from **verified Zeek flows** (not mock metadata), with stable node mapping, causal edge windows, byte/packet and timing edge features.
- Train a compact GraphSAGE or edge-aware GAT model, optionally with GRU temporal memory, if the observed graph variation supports it; use CUDA with CPU fallback.
- Provide equivalently tuned graph-free MLP, feature RF and temporal GRU baselines. Test graph-edge removal, temporal-feature removal, identity masking and unseen topology/family conditions.
- Preserve entire epoch checkpoints with optimizer/scheduler state, feature schema, random states, config and split hash. Implement and actually test restart from epoch N+1.

### E4. Make research comparisons fair and statistical

- Pre-register enough **independent** episodes and seeds; report positive/benign counts, held-out family/topology units and failure to obtain positives where applicable.
- Compare fixed vs uniform random vs strategic under the **same** data/compute budget and **same** independently frozen test set.
- Metrics: detection macro-F1, incident recall/precision, PR-AUC, AUROC only if well-defined, false alarms/benign hour, inference latency, warning coverage, conditional lead time and coverage-adjusted `T_lead`, misses/late alarms.
- Threshold and persistence chosen on validation only; hold false alarms fixed/constrained. Episode-level paired bootstrap 95% CIs and repeated independent seeds; prevent correlated overlapping-window pseudoreplication.
- Ablations: strategy selector, time features, graph features/model, topology change, withheld behaviour, sensor source and alert threshold/persistence. Report negative and inconclusive results.

### E5. Build honest paper baselines

Reproduce authors' methods **only** when corresponding code/data/versions are available and the dataset permits equivalent evaluation. Preferred Phase 1 code leads: GraphINR-IDS, TF-GATv2 and IIoT stage-detection repositories described in `MEMORY.md`. Inspect actual linked code and data licences; if source code is missing, implement documented methods as faithfully as practical, record missing details and use Optuna for undisclosed hyperparameters. Do **not** claim to have reproduced published headline results from different benchmark data, split or label regime.

---

## Phase F — final course deliverables and evidence package (priority P4)

The official Phase 3 rubric requires: (1) methodology implementation with documented Phase 2 changes, (2) dataset/preprocessing/split details, (3) baseline metrics, (4) graphical results, (5) qualified literature comparisons, (6) ablations, (7) critical results analysis. Prepare all seven from real output files, not from aspirational architecture descriptions.

The final research artefact inventory should include:

```text
researchPapers/             New Phase 1 & 2 PDFs plus verified source-paper inventory
configs/                   Exact run YAML/JSON including seeds, software and hardware metadata
lab/                       Docker Compose + bounded traffic workload sources
src/code/                  Sensor ingest, causal features, game, models, evaluation
src/data/raw/runs/<id>/     Controller configs/rounds, logs and PCAP (local, not Git)
src/data/processed/         Episode-safe tensors/graphs/split IDs (local)
outputs/logs/               UTC worker logs and capture/Zeek diagnostics
outputs/hpo/                Persistent study DBs + trial summaries (local)
outputs/model/              Epoch checkpoints and inference exports (local)
outputs/results/            Predictions, metrics JSON/CSV, split manifests, bootstrap analyses
outputs/figs/               Detection/early-warning curves, timeliness and ablation plots
docs/                       Architecture, methods, failed experiments, validity, comparison tables
MEMORY.md / SKILLS.md / AGENTS.md / INSTRUCTIONS.md
```

Be precise about which files may be published: PCAPs can contain identifiers/content and must be reviewed/anonymised/licensed prior to sharing; don't automatically commit/push large PCAPs or raw university data. The owner prohibits Git LFS.

---

## Priority table — actions and gating conditions

| Priority | Action | Must pass before next | Persistent evidence |
|---|---|---|---|
| **P0** | Verify/apply tcpdump `-Z root` hotfix on V3 and inspect container privileges | Capture probe records real packets with no error | UTC logs, source diff, container logs, PCAP audit |
| **P1a** | Resume `staged_v3_check_02` | 24 episodes/480 gateway events plus verified *closed* PCAP + Zeek alignment | `episodes.jsonl`, `complete.json`, `gateway_subset`, PCAP, audit |
| **P1b** | Resume `staged_v2_main_01` | 96 episodes/1,920 requests and valid network observations | Full run config, rounds, source hashes, audit |
| **P2** | Parallel RF/IF, HPO, GRU, Zeek audit | Completed worker exit codes, checkpoints and honest metrics | SQLite, `.pt`, logs, results/figures |
| **P3** | Realistic network conditions, detector-based game, graph model, holdouts | Causality/split/measurement tests | New versioned code + ablations |
| **P4** | Final Phase 3 report/demo | All required rubric items from real results | Final reproducible report and release checklist |

**Parallelism policy:** After P1, run P2's independent CPU/GPU/Zeek workers concurrently. During P0 or P1, only **non-competing work** (unit tests, code review, paper-source verification, offline software design, documentation) may proceed concurrently. Never run multiple captures against the same gateway or saturate CPU/GPU while measuring traffic timing.

---

## Recovery procedures by exact failure

### A. `tcpdump` privilege switch fails after `docker run`

Verify whether `-Z root` exists. If absent and the exact V3 restricted capture invocation matches, use the backed-up surgical patch. Verify Bash and container start; **do not** relax all capabilities. If it still fails, read `docker logs <exact named container>` and examine kernel/seccomp/user namespace support and bind-mount ownership. Do not bypass the packet probe or claim a fixed issue before a real packet-bearing PCAP exists.

### B. `Another staged collector holds ...lock`

Inspect `jobs -l`, process tree, capture workers. If a `Ctrl+Z` job is suspended, terminate **only that verified shell job** using Bash job control `kill %N` in its owning shell or verified PID after preserving output. Do not delete the lock file while its descriptor may be held. No capture overlap.

### C. Staged V2 completed but only `24`-byte PCAP

Use `./setup/staged_recover_v2.sh RUN_ID` to extract independent **application-only** gateway records. Preserve invalid PCAP and log. Do not relabel that run as real network evidence; use a new run ID for fresh packet capture because historical packets cannot be recreated.

### D. Compose `STAGED_CAPTURE_NAME` missing

This is a configuration interpolation error in the older V2 overlay. Do not use the overlay for V3; inspect effective `docker compose config` and variable precedence. Don't paper over required values with arbitrary dummy names in scientific jobs.

### E. Zeek checksum/filtered trace warnings

Inspect `tcpdump` capture filter (previous host capture was `tcp port 8080`), frame sizes, payload and directions. `zeek -C` can be used for validated offloading effects; it does **not** restore packets that were never captured. Save `weird.log`, `reporter.log`, `conn.log`, HTTP logs if generated and explicit coverage audit.

### F. Physical university shutdown

1. Stop starting new rounds/trials close to closing time. Observe final heartbeat, complete current round/epoch if possible.
2. Confirm each capture container is shut down and PCAP closed. Close terminal jobs normally, not by `Ctrl+Z`.
3. Verify round journals, `complete.json`, checkpoint latest pointer, SQLite integrity and job status; copy selected raw data/logs/models to an **actually separate** persistent destination using approved backup script: `./setup/university_backup.sh /path/to/external-backup` (inspect script and destination first).
4. On return: inspect fresh disk/GPU/process status, verify source/config hashes, resume only same run and epoch/study; don't promise an interrupted Python process resumes automatically.

### G. Literature/source replication blocker

Search publisher DOI, code/data availability, author repository and legal preprints. Record exact URL, version, licence, success/failure and missing experimental details; prefer genuinely public code+dataset focal baselines. No fabricated access, downloadable PDF or author settings. Distinguish external published results from this project's measured results.

---

## Required task report format — no silent waiting

At each meaningful checkpoint and in the final response, give:

```text
STATUS: VERIFIED / IN PROGRESS / BLOCKED / FAILED / PROPOSED
UTC: timestamp; working tree: commit/branch + dirty files
STEP: exact command / changed filenames / run ID
PROGRESS: completed rounds/epochs/trials, elapsed, heartbeat location
RESULT: real count/metric + unit, output paths, checksums when relevant
CHECKS: syntax, focused tests, real sensor smoke, schema, leakage, resume
SECURITY: isolation/permissions, any changes to Docker capabilities
ISSUE: exact error and first broken invariant, if any
NEXT: literal command(s), prerequisites and rollback/resume route
```

**Never claim a future external university job has been started by this chat unless it was actually launched on that host.** If working only from a repository ZIP, prepare a complete, testable patch and exact execution commands, clearly marking university validation pending.

## Session completion checklist

- [ ] Correct repo and live state inspected; latest university files preserved.
- [ ] Unit, syntax, data and process checks passed with logs.
- [ ] Capture preflight and closed packet evidence verified if claiming network research.
- [ ] Zeek and independent scenario timeline aligned with explicit exclusions.
- [ ] Detector/game causality and final-test blinding demonstrated.
- [ ] Exactly comparable fixed/random/strategic budgets and split manifests preserved.
- [ ] Genuine early warning measured at known false-alarm budget, including misses.
- [ ] GPU model properly checkpointed and resumed in an actual smoke test where used.
- [ ] Long-running tasks provide UTC heartbeat and machine-readable status.
- [ ] Main results/ablations/uncertainty figures are reproducible and honestly qualified.
- [ ] `MEMORY.md` append-only evidence log updated with exact blocker/status.
- [ ] `git diff --check` and artefact/secret/Git-LFS safety verified.
- [ ] Owner given exact commands, results, limitations and safe next steps.

## References to read for implementation details

`MEMORY.md` contains date-stamped history; `SKILLS.md` contains operational playbooks; `AGENTS.md` contains binding non-negotiables. Read Phase 1/Phase 2 research PDFs for the precise approved gap and 12-step methodology. Official external docs: [Docker Compose interpolation](https://docs.docker.com/compose/how-tos/environment-variables/variable-interpolation/), [tcpdump `-Z`](https://man7.org/linux/man-pages/man1/tcpdump.1.html), [Zeek quickstart/JSON](https://docs.zeek.org/en/current/quickstart.html), [PyTorch checkpointing](https://docs.pytorch.org/tutorials/beginner/saving_loading_models.html), and [Optuna RDB resumption](https://optuna.readthedocs.io/en/stable/tutorial/20_recipes/001_rdb.html).
