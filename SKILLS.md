# SKILLS.md — Reusable terminal engineering playbooks for Adaptive NIDS

> Read [`MEMORY.md`](MEMORY.md) for current/historical facts, [`AGENTS.md`](AGENTS.md) for hard operating constraints, and [`INSTRUCTIONS.md`](INSTRUCTIONS.md) for the executable queue. **These are workflows, not assertions that each capability already exists.** Use the actual repository and `--help` to confirm command availability. All commands below target **Bash on Ubuntu/WSL** unless specified otherwise.

## Skill 0 — Operating model: inspect, execute, validate, persist, report

The owner wants a decisive terminal agent capable of autonomous multi-step work; do not wait for confirmation of routine safe steps. The agent's loop is **inspect → identify an invariant → minimal patch → syntax test → unit test → actual-data smoke → capture/split validation → HPO/training as appropriate → saved result → documentation → small, reviewed Git commit**. When one workstream blocks, start a genuinely independent, safe workstream instead of running the same failing command repeatedly. Do not manufacture datasets, scores or “DONE” statuses.

Every sustained operation MUST print and persist **UTC start time, stage, run ID, current progress, periodic heartbeat, input/output location, exit code, and the next recovery command**. See Skill 15.

## Skill 1 — Resolve and inspect the actual machine/repository

```bash
pwd; git rev-parse --show-toplevel 2>/dev/null || true; git status --short --branch; git status --ignored --short | head -80
find . -maxdepth 3 -type f \( -name 'staged_*.sh' -o -name 'experiment.yaml' -o -name 'AGENTS.md' \) | sort
find src/data/raw/runs outputs -maxdepth 3 -type f \( -name 'complete.json' -o -name 'collector_status_v3.json' -o -name '*.sqlite3' -o -name '*.pt' \) -print | head -120
```

Inspect `.gitignore`, `.gitattributes`, tests, currently active scripts, config and consumers; do not assume the laptop ZIP matches the university host. Read Git changes and all ignored assets before edit. Avoid shell globbing on thousands of artefacts; use `find`, `du -sh` and manifests. Capture a **read-only inventory** under a new `outputs/logs/setup/` path when useful.

## Skill 2 — Probe runtime, resources and tools accurately

```bash
python --version; python -c 'import torch; print("torch",torch.__version__,"cuda",torch.cuda.is_available()); print(torch.cuda.get_device_name(0) if torch.cuda.is_available() else "CPU only")'
nvidia-smi; nproc; free -h; df -h . /var/lib/docker 2>/dev/null || true
docker ps; docker info --format '{{.DockerRootDir}}' 2>/dev/null || true; docker compose version
command -v zeek; zeek --version; command -v tcpdump; tcpdump --version | head -2
```

University historical machine: RTX 4000 Ada 20GB, approximately 28 logical CPU threads and ~31GiB RAM. **Project free disk ~1.3 TB but Docker daemon root was down to ~17GB free.** Avoid large fresh image pulls or Docker cache expansion. Set `export PATH="/opt/zeek/bin:$PATH"` where needed. In the ROS-enabled Ubuntu environment use `export PYTEST_DISABLE_PLUGIN_AUTOLOAD=1` to prevent unrelated pytest `launch_testing` plugin errors (`lark` was once missing); don't contaminate the environment to fix unrelated plugins unless needed.

Docker socket failures require inspecting `id -nG`, `docker context ls`, `stat /var/run/docker.sock`, effective group membership and university authorisation. A new shell/login may be necessary. **Never** use `chmod 666 /var/run/docker.sock`; group membership has root-equivalent implications.

## Skill 3 — Baseline gates and minimal test order

```bash
export PYTEST_DISABLE_PLUGIN_AUTOLOAD=1
bash -n setup/staged_collect_v3.sh
python -m compileall -q src lab setup tools
./setup/preflight.sh
python -m pytest -q
```

Test changes in this order: Bash syntax / Python import → focused unit tests → real local HTTP/Zeek/manifest smoke → interruption/resume smoke → resource/concurrency check → full job. Python compilation is not a data/model correctness test. A successful unit suite does not validate network isolation, packet capture, independent early-warning ground truth or cross-domain generalisation.

When a new script is introduced, add `--help/-h` output, input/permission checks, a fail-closed mode, clear exit codes and a corresponding test. Do not launch lengthy jobs before verifying entrypoint and output path.

## Skill 4 — Inspect real evidence before training

For each raw input, inspect schema, expected columns, timestamp type/time zone, IDs, count, duplicates, NaN/Inf, benign/incident balance, duration and trace origin. Verify manifest ↔ gateway ↔ Zeek joins by episode and observed time. For a sample of real records inspect both text and packet values; don't infer that matching counts mean matching traffic. Separate **raw capture**, **controller ground truth**, **application gateway observation** and **derived Zeek connection observations**. Never use gateway POST records as if they were Zeek flows.

Commands to verify a run (replace `RUN_ID`):

```bash
RUN=staged_v3_check_02; RAW="src/data/raw/runs/$RUN"
find "$RAW" -maxdepth 2 -type f -printf '%p %s bytes\n' | sort
[ ! -f "$RAW/episodes.jsonl" ] || wc -l "$RAW/episodes.jsonl"
[ ! -f "$RAW/gateway_subset.jsonl" ] || wc -l "$RAW/gateway_subset.jsonl"
[ ! -f "$RAW/complete.json" ] || cat "$RAW/complete.json"
```

Use hashes (SHA-256) for raw PCAP, manifest and split files. Never overwrite raw input or conceal filtered rows.

## Skill 5 — Docker capture lifecycle and the current Stage V3 failure

**Historical failure chain:** Stage V2 sidecar was never stopped reliably; it generated a 24-byte PCAP and hung. Stage V3 added named Docker capture with heartbeat, but its restricted container failed with `tcpdump: Couldn't change to 'tcpdump' uid=100 gid=101: Operation not permitted`. A separate hotfix was written to add `-Z root` to the exact `tcpdump` command; no post-hotfix university result has been supplied.

First inspect **live** `setup/staged_collect_v3.sh` and `lab/Dockerfile.capture`. Check presence of this **exact command fragment** before deciding to patch:

```bash
grep -n '"\$IMAGE".*-i any' setup/staged_collect_v3.sh
```

If the privilege-drop error persists, fix the `tcpdump` invocation with **`-Z root`** only after confirming the source invocation and preserved isolation. In this intentionally restricted sidecar, the flag prevents the user/group switch attempt; it does **not** grant extra Linux capabilities. Preserve `--cap-drop ALL --cap-add NET_RAW`, `--security-opt no-new-privileges:true`, namespace sharing with the **private** gateway container, read-only rootfs, capture bind mount, and bounded stop. Avoid broad `--privileged` or `--network host`. Review the implications of running as root **inside** the limited container on the institution's machine. Reference: https://man7.org/linux/man-pages/man1/tcpdump.1.html .

Preflight must exercise **four harmless, labelled HTTP requests before the episodes**, then verify actual packet records. A 24-byte PCAP is a header only. Zero records, immediate capture exit, truncated frames or a still-running capture must fail closed with logs and **no** training. Capture probe requests are **not** experiment examples. Always stop the named container and confirm it is stopped before reading PCAP.

Prefer V3's named-container launcher over old `university_pilot.sh`, `university_pilot_v2.sh`, `staged_collect_v2.sh` for new capture; old scripts remain historical/recovery tools only. Run tests and a small V3 pilot before scaling. Avoid simultaneous independent capture of the same bridge and uncontrolled training load during capture.

## Skill 6 — Solve process hangs without deleting state

Inspect the process tree and exact command (PIDs are ephemeral):

```bash
jobs -l; ps -eo pid,ppid,stat,etime,args | grep -E '[s]taged_collect|[t]cpdump|[d]ocker compose'
docker ps -a --filter 'label=phase3.staged.capture=1'
```

A `T`/stopped job after `Ctrl+Z` continues to hold its open `flock` file descriptor; deleting `outputs/locks/staged_capture.lock` does **not** release that lock and risks concurrent writers. In the same shell, use the actual job control entry; `kill %1` is a **shell builtin job target**, not an argument for `sudo kill %1`. If a signal to a stopped process is ineffective, verify the PID and permissions and terminate only that process after preserving evidence. Never use `pkill tcpdump`, kill memorised historical PIDs, `docker system prune`, or `docker compose down -v`. Use `Ctrl+C` and the script's cleanup handler rather than `Ctrl+Z` for later experiments.

An apparent hang must emit an updated heartbeat and an actionable status. Timeouts should distinguish a slow but productive job from a deadlock. For a stalled runner, inspect generator last line, file sizes, Docker logs, PID state, CPU/GPU usage and whether a child has exited before stopping anything.

## Skill 7 — Compose network/service correctness

Run `docker compose -f compose.yaml config --quiet`; inspect resulting networks, published ports, effective labels and mounts. A Compose overlay with `${STAGED_CAPTURE_NAME:?required}` will fail **even before launching** if the variable is unset; define it **before** every Compose parse or avoid the V2 overlay. Stage V3 intentionally starts its capture with direct `docker run` and therefore does not need this overlay. Official docs: https://docs.docker.com/compose/how-tos/environment-variables/variable-interpolation/ .

Inspect that both lab networks remain internal and no external route exists. Do not use untrusted hosts or traffic replay against real networks. A Docker *orphan container warning* is informational until `docker ps -a` proves a conflicting container exists; do not blindly add `--remove-orphans` because it may remove valuable state.

## Skill 8 — Zeek PCAP integrity and sensor alignment

Use `setup/staged_capture_audit.py` to inspect PCAP file header, linktype, record boundaries, packet count and truncate status. These are **structural** tests, not proof of timing/capture completeness. Count flows by episode, ensure both directions have bytes, check TCP/application diagnostics, and verify packet chronology against `start_ts`/`end_ts` windows. Explicitly record included/excluded flow counts, ambiguous joins, capture loss and missing episodes. Use the project's `setup/staged_zeek.py` if present (from the installed V2 patch); inspect CLI before invoking.

Zeek can read PCAP to JSON logs via `zeek -r capture.pcap LogAscii::use_json=T`. Offloaded checksums on local captures can require `-C`, but that bypasses checksum validation; document why it is used and inspect weird/filtered trace reports. Do **not** silence a 'control-packets-only' warning without inspecting capture filters and packet payload. Official: https://docs.zeek.org/en/current/quickstart.html .

**Research gate:** application gateway data and Zeek `conn.log` are different sensors and units (HTTP requests versus TCP connections). Required: per-episode coverage, consistent timestamps and endpoints, bidirectional observations, and no sensor-to-label leakage. A valid 24-byte global header is not a valid network trace. Previous 384 Zeek connections matched 384 gateway observations in one pilot, but **this equality is contingent, not a general invariant**.

## Skill 9 — Staged episode schema, atomic commits and replay

`lab/staged_generate.py` (`staged_v2_1`) uses policies `fixed/random/strategic/test`, scenario profiles `rapid_repeat/destination_shift/jittered_burst`, withheld `slow_ramp`, four benign variations. Each round yields benign and labelled-incident episodes with **20 HTTP requests**. Ground truth includes `episode_id`, `policy`, `condition`, `profile`, `seed`, `start_ts`, `onset_ts`, `escalation_ts`, `milestone_ts`, `end_ts`, `requests`, `topology`, milestone type and a safety note.

An episode's `onset` is at request index 5; escalation at 12; dummy transfer at 19. These are safe controlled milestones, not malicious acts. The atomic source of truth for restart is `rounds/<policy>_<index>.json`. `episodes.jsonl` and `game_rounds.jsonl` can be rematerialised from complete rounds. On `--resume` verify `scenario_config.json` **exactly** matches seed, rounds/test-rounds and schema; completed round replay must reconstruct EXP3 decisions and rewards without advancing randomly. Never treat incomplete shared gateway logs as finished episodes. Include interruption/resume tests with deliberately partial rounds.

## Skill 10 — Game-theory correctness and policy comparisons

`src/code/game.py` implements an EXP3-like bounded weighted-regret action chooser. The **current Stage V2 reward** in `lab/staged_generate.py` is a heuristic of inter-request timing and destination diversity with `rate` and `spread` defences. **This is not a detector-in-the-loop attacker/defender game**. The agent must document this limitation and implement actual detector-feedback policies only if scientifically justified, separately versioned and restricted to permitted lab traffic. All policies must have the same action menu, number of episodes, overall byte/duration budget and held-out test episodes; report any mismatch. Freeze the final evaluation model and reserve test outcomes from game feedback.

For the game, persist per-round action, probability, active defence, reward, seed, episode start/milestone and measured outcome, with enough state to reconstruct exact continuation. A strategy selected from prior completed episodes is acceptable; any use of future test labels is prohibited.

## Skill 11 — Causal feature construction and label hygiene

`src/code/ingest.py` validates observation columns; `src/code/features.py` derives timed windows. Candidate features: flow duration, directional packet/byte totals, rates, TCP state, protocol, inter-arrival statistics, burstiness, rolling change, distinct neighbours, graph in/out degree, new segment edges. Every feature must come from observations available **at or before** its `window_end_ts`. Never feed `episode_id`, scenario/profile/policy name, attack-stage labels, requested `milestone_ts`, deterministic synthetic IP shortcuts, file paths or future window statistics into the classifier. Do not use the generated label as a feature or compute test-derived normalisation.

Chronological feature windows should be entirely within one episode, and episodes must be partitioned first. Validate boundary cases with exact equality at onset/milestone, empty windows, irregular sampling, invalid floats, and lack of positive examples.

## Skill 12 — Early-warning metrics and threshold selection

Use the Phase 2 definition of lead time and the actual updated `src/code/early_warning.py`; only a sustained (if configured) alert between onset and *before* milestone is early. Report: pre-onset false alarms, pre-milestone coverage, conditional mean and median lead time, **coverage-adjusted** mean lead time (zero for un-warned incidents), false-positive episodes, false alarms/benign hour, late detections, misses. Select alert threshold/persistence against **validation** episodes at a documented false-alarm budget; unavailable threshold is an admissible **failure**. Distinguish current anomaly detection from a separately trained future-horizon predictor; do not call the former a future-event prediction model.

## Skill 13 — Leakage-safe evaluation and honest comparison

Split by **whole experiment episode before windowing**. Freeze common `policy=test` episodes, with the `slow_ramp` family held out in the V2 scheme. Keep all manifests, source hashes, split IDs, feature schema, fit-only scalers, hyperparameter study history and model checkpoints. Distinguish random-within-topology from actual cross-topology transfer: the current Compose lab has **only one** defined network configuration. No topology-generalisation claim until a second independent network configuration is actually measured and withheld. Verify class counts before reporting AUROC/forecast scores. Avoid basing significance tests on correlated overlapping windows; bootstrap by episode or higher unit.

## Skill 14 — CPU baselines, HPO and model exports

Run a rule baseline, Random Forest and Isolation Forest first on the same causal network features. For HPO use Optuna TPE with persistent SQLite DB and validation-only objectives, no nonfinite values, no empty splits, and per-trial failure/pruning metadata. The earlier 90 trials (30 per policy) were run on the **tiny first pilot** and must not be reused as new staged-data evidence. A loaded SQLite study resumes trials, but the sampler's complete RNG state is not automatically persisted; exact bit-for-bit continuation requires additional state handling. Official: https://optuna.readthedocs.io/en/stable/tutorial/20_recipes/001_rdb.html .

Record model/scaler/feature-schema versions, train/validation/test manifest SHA-256 and metric provenance. Don't let multiple workers write the same SQLite DB or checkpoint directory. Fail on NaN/Inf or invalid class splits. Use CPU thread limits during multi-worker execution to avoid contention.

## Skill 15 — GPU training, checkpointing and **mandatory live logging**

CUDA is available on the university RTX 4000 Ada, but RF/IsolationForest remain CPU models. The existing `src/code/temporal_gru_sprint.py` GRU is **not** a graph model. For PyTorch, save **after every epoch** (atomically where possible): model weights, optimizer/scheduler state, epoch, best validation metrics, hyperparameters/config hash, RNG/sampler state where feasible, device/versions and fit-only preprocessing. Validate a genuine interrupted-run resume; avoid silently restarting. Separate latest checkpoint, validated best checkpoint and inference-only export. Official: https://docs.pytorch.org/tutorials/beginner/saving_loading_models.html .

Every nontrivial process MUST use these logging conventions:

- Terminal + persistent run-specific log in `outputs/logs/<stage>/<run_id>/` or run directory; UTC ISO-8601 with stage label, run ID and executable command.
- **Progress at start and each meaningful unit** (round, epoch, HPO trial, file processed). Also heartbeat during long silent periods (recommended every 15–30 seconds or stage-appropriate cadence).
- Append-only JSONL event log where useful, periodic atomic `status.json`, `latest`/`checkpoint` pointer, and clear final `SUCCESS` or `FAILED` with exit code and next resume command.
- Use `tee` or unbuffered Python (`python -u` / `PYTHONUNBUFFERED=1`) to prevent the appearance of a silent hang; verify PIPESTATUS and pipefail so failure isn't swallowed by `tee`.
- Print data sizes and useful throughput estimates, but never guess performance or announce success before validated artefacts exist.
- `tmux` for SSH stability; **does not survive shutdown**. Confirm no activity remains before institutional closing time and back up to a second persistent storage location.

## Skill 16 — Controlled concurrency and job scheduling

Safe parallel workers after **data collection**: (1) independent Zeek audit, (2) CPU baseline evaluation, (3) persistent CPU Optuna, (4) one GPU GRU/graph-training job, provided they use separate output paths and manageable CPU threads. `setup/staged_train_start.sh` creates individual `tmux` sessions; `setup/staged_train_guard_v3.sh` first validates PCAP structural evidence. Check `./setup/staged_status.sh`, `tmux ls`, `nvidia-smi`, CPU/RAM and root filesystem.

**Do not run multiple captures, or train heavy CPU/GPU jobs concurrently with timing-sensitive traffic generation**, because resource competition biases inter-arrival times and network latency. Avoid two GPU HPO jobs or writes to same SQLite DB. Start a fresh run ID for scientifically independent repetitions; use `--resume` solely for the same run/config.

## Skill 17 — Build a real graph baseline only if justified

Define node identity (host/service), directed edges (Zeek connection flows), edge time and attributes, lookback window, unknown-host policy and graph sample target (host, edge, time-window, or episode). Make graph features causal and local to each episode; test no graph references a future connection. Build a simple relational GNN (GraphSAGE or edge-aware GAT) + temporal comparator only after establishing actual captured host-to-host structure and sufficient variation. Keep controlled feature-only RF, temporal GRU and graph-free MLP as fair references. Ablate graph edges, time encoding and neighbour aggregation; consider graph-free wins legitimate.

## Skill 18 — Statistical evaluation and ablations

Run repeated **independent experiment seeds** and hold out scenario families and topology (only once enough independent topologies exist). Compare fixed/uniform/strategic with identical frozen test and data budget. Report macro-F1/precision/recall/PR-AUC, warning coverage, conditional/adjusted `T_lead`, false alarms/hour, time to detection, confidence intervals and inference/runtime/memory. Group bootstrap by **episode**, not correlated flow windows; report uncertainty, count of positive pre-milestone examples and failure cases. Required ablations: scenario policy, causal temporal features, graph/relations, warning persistence/threshold, unseen scenarios, test topology and capture source if defensible.

Never compare source-paper numeric scores directly without showing dataset, attack type, split, labels, feature availability and evaluation alignment. If exact paper code/data are unavailable, record attempted retrieval and faithful implementation deviations; do not invent paper reproductions.

## Skill 19 — Safe Git, file preservation and rollback

Use `git status --short --branch`, `git diff --check`, `git diff --stat`, and inspect `git ls-files` vs ignored data. The laptop ZIP's `.gitignore` contains irregular entries (including an ignored `.gitignore`); fix tracking **only after inspecting live state**. Never delete precious ignored files. Commit small, relevant **normal Git** source/config/docs/test changes; **no Git LFS**. Don't commit large model checkpoints, PCAP, SQLite, private logs, `.env` or credentials; normal small JSON manifests can be tracked after privacy/reproducibility review. `.gitattributes` may declare text/binary handling but never an LFS filter. Avoid `git clean -fdx`, hard resets, destructive rebases/force pushes and broad `docker prune`.

Before an edit, snapshot only the relevant source file to a timestamped `outputs/backups/...` directory. Maintain a tested rollback and run-aware changelog; never use a hotfix ZIP blindly if its SHA/site contract does not match the live file.

## Skill 20 — Stop criteria, recovery and acceptance

A change is not finished until the appropriate gates pass: syntax, targeted tests, live small real-data smoke, sensor and time alignment, valid output schema/numerics, true checkpoint replay where claimed, actual CPU/GPU path, metrics with unit/denominator, saved logs/manifest, clean reviewed diff, and rollback instructions. If a failure cannot be fixed within a reasonable number of evidence-driven attempts, preserve state, clearly report **the exact blocker**, and work on an independent priority without corrupting the experiment.

### Diagnostic quick-reference

| Symptom | Likely issue | Required action |
|---|---|---|
| `STAGED_CAPTURE_NAME required` | Compose overlay interpolated before variable set | Define before config or use V3 direct capture; do not hide error |
| `Couldn't change to 'tcpdump' uid...` | Restricted container blocks tcpdump UID/GID switch | Check expected V3 invocation; consider scoped `-Z root` hotfix and verify live |
| 24-byte PCAP | Global header only, zero packet records | Reject PCAP; do **not** infer captured network traffic |
| `Another staged collector holds lock` | Existing/suspended process still holds `flock` | Inspect jobs/processes; terminate only verified job; **never delete lock blindly** |
| `docker ps` permission denied | Current shell lacks Docker socket permission/context | Inspect groups/context; approved re-login; avoid broad socket permissions |
| Zeek checksum warnings | Offloading/incomplete trace possible | Inspect; `-C` only with documented caveat; check payload and directions |
| `pytest11` / ROS `lark` error | Unrelated autoloaded ROS pytest plugin | `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1` unless plugin explicitly needed |
| HPO PR-AUC = 1 on tiny pilot | Simple separable lab profiles, possible shortcut/overfit | Audit labels/features/splits; don't claim real-world detection |
| GPU idle during RF | scikit-learn RF/IsolationForest run on CPU | Not a CUDA failure; use torch only for graph/GRU models |
| Docker root low disk | Docker data-root separate from project volume | Check `docker system df`; don't assume project 1.3TB applies to images |
| Physical shutdown | `tmux` sessions die | Commit rounds/checkpoints; externally back up, verify resume |

## Skill 21 — Documentation and reporting

Maintain `MEMORY.md` as date-stamped verified handover, `AGENTS.md` as mandatory rules, `SKILLS.md` as repeatable playbooks, `INSTRUCTIONS.md` as active queue. Document architecture, versions, schema, invariants, exact run IDs, seeds, data splits, hashes, model artefacts, error analysis and known negatives. Phase 3 report must fulfil its official rubric: implemented method, dataset/preprocessing, baselines, results/figures, comparable literature comparisons, ablation and critical discussion. No claim that controlled profile F1 implies real-world NIDS efficacy. Use British English technical style.
