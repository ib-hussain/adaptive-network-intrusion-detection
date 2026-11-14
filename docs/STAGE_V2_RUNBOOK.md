# Phase 3: staged, causally labelled network research — university runbook

## 0. Verified state from the uploaded laptop ZIP and university logs

The **earlier** 32-episode pilot completed with 384 application gateway observations and 384 Zeek connection records spanning all 32 episodes. The 96-episode/1,152-request pilot was separately postprocessed. The read-only Optuna sprint completed 90 trials; all three GRU training-policy outputs report epoch 60. These are non-malicious controlled traffic evaluations, not evidence of production intrusion detection. Several earlier collection wrappers were stopped or left `tcpdump` running. The laptop ZIP does **not** include university raw PCAPs, gateway subset JSONL files, full GPU model checkpoints, or SQLite HPO studies, which remain on that machine. **Never delete or overwrite them.**

## 1. Install patch safely (same command on WSL or Ubuntu)

This ZIP contains only a *patch*, not a replacement repository. It adds a new staged scenario generator, Docker network-namespace capture sidecar, restartable training launcher, and strict causal-label checks. It modifies five existing source files. The installer checks their original SHA256 before changing anything and puts backup copies in `outputs/backups/staged_v2_<UTC>`. If your university files differ from the submitted laptop ZIP, installation STOPS instead of overwriting unknown edits. No Git reset or repository cleaning is involved.

```bash
cd /home/fastlab/deepFakeDetection/adaptive-network-intrusion-detection
mkdir -p /tmp/phase3-stage-v2
unzip -q ~/Downloads/Phase3_Staged_Network_Research_V2.zip -d /tmp/phase3-stage-v2
bash /tmp/phase3-stage-v2/install.sh "$PWD"
source .venv-cuda/bin/activate
export PYTEST_DISABLE_PLUGIN_AUTOLOAD=1
export PATH="/opt/zeek/bin:$PATH"
./setup/preflight.sh
```

> If the ZIP was copied to the repository root rather than `~/Downloads`, use its **actual path** in the unzip command.

## 2. Do NOT start a new capture until old ones are gone

First inspect live processes and job control:

```bash
pgrep -a -x tcpdump || true
ps -eo pid,ppid,stat,etime,args | grep -E '[t]cpdump|[u]niversity_pilot' || true
docker compose ps -a
tmux ls || true
```

The earlier logs showed `tcpdump` PIDs 74855, 80058 and 94532, but **PIDs can be reused**. They are NOT safe to kill by memorised number. Only after checking each exact live process and PCAP destination, stop the relevant former capture gracefully from an authorised Ubuntu terminal:

```bash
sudo kill -INT ACTUAL_VERIFIED_TCPDUMP_PID
```

If an old `university_pilot_v2.sh` is suspended by `Ctrl+Z`, recover or terminate that shell job by its job-control identifier in the *same terminal*, after preserving files. Do **not** run `pkill tcpdump`, `docker system prune`, `docker compose down -v`, or `chmod 666 /var/run/docker.sock`. The new launcher itself checks for old captures on the relevant Docker bridge and refuses to overlap them.

## 3. Collect stage-labelled network observations (no root-owned host tcpdump)

**First** make sure `docker ps` works under this account and no previous capture is active. The sidecar shares only the existing gateway container's network namespace and has NET_RAW capability; it has no host-network mode. It records both client/gateway and gateway/service TCP-8080 traffic into your persistent project `src/data/raw/runs/<RUN_ID>/` directory. An image is built once from the cached `python:3.12-slim` base by adding `tcpdump`; this needs Ubuntu package access once. If that is unavailable, `--no-capture` tests only the application instrumentation and is **not sufficient for network-flow findings**.

Short gated pilot, then independently larger collection:

```bash
./setup/staged_collect_v2.sh --run-id staged_v2_check_01 --rounds 3 --test-rounds 3 --seed 20261114 --capture
./setup/staged_collect_v2.sh --run-id staged_v2_main_01 --rounds 12 --test-rounds 12 --seed 20261115 --capture
```

The main collection will generate 96 complete episodes (four policies, 12 benign and 12 controlled incident per policy), each with **20 genuinely observed HTTP requests**: 1,920 accepted lab requests. Incident onsets occur at request index 5, escalation at 12 and a separately timestamped harmless 2 KiB transfer at 19. The final transfer is NOT real data exfiltration. Benign traffic includes maintenance bursts, service fanout and approved bulk transfers. The *held-out test incident profile* is `slow_ramp`, withheld from all three policy-training menus. This is scenario-family novelty, NOT a genuine zero-day exploit or held-out network topology.

**Crucial fairness caveat:** event counts and policy budgets are matched, but physical time-duration/packet-byte budgets may still differ across profiles. Report those differences rather than claiming perfect matched-budget experimental validity.

### Resume an interrupted experiment

The generator writes each completed benign+incident pair as one atomic round journal. An interrupted/partially generated round is **not published** and will be rerun with a new unique episode ID; orphan gateway events are ignored by the independent extractor. The EXP3 strategy is deterministically replayed from the saved round journals. No byte-for-byte reproduction of an interrupted HTTP request is claimed.

```bash
./setup/staged_collect_v2.sh --run-id staged_v2_main_01 --rounds 12 --test-rounds 12 --seed 20261115 --capture --resume
```

**Do not change the original seed, budget or run ID while resuming.** An interrupted restart creates another PCAP segment rather than overwriting a previous one. The script refuses a mismatched run configuration.

## 4. Start CPU HPO, GPU temporal training, CPU baselines and Zeek analysis in parallel

**Only after** the staged collection has produced both `complete.json` and `gateway_subset.jsonl`, launch:

```bash
./setup/staged_train_start.sh staged_v2_main_01 --hpo-trials 30 --gru-epochs 80
./setup/staged_status.sh
tmux ls
nvidia-smi
```

This creates four distinct tmux workers: (1) CPU baseline evaluation, (2) Optuna SQLite HPO, (3) epoch-checkpointed CUDA GRU, and (4) independent packet/Zeek processing with a network-flow baseline **only if the Zeek coverage gate passes**. All model decisions use causal feature windows and label observations *positive only after onset*; warnings before the independently timed onset are not awarded lead time. All data live under the large 1.3-TB project disk; Docker's root filesystem previously had only ~17 GB available, so do not accumulate unnecessary images or build caches.

Optuna re-invocation with the same study adds *additional* trials. The GRU has per-epoch resumability if interrupted before `complete.json`, but a **completed** model run is skipped; change the output path deliberately for a new modelling experiment. The model is a temporal GRU, **not a graph neural network**. A GNN and genuine topology-holdout are still separate research milestones.

**No parallel capture:** running CPU-heavy HPO and GPU model training while a new network capture is being recorded changes server timing and confounds traffic comparisons. Parallelise completed-data computation, not simultaneous collection.

## 5. Read and validate results before claiming findings

```bash
./setup/staged_status.sh
find outputs/results -maxdepth 2 -name results.json -print
find outputs/model/staged -name complete.json -print
find outputs/hpo/staged -name '*.sqlite3' -print
find src/data/raw/runs/staged_v2_main_01 -maxdepth 2 -type f -printf '%p %s bytes\n'
```

The early-warning metric requires an alert at or after onset, and before the independently logged dummy-transfer milestone. Lead time remains constrained by false-positive and **pre-onset** false-warning rates. If zero held-out positives or inadequate Zeek coverage prevents a metric, report it as unmeasurable, not zero or perfect.

**Before leaving the lab:** preserve raw captures, journals, HPO SQLite, GRU epoch checkpoints, Zeek and derived results using the existing university backup script to a **different persistent location**. The local laptop ZIP excluded raw captures; a laptop ZIP cannot substitute for the university's authoritative dataset.

## 6. Known limits and next scientific steps

1. This is a controlled **proxy behaviour** lab. No malware, unauthorised vulnerability exploitation, network propagation, verified zero-day exploit or real data leakage occurs.
2. All scenarios use two services behind one gateway in two Docker network segments; **no unseen topology generalisation claim** is warranted yet.
3. The transfer milestone is a controlled dummy 2 KiB request. Causally valid warning for this milestone is experimentally measurable, but it does not establish useful enterprise warning time.
4. Sensor coverage is audited from independently captured PCAPs; gateway instrumentation is kept separate. Zeek `-C` handles likely checksum-offload artefacts but cannot repair packet loss or hidden traffic.
5. Complete source + study manifests and leakage-safe splits are maintained. Compare fixed, random and strategic methods on the same *held-out* test and independently repeated seeds. Do not present one run as a statistically significant result.
6. After the first verified main run, prioritise independent topology variation, graph construction with true measured host links, a modest graph neural baseline, and resource/lead-time ablations.
