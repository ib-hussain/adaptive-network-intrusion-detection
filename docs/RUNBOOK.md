# University Phase 3 Parallel Research Sprint — operational runbook

**Target repo:** `~/deepFakeDetection/adaptive-network-intrusion-detection` on the university Ubuntu machine.
**Baseline observations:** `pilot_20261113T083155Z_61354` finished with 32 complete episodes, 384 HTTP gateway records, a ~600-KB PCAP, and Zeek logs. These are **controlled non-malicious lab observations**. The previous `pilot_...102813Z_79699` may be hung in the capture-stop wrapper; do not call it complete without checking.

## Start immediately — three independent jobs, one command

1. Extract `Phase3_Parallel_Research_Sprint.zip` **into the repository root**. The ZIP adds only new files under `setup/`, `src/code/`, `tests/`, and `docs/`; it does not overwrite previous launchers.
2. From a terminal, with `.venv-cuda` active and the Zeek path exported, execute:

```bash
cd /home/fastlab/deepFakeDetection/adaptive-network-intrusion-detection
unzip -n ~/Downloads/Phase3_Parallel_Research_Sprint.zip -d .
chmod +x setup/sprint_*.sh setup/university_pilot_v3.sh setup/zeek_from_pcap_v3.sh
export PATH="/opt/zeek/bin:$PATH"
export PYTEST_DISABLE_PLUGIN_AUTOLOAD=1
python -m pytest -q tests/test_sprint_modules.py
./setup/sprint_start.sh pilot_20261113T083155Z_61354 --hpo-trials 30 --gru-epochs 60
./setup/sprint_status.sh
```

Three parallel `tmux` sessions launch:

- **PCAP/Zeek audit:** verifies PCAP structure, file hashes, gateway records and run manifest. Reprocesses the existing PCAP with `zeek -C` into an untouched, separate derived directory. Only if it passes coverage/content gates does it attempt the actual Zeek **network-flow** baseline as a fourth sequential step within this audit worker. This job is read-only with respect to original data.
- **CPU HPO:** 30 **additional** Optuna TPE Random Forest trials for each policy, saving separate SQLite studies in `outputs/hpo/sprints/<RUN_ID>/`. Re-running *adds* trials; it does not restart a completed study or delete the SQLite file. Results on this tiny pilot have no scientific generalisation claim.
- **GPU GRU:** a small causal temporal model (not a GNN) trained on episode-safe gateway observation windows; CUDA is preferred. Epoch checkpoints with model + optimiser + RNG state are written to `outputs/model/sprints/<RUN_ID>/`. If interrupted before `complete.json`, re-executing the job resumes from the last epoch. Completed policies are skipped to prevent destructive overwrite.

Check job status:

```bash
./setup/sprint_status.sh
tmux ls
cat outputs/sprints/latest_sprint_path.txt
```

Review separate logs at the path printed by `sprint_start.sh`; use `tail -f /absolute/path/to/gru.log`. Do not treat the absence of a tmux session as success; check the `.exitcode` marker and `complete.json` / `audit.json`.

**Isolation:** all tasks read immutable completed-run files and produce separate output directories. Do not run two HPO or two GRU jobs for the *same* run simultaneously, as they share per-policy checkpoints/SQLite databases.

## Existing 12-episode pilot

Inspect in a second terminal:

```bash
ps -eo pid,ppid,stat,etime,args | grep -E '[u]niversity_pilot|[t]cpdump|[d]ocker compose'
RUN=pilot_20261113T102813Z_79699
wc -l "src/data/raw/runs/$RUN/episodes.jsonl"
ls -lh "src/data/raw/runs/$RUN/"
docker compose ps -a
```

The 12-episode pilot should create 96 manifest rows and 1,152 gateway request observations **if the run completed fully** (4 policies × 12 benign and 12 incident episodes × 12 requests). A manifest file by itself does not prove success.

If the runner has finished and only an old `tcpdump` or sudo-wrapper remains, stop only that run's verified PID with administrator approval, and then run the existing recovery script:

```bash
./setup/university_finish_existing.sh pilot_20261113T102813Z_79699
```

Do not kill unrelated captures, remove Docker volumes, clear `outputs/`, run `docker system prune`, or restart the same run ID. If the v2 launcher is still running, do not start another collector on the same Compose service bridge.

## Start the next network collection, separately from HPO/GPU/audit

After verifying the old capture stopped, no pilot launcher remains, and the CPU-heavy HPO and GPU model tasks are finished (or you have measured and controlled resource contention):

```bash
sudo -v
./setup/university_pilot_v3.sh --episodes 12 --seed 20261114 --capture
```

**Run this in a dedicated interactive Ubuntu terminal** to preserve `sudo -n` permissions. Avoid overlapping a scientific traffic capture with CPU-saturating HPO/training on the same host: the extra load can change observed request timing and confound the comparison. Parallelise processing of *completed* runs; keep new capture collection exclusive and under a documented stable compute load. The v3 wrapper uses a per-repository capture lock, a fresh experiment ID, records the scenario seed, invokes `zeek -C`, and does not execute an unbounded wait on the sudo capture wrapper. It does not resume unfinished traffic episodes. The wrapper must still be verified on your university machine; it is not yet certified for unattended extended capture.

The new generation code keeps the old `paced/bursty/fanout` **harmless** patterns. Increasing episode count or changing the seed does **not** create genuine malware or new exploit families. For defensible Phase 3 results we must later define independently observable multi-stage network milestones, vary topology/services/benign workloads, and use a truly held-out scenario family with adequate positive warning examples. Separate gateway log observations from Zeek flow observations; do not pool them as if independent connections.

## Before lab shutdown

Inspect the job exitcodes and checkpoint files, then back up to persistent/external storage. Use the existing non-destructive university backup script with a path you control:

```bash
./setup/sprint_status.sh
./setup/university_backup.sh /path/to/persistent-backup
```

The job sessions and active CPU/GPU computations cannot survive power-off; saved epoch checkpoints and Optuna studies can. Do not assume the in-memory EXP3 game has been checkpointed — it has not. End-of-day backups must complete before shutting down.

## Safety and validity notes

- Optuna SQLite supports persistence of completed trials but does not itself store every sampler/internal state bit; resume is practical but not necessarily bitwise identical to one uninterrupted run.
- Early-warning leads from artificially fixed final-request milestones are **engineering feasibility tests**, not evidence of pre-impact detection in a real network.
- Zeek `-C` is the documented option for handling checksum-offload artefacts in traces; it does not repair incomplete bridge visibility or guarantee application payload capture. Inspect the PCAP and `audit.json`.
- This patch does not implement a graph neural network. The GPU GRU is a separate temporal baseline; graph neural models and meaningful holdout topology experiments remain future work.
