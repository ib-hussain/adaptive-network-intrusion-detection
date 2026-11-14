# Phase 3 — Stage V3 Capture Recovery & Observable Runs

## Diagnosed from the 2026-11-14 university transcript

- The prior `staged_v2_check_01` generator successfully committed **24 episodes**, but the wrapper was suspended at packet-capture shutdown.
- `traffic_20261114T051137Z_112948.pcap` has a file length of **24 bytes**, which is a classic PCAP global header and **zero packet records**. Its existence is **not** evidence of network capture.
- Therefore `gateway_subset.jsonl` was not extracted by the interrupted wrapper; it can still be recovered from the persistent gateway log.
- The stalled process retained the `flock` descriptor, causing `Another staged collection is active`. Deleting the lock file is **not** a safe fix.
- The independent main run `staged_v2_main_01` has an initialised configuration, but the shared transcript does **not** show any completed rounds for it.

## 1. Installation

Copy `Phase3_Stage_V3_Capture_Recovery.zip` to the project directory on the university machine and run:

```bash
cd /home/fastlab/deepFakeDetection/adaptive-network-intrusion-detection
mkdir -p /tmp/p3-v3
unzip -q Phase3_Stage_V3_Capture_Recovery.zip -d /tmp/p3-v3
bash /tmp/p3-v3/install.sh "$PWD"
source .venv-cuda/bin/activate
export PATH="/opt/zeek/bin:$PATH"
export PYTEST_DISABLE_PLUGIN_AUTOLOAD=1
./setup/preflight.sh
```

This is **additive**: original V2 launcher and all data stay as they are. The installer refuses to overwrite a differing V3 file.

## 2. Clear the suspended launcher, not its data

Use the **same shell that has the suspended job**:

```bash
jobs -l
```

If the job shown is **specifically** the stuck `staged_collect_v2.sh` process, stop that job with `kill %1` (change `1` to the actual job number). In a separate shell, check:

```bash
ps -eo pid,ppid,stat,etime,args | grep -E '[s]taged_collect|[t]cpdump'
sudo pgrep -a -x tcpdump || true
docker ps --format 'table {{.Names}}\t{{.Status}}'
```

Do not globally kill Docker or `tcpdump`, do not delete the lock path, and do not clear the run directory. If the process remains despite `kill %1`, identify its **actual** PID and inspect it before terminating it. On an institutional computer, follow local administrative policy.

## 3. Recover the already completed pilot's gateway observations

```bash
./setup/staged_recover_v2.sh staged_v2_check_01
```

This should create `src/data/raw/runs/staged_v2_check_01/gateway_subset.jsonl` if the 480 observed requests remain available. It will also report that the existing **24-byte PCAP has zero packets**. The script exits nonzero for that invalid capture; this is deliberate and does not mean that the gateway data were lost.

### Why the same pilot cannot be fixed by `--resume`

The experiment has already committed the 24 episode bundles. The generator's `--resume` correctly skips them. It cannot recreate their historical network packets. **Do not treat a newly opened PCAP as if it contained those already-completed episodes.** The old run is application-only diagnostic data.

## 4. Start a fresh network-observed pilot

```bash
./setup/staged_collect_v3.sh --run-id staged_v3_check_02 --rounds 3 --test-rounds 3 --seed 20261114 --capture
```

V3 uses a **separate Docker capture container**, directly attached to the gateway network namespace. It does **not** invoke the V2 Compose capture overlay. It performs 4 HTTP probe requests, verifies that real packets appear in the growing PCAP, then begins the 24-episode generator. It writes the container's final stdout/stderr and stops the container with a bounded Docker signal. The data collector requires a closed PCAP containing actual packet records before reporting capture success. The network setup and capture still require the first real university verification.

During a run, open another terminal:

```bash
./setup/staged_v3_status.sh staged_v3_check_02
./setup/staged_v3_status.sh staged_v3_check_02 --follow
```

Logs have UTC timestamps, worker heartbeat, completed-round count, and last runner output. Run-specific logs are preserved under `src/data/raw/runs/RUN_ID/collector_v3_*.log` and `generator_*.log`. Status: `collector_status_v3.json`. Use **Ctrl+C** to interrupt, **not Ctrl+Z**, because suspension preserves locks and leaves capture workers alive.

The fresh pilot should produce **24 committed episodes, 480 gateway request observations** plus **4 separately labelled capture-probe requests**. The probe requests are intentionally excluded from the 24-episode dataset by manifest-ID matching.

If packet capture fails preflight, the script prints `docker logs` and exits before collecting the episodes. Do not start training if the PCAP audit fails.

## 5. Resume the already initialised main experiment

**Only after V3 pilot and its Zeek alignment check pass:**

```bash
./setup/staged_collect_v3.sh --run-id staged_v2_main_01 --rounds 12 --test-rounds 12 --seed 20261115 --capture --resume
```

Main budget: **96 episodes / 1,920 observed HTTP requests**. The launcher leaves previous V2 files untouched and uses a distinct new PCAP filename.

To start the four training workers after the main collection:

```bash
./setup/staged_train_guard_v3.sh staged_v2_main_01 --hpo-trials 30 --gru-epochs 80
./setup/staged_status.sh
```

The training wrapper fails closed for insufficient captured packet records. Passing it still requires an independent Zeek/manifest audit for research-grade network validation. Prior research scores on tiny harmless profiles are *not* real intrusion-detection evidence.

## 6. Pre-shutdown checklist

```bash
./setup/staged_v3_status.sh staged_v2_main_01
pgrep -a -x tcpdump || true
docker ps --filter 'label=phase3.staged.capture=1'
df -h .
```

After closing V3 collection and GPU workers, use the existing approved end-of-day backup script to a **separate persistent device/destination**. `tmux` cannot preserve running computations through a physical shutdown. Avoid Docker image pruning, `docker compose down -v`, deleting raw runs, and clearing SQLite/checkpoint directories.

## Key limitations

- A structural PCAP count proves that packets were captured, **not** that all episodes were captured or time-aligned. Zeek independent coverage evaluation remains mandatory.
- The controlled traffic profiles are not actual malware, authentic zero-day exploitation, or real data exfiltration.
- The recovery patch has been syntax/unit tested without Docker. Direct Docker-sidecar packet visibility requires validation on the university machine.
