# Phase 3 Stage V2 capture-variable hotfix

## Verified failure
`staged_collect_v2.sh` passed `STAGED_RUN_ID` to the shell, then ran
`docker compose -f compose.yaml -f compose.staged.capture.yaml config --quiet`
**before** exporting `STAGED_CAPTURE_NAME`. The overlay correctly used the
required Compose syntax `${STAGED_CAPTURE_NAME:?STAGED_CAPTURE_NAME required}`,
so Compose terminated before starting a new episode. The partially initialised
run directories are not necessarily faulty.

## Apply safely on university Ubuntu

```bash
cd /home/fastlab/deepFakeDetection/adaptive-network-intrusion-detection
bash ~/Downloads/fix_stage_v2_capture.sh "$PWD"
source .venv-cuda/bin/activate
export PATH="/opt/zeek/bin:$PATH"
export PYTEST_DISABLE_PLUGIN_AUTOLOAD=1
bash -n setup/staged_collect_v2.sh
./setup/preflight.sh
```

This patch updates **only** `setup/staged_collect_v2.sh`, first checking exact
original code markers, and backs up the previous file under `outputs/backups/`.
It is idempotent and does not touch any raw captures, model checkpoints, study
databases or initialised run directories.

## Verify no existing capture remains

```bash
sudo pgrep -a -x tcpdump || true
docker ps
```

If `tcpdump` remains, inspect its exact PID and output file first. Stop **only**
old captures associated with these experiments, from an authorised terminal,
e.g. `sudo kill -INT ACTUAL_VERIFIED_PID`. Do not run broad `pkill` or delete
captures. Ensure any old suspended `university_pilot` scripts are no longer
active before starting a new experiment.

## Resume the already initialised runs

First, the small pilot:

```bash
./setup/staged_collect_v2.sh --run-id staged_v2_check_01 --rounds 3 --test-rounds 3 --seed 20261114 --capture --resume
```

Validate the pilot:

```bash
ls -lh src/data/raw/runs/staged_v2_check_01/{complete.json,gateway_subset.jsonl}
wc -l src/data/raw/runs/staged_v2_check_01/episodes.jsonl
find src/data/raw/runs/staged_v2_check_01 -maxdepth 1 -name 'traffic_*.pcap' -ls
```

Expected at full completion: 24 episodes, 480 gateway observations.

Then resume the main run **only after** the pilot capture completed and audit
checks passed:

```bash
./setup/staged_collect_v2.sh --run-id staged_v2_main_01 --rounds 12 --test-rounds 12 --seed 20261115 --capture --resume
```

Expected at full completion: 96 episodes, 1,920 gateway observations.

Then start parallel model jobs (CPU baselines, Optuna, GRU and gated Zeek audit):

```bash
./setup/staged_train_start.sh staged_v2_main_01 --hpo-trials 30 --gru-epochs 80
./setup/staged_status.sh
```

No claim is made that the Docker sidecar, full capture completeness, or the
university runtime has been verified by this local fix. This hotfix only
addresses the missing Compose interpolation variable. Check available Docker
storage if building `lab/Dockerfile.capture` fails, and validate Zeek coverage
and timing before interpreting experimental metrics.
