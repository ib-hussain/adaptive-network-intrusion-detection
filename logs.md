## Repository audit: confirmed results

I inspected the uploaded repository and its saved research outputs.

| Component                         | Verified from files                                              | Assessment                 |
| --------------------------------- | ---------------------------------------------------------------- | -------------------------- |
| Initial network pilot             | 32 episodes, 384 HTTP observations                               | Completed                  |
| Independent Zeek audit            | 384 connection records, all 32 episodes covered                  | Passed recorded checks     |
| Random Forest HPO                 | 90 completed Optuna trials                                       | Completed                  |
| GPU temporal GRU                  | 60 epochs per policy; completion records present                 | Completed                  |
| Expanded pilot                    | 96 episodes, 1,152 gateway observations                          | Postprocessed successfully |
| Additional captures               | Some stopped launchers and lingering `tcpdump` processes in logs | Requires cleanup           |
| Unseen-attack generalisation      | Not established                                                  | Research gap               |
| Genuine multi-stage early warning | Not established                                                  | Research gap               |

The current Random Forest validation PR-AUC of 1.0 is **not proof of excellent intrusion detection**. The existing traffic profiles are small and deliberately distinguishable, and their incident milestone is artificially placed at the final request.

More HPO on those same profiles would have limited scientific value.

**I'm moving development to the next experiment version:** separately identifiable precursor and milestone events, an unseen held-out behaviour, causal labels, recoverable collection rounds, and independent capture-process management.

Ibrahim, I've completed the next substantial Phase 3 development patch using your actual repository and university logs. **We are moving beyond the original pilots to a new, staged network experiment.**

## 1. Download the new development package

**Phase 3 — Staged Network Research V2**

ZIP · 15 implementation and documentation files · Safe installer · Automated tests

[Download Phase 3 Research V2]\(/mnt/data/Phase3_Staged_Network_Research_V2.zip)

---

[Read the complete university execution runbook]\(/mnt/data/Phase3_Staged_Network_Research_V2/docs/STAGE_V2_RUNBOOK.md)

### What has been implemented

| Component                                                 | Development status                     |
| --------------------------------------------------------- | -------------------------------------- |
| Multi-stage network scenario generator                    | Implemented                            |
| Independently timestamped onset, escalation and milestone | Implemented                            |
| Previously unseen behavioural profile for testing         | Implemented                            |
| Diverse benign traffic profiles                           | Implemented                            |
| Restartable experiment rounds and EXP3 replay             | Implemented                            |
| Causal feature labels and corrected early-warning metrics | Implemented                            |
| Docker-based PCAP capture sidecar                         | Implemented; live verification pending |
| Parallel CPU, GPU and Zeek evaluation                     | Implemented; live verification pending |
| Safe patch installation and original-file backups         | Tested                                 |

**18/18 tests passed**, including complete baseline evaluation and checkpoint recovery.

## 2. Install it on the university machine

Transfer the ZIP to the university machine's `~/Downloads` directory.

```
cd /home/fastlab/deepFakeDetection/adaptive-network-intrusion-detection

mkdir -p /tmp/phase3-stage-v2

unzip -q ~/Downloads/Phase3_Staged_Network_Research_V2.zip -d /tmp/phase3-stage-v2

bash /tmp/phase3-stage-v2/install.sh "$PWD"

source .venv-cuda/bin/activate

export PATH="/opt/zeek/bin:$PATH"
export PYTEST_DISABLE_PLUGIN_AUTOLOAD=1

./setup/preflight.sh
```

The installer verifies file hashes before replacing the five modified source files. If university files differ from your uploaded laptop repository, it stops rather than overwriting unknown changes.

### Important: clear old captures first

Your latest logs still show lingering captures from older pilot launchers.

Run:

```
pgrep -a -x tcpdump || true
ps -eo pid,ppid,stat,etime,args | grep -E '[t]cpdump|[u]niversity_pilot' || true
docker ps
```

If an old lab capture is still running, verify its PID and output path, then stop only that process from an authorised terminal. The new collector refuses to overlap an old host-bridge capture.

## 3. Start the new network experiment

First execute a short integration pilot:

```
./setup/staged_collect_v2.sh --run-id staged_v2_check_01 --rounds 3 --test-rounds 3 --seed 20261114 --capture
```

This should produce 24 completed episodes and 480 observed HTTP requests.

After successful collection and capture validation, begin the larger experiment:

```
./setup/staged_collect_v2.sh --run-id staged_v2_main_01 --rounds 12 --test-rounds 12 --seed 20261115 --capture
```

MAIN EXPERIMENT TARGET

# 96

Experimental episodes

# 1,920

HTTP requests

---

Four policies, including the independent test set. Three controlled incident profiles for training, plus one held-out behavioural profile.

The new capture system runs `tcpdump` inside a Docker sidecar sharing the gateway's network namespace, rather than maintaining a privileged host-side `tcpdump` process. Docker supports this namespace-sharing arrangement.

This should address the earlier process-management problem, but it still needs validation on your machine.

## 4. Start the heavy jobs together

Once `staged_v2_main_01` completes and its observed events are validated, execute:

```
./setup/staged_train_start.sh staged_v2_main_01 --hpo-trials 30 --gru-epochs 80
```

This launches four workers in separate `tmux` sessions.

| Parallel job | Task                                                                            |
| ------------ | ------------------------------------------------------------------------------- |
| CPU baseline | Train and evaluate RF/Isolation Forest using causal labels                      |
| CPU HPO      | Persistent Optuna studies                                                       |
| GPU          | Train checkpointed temporal GRU models                                          |
| Zeek         | Independently process PCAPs, audit coverage and evaluate eligible network flows |

Monitor them using:

```
./setup/staged_status.sh
tmux ls
nvidia-smi
```

The Zeek analysis uses its documented `-C` mode for locally captured traffic with checksum-offloading artefacts. This does not replace checking packet completeness or network visibility.

Run the parallel training workers **after collection**, rather than during capture, to avoid introducing uncontrolled CPU-load changes into the traffic timings.

## 5. Daily shutdown and recovery

If collection stops before completion, repeat it with the same run ID and original settings:

```
./setup/staged_collect_v2.sh --run-id staged_v2_main_01 --rounds 12 --test-rounds 12 --seed 20261115 --capture --resume
```

Completed rounds are preserved. An interrupted round is regenerated with a new identifier; its incomplete observations are excluded from the published dataset.

The GRU retains epoch checkpoints and the HPO uses persistent SQLite studies. Active processes still cannot survive a powered-off computer.

## 6. What remains scientifically unfinished

The new experiment introduces meaningful temporal stages and a withheld behaviour profile, but it is still **controlled, non-malicious network traffic**. It does not yet demonstrate zero-day exploit detection, authentic malicious propagation, or generalisation to an entirely unseen physical topology.

The temporal GRU is also not a GNN. Our next substantial model development must construct communication graphs from the captured network flows and test a graph-based detector against the established tabular and temporal baselines.

**The immediate next milestone is a successful staged V2 Docker capture followed by the four parallel evaluation jobs.** The local code and recovery tests have passed; the live university deployment remains to be verified.

The package preserves your existing research artifacts and provides the commands needed to begin that milestone.
