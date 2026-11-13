Ibrahim, we can start **multiple independent jobs in parallel**, but not multiple simultaneous captures on the same Docker network.

Your logs establish:

- The first pilot completed 32 episodes, 384 gateway observations, three policy evaluations, and Zeek processing.
- Docker permissions are now resolved.
- The newer 12-episode run generated its manifest, but its capture-shutdown sequence has not been confirmed complete.
- The original Zeek capture reported checksum and filtered-trace warnings. These need investigation before we rely on the PCAP-derived features.

The most productive parallel workloads are **Zeek/PCAP validation, resumable CPU hyperparameter optimisation, and a first GPU temporal-model experiment**, while network collection runs as a separate, exclusive job.

Importantly, the present lab still generates harmless traffic profiles rather than actual malicious propagation. Any model scores at this stage are engineering diagnostics, not validated cybersecurity results.

## **Parallel research package ready**

**Phase 3 — Parallel Research Sprint Kit**

Additive ZIP patch · Three parallel research workers · Capture launcher v3 · Checkpointing · Tests

Download the ZIP

Complete execution runbook

### **1. Start three jobs together — university terminal**

Copy the ZIP into the Ubuntu machine's `~/Downloads` directory, then execute:

```
cd /home/fastlab/deepFakeDetection/adaptive-network-intrusion-detection

source .venv-cuda/bin/activate
export PATH="/opt/zeek/bin:$PATH"
export PYTEST_DISABLE_PLUGIN_AUTOLOAD=1

unzip -n ~/Downloads/Phase3_Parallel_Research_Sprint.zip -d .

chmod +x setup/sprint_*.sh setup/university_pilot_v3.sh setup/zeek_from_pcap_v3.sh

python -m pytest -q tests/test_sprint_modules.py

./setup/sprint_start.sh pilot_20261113T083155Z_61354 --hpo-trials 30 --gru-epochs 60
```

This starts three independent `tmux` jobs:

| Job                   | Workload                                                                      | Recovery mechanism                          |
| --------------------- | ----------------------------------------------------------------------------- | ------------------------------------------- |
| Zeek audit            | Reprocess PCAP, verify network observations, attempt gated Zeek-flow baseline | Separate immutable input and derived output |
| CPU HPO               | 30 Optuna trials per policy, 90 trials total                                  | Persistent SQLite studies                   |
| GPU temporal baseline | GRU training, 60 epochs per policy                                            | Checkpoint after every epoch                |

The Zeek reprocessing uses `-C` to handle possible checksum-offloading artefacts, as documented by Zeek. That does not, by itself, prove the capture is complete.&#x20;

[image](https://www.google.com/s2/favicons?domain=https://zeek.org\&sz=32)

Zeek Network Security Monitor



Optuna studies can resume from SQLite, though bit-for-bit identical sampler continuation is not guaranteed without preserving additional sampler state.&#x20;

[image](https://www.google.com/s2/favicons?domain=https://optuna.readthedocs.io\&sz=32)

Optuna 5.0.0 documentation



### **2. Monitor all three jobs**

```
./setup/sprint_status.sh
tmux ls
nvidia-smi
```

The status script displays each worker's output and exit status. Results are stored separately under `outputs/sprints/`, `outputs/hpo/sprints/`, and `outputs/model/sprints/`.

### **3. Recover the existing 12-episode collection**

In another terminal:

```
RUN=pilot_20261113T102813Z_79699

wc -l "src/data/raw/runs/$RUN/episodes.jsonl"

ps -eo pid,ppid,stat,etime,args | grep -E '[t]cpdump|[u]niversity_pilot'
```

A completed 12-episode-per-policy collection should contain **96 episode records and 1,152 HTTP observations**.

If the runner has completed and the old capture processes are stopped, execute:

```
./setup/university_finish_existing.sh pilot_20261113T102813Z_79699
```

Do not start another capture while the previous one is active.

### **4. Start a fresh network experiment**

After the CPU-intensive model jobs finish and the previous capture is safely closed, use the revised launcher in a dedicated interactive terminal:

```
sudo -v
./setup/university_pilot_v3.sh --episodes 12 --seed 20261114 --capture
```

This launcher records the random seed, protects against overlapping v3 captures, and avoids the previous unbounded capture-process wait.

I recommend keeping CPU-heavy training separate from new traffic collection on this shared machine. Otherwise, training load could change network timing measurements and confound our research comparison.

## **Validation status**

**15 automated tests passed locally.**

**Optuna persistence and temporal-model epoch recovery tested locally.**

**University deployment and the revised capture launcher still require live verification.**

I cannot execute commands on your university machine directly. The package is ready for you to start there using the commands above.

The GPU GRU is a **temporal baseline, not yet a GNN**. The next substantive research upgrade must introduce independently timed multi-stage incidents, meaningful unseen network behaviours, and topology variation. The existing EXP3 generator also remains episode-restartable rather than checkpoint-resumable.

**Start with the command in Section 1.** It launches the three independent workers together without disturbing your existing completed pilot.
