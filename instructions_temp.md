## **Phase 3 — Progress and verified status**

I have read the four new project documents and the newer university execution log.

The project has progressed beyond the earlier `tcpdump` failure.

| Component                  | Latest supplied evidence                       |
| -------------------------- | ---------------------------------------------- |
| V3 pilot                   | 24 episodes, 480 HTTP requests                 |
| Packet capture             | 13,550 packets reported                        |
| Zeek                       | 960 assigned connections                       |
| CPU baselines              | Completed                                      |
| Optuna                     | 90 trials completed                            |
| CUDA GRU                   | Three models trained for 80 epochs             |
| Main 96-episode experiment | Still blocked by a later exit-code-124 timeout |
| Genuine GNN                | Not present in the earlier repository version  |

**I have also implemented and locally tested a new 20–50-employee Docker lab add-on**, including two topology configurations, causal feature extraction, parallel CPU training, and a GraphSAGE–GRU model with checkpoint recovery.

The six local regression tests pass. These are software tests, not evidence that the new Docker experiment has successfully run on the university workstation.

## **Download the implementation**

**Adaptive NIDS — 20–50 Node Lab & Training Add-on**

ZIP · 19 files · 42 KB · Integrity checked

Supporting documentation

Complete execution runbook

Local verification report

### **What the implementation includes**

- **20–50 employee containers**, with Sales, Engineering, HR and Finance workloads.
- **Five private network segments** in the departmental configuration, plus a flat-network alternative.
- Controlled traffic generation, independent ground-truth timestamps and packet-capture validation.
- Six parallel CPU model jobs: Random Forest and Isolation Forest for each scenario policy.
- Three GPU GraphSAGE–GRU training runs, executed sequentially to avoid competing GPU workloads.
- Persistent model checkpoints, recovery, logs and early-warning evaluation.

### **Run it on the university machine**

After verifying that no existing capture job is running, transfer the ZIP to `~/Downloads` and execute:

```
cd /home/fastlab/deepFakeDetection/adaptive-network-intrusion-detection

source .venv-cuda/bin/activate
export PATH="/opt/zeek/bin:$PATH"
export PYTEST_DISABLE_PLUGIN_AUTOLOAD=1

unzip -n ~/Downloads/Adaptive_NIDS_OrgLab_Addon.zip -d .

chmod +x setup/orglab_*.sh

python -m pytest -q tests/test_orglab.py
```

Then launch the 20-employee pilot, its capture and validation, and the guarded training workflow:

```
./setup/orglab_run.sh \
  --run-id org20_pilot_01 \
  --nodes 20 \
  --topology departmental \
  --rounds 6 \
  --test-rounds 6 \
  --seed 20261114 \
  --step-seconds 0.6 \
  --train
```

This configures **48 episodes and 1,152 experimental HTTP requests**. Training is blocked automatically if capture or Zeek validation fails.

For the existing 96-episode experiment, I also added:

```
./setup/orglab_v3_diagnose.sh staged_v2_main_01
```

This inspects the unresolved timeout without modifying its existing datasets, captures or checkpoints.

### **Important limitations**

The older repository ZIP could not be opened in the execution environment despite attempts to materialise it. Consequently, this deliverable is an **additive implementation**, not a verified replacement for your entire repository.

Docker, Zeek and CUDA execution on your university workstation remain unverified for this new code. The new GraphSAGE–GRU has passed local CPU training and checkpoint-resumption tests, but its university GPU performance and scientific validity remain to be established.

The existing V3 pilot results are preserved. No fake intrusion measurements or GPU training results have been reported.

**Next execution priority:** diagnose and complete `staged_v2_main_01`, then run the 20-node departmental experiment and compare its results against the existing smaller-network baselines.
