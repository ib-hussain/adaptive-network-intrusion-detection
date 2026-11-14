Understood. **From now on, whenever you send logs, I will respond with the exact Bash commands to execute, in order, directly in chat. No Markdown files, no separate runbooks, and no unnecessary explanations.**

Your logs confirm that the 24-episode V3 pilot and its training completed. The main 96-episode run still exits with code `124` after the HTTP probes. We should diagnose that timeout without repeating the failing command, while starting the new 20-container experiment independently.

### **Step 1 — Check the university machine and existing jobs**

```
cd /home/fastlab/deepFakeDetection/adaptive-network-intrusion-detection

source .venv-cuda/bin/activate

export PATH="/opt/zeek/bin:$PATH"
export PYTEST_DISABLE_PLUGIN_AUTOLOAD=1
export PYTHONUNBUFFERED=1

date -u
git status --short --branch
nvidia-smi
docker ps
docker system df
df -h . /var/lib/docker

ps -eo pid,ppid,stat,etime,args | grep -E '[s]taged_collect|[o]rglab_run|[t]cpdump' || true

./setup/staged_v3_status.sh staged_v2_main_01

grep -n -C 8 -E 'timeout|CAPTURE_PROBE|CAPTURE_PREFLIGHT|probe' setup/staged_collect_v3.sh
```

### **Step 2 — Install and test the 20–50-container add-on**

Use the ZIP supplied in my previous response. Place it in `~/Downloads` on the university machine.

```
cd /home/fastlab/deepFakeDetection/adaptive-network-intrusion-detection

unzip -t ~/Downloads/Adaptive_NIDS_OrgLab_Addon.zip

unzip -n ~/Downloads/Adaptive_NIDS_OrgLab_Addon.zip -d .

sha256sum -c MANIFEST.sha256

chmod +x setup/orglab_*.sh

python -m compileall -q orglab

for f in setup/orglab_*.sh; do bash -n "$f" || break; done

python -m pytest -q tests/test_orglab.py

python -m orglab.composegen --nodes 20 --topology departmental --output compose.orglab.20.departmental.json
```

Proceed only if integrity, syntax and tests pass.

### **Step 3 — Diagnose the main-run timeout**

```
./setup/orglab_v3_diagnose.sh staged_v2_main_01

./setup/staged_v3_status.sh staged_v2_main_01

find outputs/logs/setup -maxdepth 2 -type f -name 'audit.log' | sort | tail -5
```

Do not restart `staged_v2_main_01` yet. The repeated exit `124` needs to be traced to its exact timeout command.

### **Step 4 — Start the isolated 20-employee network and training**

Only execute this after Step 2 passes and Step 1 confirms no existing capture is running.

```
./setup/orglab_run.sh --run-id org20_pilot_01 --nodes 20 --topology departmental --rounds 6 --test-rounds 6 --seed 20261114 --step-seconds 0.6 --train
```

This command is intended to collect 48 episodes, validate the packet capture and Zeek observations, then launch six CPU training jobs and three sequential GPU model runs. Training will not start if capture validation fails.

### **Step 5 — Check the results**

After the command finishes:

```
cat outputs/orglab/org20_pilot_01/status.json

cat outputs/orglab/org20_pilot_01/zeek_audit.json

cat outputs/orglab/org20_pilot_01/training/training_summary.json

find outputs/orglab/org20_pilot_01/training/logs -name '*.exitcode' -print -exec cat {} \;

nvidia-smi
```

### **Step 6 — Scale up only after the pilot passes**

If Step 5 confirms valid capture, full episode coverage and successful training, run:

```
./setup/orglab_run.sh --run-id org20_main_01 --nodes 20 --topology departmental --rounds 12 --test-rounds 12 --seed 20261115 --step-seconds 0.8 --train
```

This targets 96 episodes and 2,304 HTTP requests across the 20-employee topology.

**Send me the terminal logs from these steps, particularly the first failure if one occurs.** I will use them to give you the next exact commands, including any necessary fix, without creating additional documentation files.
    