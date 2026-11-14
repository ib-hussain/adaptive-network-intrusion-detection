Your new logs confirm that **the OrgLab capability fix was applied successfully**. The remaining immediate issues are:

1. An old `university_pilot_v2.sh` process and its `tcpdump` child are still running.
2. One test expects Docker's deprecated `--time` argument instead of the working `--timeout` argument.
3. The new 20-node training run has not yet been launched after the fixes.

Execute these commands **in order on the university machine**. No new ZIPs or Markdown files.

### **Step 1 — Stop only the verified old capture process**

This works from a new terminal. It does not rely on `%1` job control.

```
cd /home/fastlab/deepFakeDetection/adaptive-network-intrusion-detection

source .venv-cuda/bin/activate

export PATH="/opt/zeek/bin:$PATH"
export PYTEST_DISABLE_PLUGIN_AUTOLOAD=1
export PYTHONUNBUFFERED=1

mapfile -t CAP_PIDS < <(
  ps -eo pid=,comm=,args= |
  awk '$2 == "tcpdump" && index($0, "/pilot_20261114T112937Z_251982/traffic.pcap") {print $1}'
)

if (( ${#CAP_PIDS[@]} > 1 )); then
  echo "STOP: Multiple matching captures. Inspect manually."
elif (( ${#CAP_PIDS[@]} == 1 )); then
  echo "Gracefully closing old capture PID ${CAP_PIDS[0]}"
  sudo kill -INT "${CAP_PIDS[0]}"
else
  echo "Old capture already stopped."
fi

sleep 3

if ps -p 251982 -o args= | grep -Fxq 'bash ./setup/university_pilot_v2.sh --episodes 4 --capture'; then
  echo "Releasing suspended V2 launcher"
  kill -TERM 251982
  kill -CONT 251982 2>/dev/null || true
fi

sleep 3

ps -eo pid,ppid,stat,etime,args |
grep -E '[u]niversity_pilot_v2|[s]taged_collect|[o]rglab_run|[t]cpdump' || true

docker ps --filter label=phase3.staged.capture=1
```

**Do not proceed if a capture or collection process is still active.** Preserve the old PCAP and logs.

### **Step 2 — Fix the outdated test without reverting the Docker command**

```
python - <<'PY'
from pathlib import Path
import shutil
from datetime import datetime, timezone

source = Path("setup/staged_collect_v3.sh").read_text()
test = Path("tests/test_v3_launcher_contract.py")
content = test.read_text()

old = "self.assertIn('docker stop --signal SIGINT --time 8', SRC)"
new = "self.assertIn('docker stop --signal SIGINT --timeout 8', SRC)"

assert 'docker stop --signal SIGINT --timeout 8' in source
assert 'step timeout 180s' in source

if old in content:
    backup = Path("outputs/backups") / (
        "v3_test_fix_" +
        datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    )
    backup.mkdir(parents=True, exist_ok=False)
    shutil.copy2(test, backup / test.name)
    test.write_text(content.replace(old, new))
    print("FIXED outdated Docker stop assertion")
elif new in content:
    print("Test already fixed")
else:
    raise SystemExit("STOP: Unexpected test content")

print("V3 timeout and Docker stop checks verified")
PY
```

### **Step 3 — Run all tests**

```
python -m compileall -q orglab src setup

bash -n setup/staged_collect_v3.sh

bash -n setup/orglab_run.sh

bash -n setup/orglab_train_parallel.sh

python -m pytest -q tests/test_orglab.py tests/test_v3_launcher_contract.py tests/test_staged_capture_audit.py

python -m pytest -q

git diff --check
```

Continue only if the tests pass.

### **Step 4 — Launch the new 20-node captured-data pilot and training**

This is a smaller first run to verify the entire capture → Zeek → CPU/GPU training pipeline without committing to a larger collection prematurely.

```
SMOKE="org20_smoke_$(date -u +%m%d%H%M%S)"

echo "RUN ID: $SMOKE"

./setup/orglab_run.sh \
  --run-id "$SMOKE" \
  --nodes 20 \
  --topology departmental \
  --rounds 4 \
  --test-rounds 2 \
  --seed 20261118 \
  --step-seconds 0.2 \
  --train
```

Expected workload: **28 episodes and 672 experimental HTTP requests**.

The `--train` option launches six CPU baseline jobs and three sequential GPU GraphSAGE–GRU models after collection and Zeek validation.

### **Step 5 — Check the trained models**

```
echo "CHECKING RUN: $SMOKE"

cat "outputs/orglab/$SMOKE/status.json"

cat "outputs/orglab/$SMOKE/zeek_audit.json"

cat "outputs/orglab/$SMOKE/training/training_summary.json"

find "outputs/orglab/$SMOKE/training/logs" \
  -name '*.exitcode' -print -exec cat {} \;

find "outputs/orglab/$SMOKE/training/models" \
  -type f \( -name 'results.json' -o -name 'latest.pt' -o -name 'best.pt' -o -name 'inference.pt' \) -print

nvidia-smi
```

### **Step 6 — Start the larger 20-node experiment only if Step 4 passes**

```
MAIN="org20_main_$(date -u +%m%d%H%M%S)"

echo "MAIN RUN ID: $MAIN"

./setup/orglab_run.sh \
  --run-id "$MAIN" \
  --nodes 20 \
  --topology departmental \
  --rounds 12 \
  --test-rounds 12 \
  --seed 20261119 \
  --step-seconds 0.35 \
  --train
```

This targets **96 episodes and 2,304 experimental HTTP requests**, followed by the parallel training workflow.

Do not run Steps 4 and 6 simultaneously.

**If any command fails, stop at that step and send its output.** In particular, I need the capture and training logs from Step 4 before treating the new deployment as verified.
