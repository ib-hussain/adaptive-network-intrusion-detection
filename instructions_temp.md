The corrected logs reveal three problems: **OrgLab&#x20;**`tcpdump`**&#x20;lacks the UID/GID capabilities it needs, V3 times out during the 45-second probe command, and an older V2 pilot is suspended.** The 20- and 50-employee containers themselves started successfully.

I tested the OrgLab source correction locally: **6 tests passed**. Follow these commands in order. No new ZIP or Markdown files are needed.

### **1. Check and release the suspended V2 job**

Run in the same terminal where the V2 job was suspended:

```
cd /home/fastlab/deepFakeDetection/adaptive-network-intrusion-detection

source .venv-cuda/bin/activate

export PATH="/opt/zeek/bin:$PATH"
export PYTEST_DISABLE_PLUGIN_AUTOLOAD=1
export PYTHONUNBUFFERED=1

jobs -l

ps -eo pid,ppid,stat,etime,args | grep -E '[u]niversity_pilot_v2|[s]taged_collect|[o]rglab_run|[t]cpdump' || true

docker ps --filter label=phase3.staged.capture=1
```

**Only if job&#x20;**`[1]`**&#x20;is still the stopped&#x20;**`university_pilot_v2.sh`**&#x20;process**, execute:

```
kill -TERM %1
kill -CONT %1 2>/dev/null || true

jobs -l

ps -eo pid,ppid,stat,etime,args | grep -E '[u]niversity_pilot_v2|[s]taged_collect|[o]rglab_run|[t]cpdump' || true
```

Do not continue until the previous capture processes have stopped. Do not delete lock files.

### **2. Apply both fixes with automatic backups**

This changes only the restricted OrgLab capture capabilities, their existing test expectation, generated OrgLab Compose configurations, and the V3 probe timeout. It preserves all existing experiment outputs.

```
cd /home/fastlab/deepFakeDetection/adaptive-network-intrusion-detection

export FIX_BACKUP="outputs/backups/capture_runtime_fix_$(date -u +%Y%m%dT%H%M%SZ)"

python - <<'PY'
import os
import json
import shutil
from pathlib import Path

backup = Path(os.environ["FIX_BACKUP"])
changes = {}

def replace_exact(filename, old, new):
    p = Path(filename)
    s = p.read_text()
    if new in s and old not in s:
        print("ALREADY PATCHED:", p)
        return
    if s.count(old) != 1:
        raise SystemExit(f"STOP: Unexpected content in {p}. No modifications applied.")
    changes[p] = s.replace(old, new)

replace_exact(
    "orglab/composegen.py",
    '"cap_add": ["NET_RAW"],',
    '"cap_add": ["NET_RAW", "SETUID", "SETGID"],'
)

replace_exact(
    "tests/test_orglab.py",
    'assert c["services"]["capture"]["cap_add"] == ["NET_RAW"]',
    'assert c["services"]["capture"]["cap_add"] == ["NET_RAW", "SETUID", "SETGID"]'
)

replace_exact(
    "setup/staged_collect_v3.sh",
    'step timeout 45s "${COMPOSE[@]}" --profile runner run --rm -T --no-deps runner python -c "$PROBE"',
    'step timeout 180s "${COMPOSE[@]}" --profile runner run --rm -T --no-deps runner python -c "$PROBE"'
)

for p in sorted(Path(".").glob("compose.orglab.*.json")):
    obj = json.loads(p.read_text())
    caps = obj["services"]["capture"]["cap_add"]
    if caps == ["NET_RAW"]:
        obj["services"]["capture"]["cap_add"] = ["NET_RAW", "SETUID", "SETGID"]
        changes[p] = json.dumps(obj, indent=2) + "\n"
    elif caps != ["NET_RAW", "SETUID", "SETGID"]:
        raise SystemExit(f"STOP: Unexpected capabilities in {p}. No modifications applied.")

for p, content in changes.items():
    destination = backup / p
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(p, destination)
    p.write_text(content)
    print("PATCHED:", p, "| BACKUP:", destination)

print("PATCH COMPLETE:", len(changes), "files changed")
PY
```

The added `SETUID` and `SETGID` capabilities are confined to the capture container; no host networking privileges or `--privileged` flag are added. Use this configuration only where your university permits those scoped container capabilities.

### **3. Verify the fixes**

```
python -m compileall -q orglab

bash -n setup/staged_collect_v3.sh

bash -n setup/orglab_run.sh

bash -n setup/orglab_train_parallel.sh

PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest -q tests/test_orglab.py tests/test_v3_launcher_contract.py tests/test_staged_capture_audit.py

python - <<'PY'
from orglab.composegen import build_compose

for n in (20, 50):
    for topology in ("flat", "departmental"):
        c = build_compose(n, topology)
        cap = c["services"]["capture"]
        assert cap["cap_add"] == ["NET_RAW", "SETUID", "SETGID"]
        assert cap["cap_drop"] == ["ALL"]
        assert cap["security_opt"] == ["no-new-privileges:true"]
        assert all(v["internal"] for v in c["networks"].values())
        assert all(not s.get("ports") for s in c["services"].values())
        print("VERIFIED", n, topology)

print("SECURITY AND TOPOLOGY CHECKS PASSED")
PY

git diff --check

git status --short
```

**Proceed only if all checks pass.**

### **4. Run a new 20-node pilot with training**

The failed `org20_pilot_01`, `org20_main_01`, `org20_flat_01` and `org50_pilot_01` directories must remain preserved. Use a new run ID.

```
./setup/orglab_run.sh \
  --run-id org20_pilot_02 \
  --nodes 20 \
  --topology departmental \
  --rounds 6 \
  --test-rounds 6 \
  --seed 20261117 \
  --step-seconds 0.6 \
  --train
```

This should first collect and validate the network traffic, then launch the CPU baselines and GPU GraphSAGE–GRU training. **Do not start another capture while this command is running.**

### **5. Inspect the training and capture results**

Run after Step 4 finishes.

```
RUN=org20_pilot_02

cat "outputs/orglab/$RUN/status.json"

cat "outputs/orglab/$RUN/zeek_audit.json"

cat "outputs/orglab/$RUN/training/training_summary.json"

find "outputs/orglab/$RUN/training/logs" -name '*.exitcode' -exec sh -c 'echo "$1: $(cat "$1")"' _ {} \;

find "outputs/orglab/$RUN/training/models" -type f \( -name 'results.json' -o -name 'latest.pt' -o -name 'best.pt' \) -print

nvidia-smi
```

If Step 4 fails, **stop there and send its logs**. Do not attempt manual training on a header-only PCAP.

### **6. Resume the original 96-episode V3 experiment**

Execute only after the 20-node pilot and its training have stopped.

```
./setup/staged_collect_v3.sh \
  --run-id staged_v2_main_01 \
  --rounds 12 \
  --test-rounds 12 \
  --seed 20261115 \
  --capture \
  --resume
```

Then:

```
./setup/staged_v3_status.sh staged_v2_main_01
```

If it reports `COLLECTION_COMPLETE` with valid capture evidence, run:

```
./setup/staged_train_guard_v3.sh staged_v2_main_01 --hpo-trials 30 --gru-epochs 80
```

If it fails again, do not retry blindly. Inspect:

```
RUN=staged_v2_main_01

tail -n 100 "$(ls -t src/data/raw/runs/$RUN/collector_v3_*.log | head -1)"

ls -lh src/data/raw/runs/$RUN/*.pcap

./setup/staged_v3_status.sh "$RUN"

./setup/staged_status.sh
```

**Send me the Step 4 and Step 5 logs first.** Those will establish whether the capture capability correction works on the university machine and whether the multi-node data can pass the training gates.