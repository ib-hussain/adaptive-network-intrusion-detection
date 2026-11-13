# University Ubuntu 24.04 deployment — Phase 3 pilot

## Scope
This kit is an **add-on**, not a replacement for the starter project. It preserves every existing file. It creates one new run directory per pilot and a validated run-specific extraction from the gateway's append-only log. It does **not** provide mid-run resume, game-state checkpoints, GPU graph model training or automatic PCAP capture without root permission.

## Install add-on
Copy `Phase3_University_Deployment_Kit.zip` to the Ubuntu machine, extract into the repository root using `unzip -n` (never overwrite pre-existing files):

```bash
cd ~/adaptive-network-intrusion-detection
unzip -n ~/Downloads/Phase3_University_Deployment_Kit.zip -d .
chmod +x setup/university_{check,pilot,backup}.sh
```

If cloning a Git repository, use your *actual* remote URL; this starter does not presume a remote exists. Check `git status` before and after adding new files. Files in `src/data/` and `outputs/` remain local and excluded from Git.

## Prepare Linux environment (one time)
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
./setup/university_check.sh
./setup/preflight.sh
```

Docker daemon + Compose, Zeek and tcpdump are prerequisites for **PCAP** pilot capture; the readiness check reports whether they are available. Contact the university lab administrator if packages or capture privileges are missing. Do not modify university firewall/host configuration without permission. `nvidia-smi` and the installed CUDA-enabled PyTorch wheel must be checked independently; the starter's scikit-learn baselines use the CPU.

## Run one real container/packet-sensor pilot
```bash
sudo -v
./setup/university_pilot.sh --episodes 4 --capture
```

This validates Compose internal bridges, captures on the *services* bridge only, runs 32 independent benign/incident-like harmless episodes and 384 HTTP requests, extracts the matching gateway events to a unique run directory, runs non-HPO CPU baselines, evaluates early-warning *proxy* metrics, and optionally converts captured PCAP to Zeek `conn.log`. It does not establish actual malware/zero-day detection. Check `outputs/logs/zeek/RUN_ID/conn.log` and alignment before interpreting those data.

If root access or sensors are unavailable, this is **only a software pilot**:
```bash
./setup/university_pilot.sh --episodes 4 --no-capture
```

Every invocation creates an independent timestamped run ID. You can specify `--run-id custom_01` once; an existing ID cannot be reused. Increase to `--episodes 12` for a modest first dataset **after** verifying capture.

## Inspect and end the day
```bash
docker compose ps
find src/data/raw/runs -maxdepth 2 -type f | tail -30
du -sh src/data outputs
df -h .
./setup/university_backup.sh /path/to/RELIABLY_PERSISTENT_EXTERNAL_STORAGE
```

When no experiment is running, `docker compose stop` may be used to stop services; all raw events and output files are bind-mounted on the host. Do **not** run `docker system prune -a`, `docker compose down -v`, `rm -rf src/data outputs`, or use Git clean on ignored data. Use a user-writable external disk or permitted persistent server storage for backups; a second folder on the same physical disk is not independent protection.

## Resume/interrupt matrix
| Stage | Current status | What to do if interrupted |
|---|---|---|
| Git source/venv | Persistent on non-ephemeral disk | Reopen environment; check `git status` |
| Compose services | Restartable (not a resume of active requests) | `docker compose up -d server_a server_b gateway` |
| HTTP gateway logs | Append-only bind mount; partial records possible | Preserve old log; never truncate |
| Episode generator + EXP3 state | **NOT resume-safe** | Preserve partial run, start a NEW run ID, do not reassign it as complete |
| Packet capture | Partial PCAP may remain; must validate | Preserve original PCAP, new capture in new run |
| Baseline RF/IsolationForest | Models saved only after fit, no mid-fit checkpoint | Start a NEW output directory and retrain |
| Optuna | SQLite studies persist, but pipeline refuses nonempty output directory | Do not rely on end-to-end resume; schedule small HPO or implement resume-aware pipeline first |
| Future GPU training | Not implemented yet | Require epoch+optimizer+scheduler+RNG checkpoints before long training |
| `tmux` | Survives terminal disconnect, **not power-off** | Useful only for SSH/network interruptions |

### Why this is a pilot, not a final research experiment
The controller currently simulates benign and unusual HTTP traffic, not real intrusions. Only one network topology exists, and there are no held-out unseen behaviour families or operational attack-stage labels. A separate graph/temporal model, true positive early-warning ground truth and verified capture alignment are still required for Phase 3 evaluation.

## Approximate peak disk allocation
The source repository is under 1 MB. A reasonable fresh Ubuntu planning range is 2–5 GB for Python, Docker images, package caches and a small sensor pilot (subject to what's already installed). Installing a GPU PyTorch stack can add several GB. A broader experimental collection including retained PCAPs, public datasets, converted logs, HPO artefacts and models could need 20–60+ GB depending on duration, traffic volume and public data. This project currently sets **no** hard PCAP quotas. Reserve **at least 100 GB free** for the planned larger study; 150 GB is preferable if large public PCAP datasets are imported. These are estimates, not measurements. Verify `df -h .`, Docker's root filesystem, `du -sh` and `docker system df` daily. Add capture rotation/quotas before running for hours.
