# Starter validation report — 2026-11-12

## Verified in the packaging environment

- Python 3.13.5; pytest and the required numerical/ML libraries available.
- `python -m compileall -q src lab setup`: PASS.
- `python -m pytest -q tests`: **13 passed**.
- Local loopback integration run with 4 iterations per collection policy and matching benign/incident episodes: **32 experimental episodes** and **384 actual HTTP gateway observations**.
- Causal feature pipeline processed the locally observed events, trained both baseline model classes, selected thresholds using validation episodes, emitted separate shared-test predictions and metrics. These numbers validate the code path, **not** real-world cyber detection.
- Generated figures were checked against actual pipeline JSON (for software smoke only).
- Output validation confirmed mutually exclusive episode partitions and finite metrics.
- Resumable Optuna TPE study creation was smoke-tested with two trials per generation policy; this does not establish tuned research-quality parameters.

## Not verified

- Docker Compose daemon and container-level network isolation: Docker not installed in packaging runtime.
- Zeek packet captures and bidirectional flow visibility: Zeek/tcpdump not installed in packaging runtime.
- CUDA acceleration: `torch.cuda.is_available()` reported False in packaging runtime.
- Public-paper model reproduction, full HPO budget, true attack classification, topology holdout, unseen scenario family holdout and publishable estimates: **not completed**.

## Required user-side next execution

On a real Docker-enabled Linux/WSL host, run `./setup/preflight.sh`, verify `docker compose config`, start the isolated lab, record packet captures, validate Zeek schema and run a pilot. Preserve all raw results before any destructive changes.
