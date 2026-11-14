# Adaptive NIDS — additive 20–50 employee network and parallel training patch

**Start here:** [`docs/ORGLAB_20_50_RUNBOOK.md`](docs/ORGLAB_20_50_RUNBOOK.md).

This archive adds an independent ORGLAB testbed and training modules; it intentionally does not overwrite the live university checkout's `AGENTS.md`, `MEMORY.md`, `SKILLS.md`, `INSTRUCTIONS.md`, `src/code/`, staged capture code, previous experiment data, checkpoints or HPO studies. Install via `unzip -n`, not `unzip -o`. Do not run collection while a Stage V3 collector is active.

Validated locally: Python compilation, 6 focused regression tests (including checkpoint/resume), Bash syntax, deterministic Compose generator; Docker Engine, Zeek, GPU and live packet capture **not available in this execution environment**.
