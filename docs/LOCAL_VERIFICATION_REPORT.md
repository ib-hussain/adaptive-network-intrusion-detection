# Local verification report — 14 November 2026

## Source scope

Read all uploaded `INSTRUCTIONS.md`, `AGENTS.md`, `SKILLS.md`, `MEMORY.md`, and `Pasted text(5).txt`, plus the Phase 1/Phase 2 research documents and the user's pasted repository tree. The `entire_repository.zip` attachment was recorded by the file service but its materialised bytes **were not visible** to the executable Python/container runtime; therefore the original repository source files **could not be exhaustively audited or directly modified**. This add-on uses new paths only. Latest university source and runtime remain authoritative. Do not copy the old ZIP over the university source tree.

## Captured historical evidence, not independently re-executed here

The later university log reports a successful 24-episode `staged_v3_check_02` with 480 HTTP events, 13,550 PCAP packet records, 960 Zeek connections, 90 Optuna trials, and three 80-epoch CUDA GRU runs. It also reports 96-episode `staged_v2_main_01` still failing exit 124 after successful four-request capture probes. These are the university user's supplied reports, **not** new measurements made in this sandbox. The earlier `-Z root` tcpdump fix is reported as applied on the university workstation. Never reuse the old 24-byte PCAPs as valid training data.

## New code checks executed locally

- `python -m compileall -q orglab` — **PASS**.
- `bash -n setup/orglab_run.sh setup/orglab_train_parallel.sh setup/orglab_v3_diagnose.sh` — **PASS** (each verified separately).
- `PYTHONPATH=. PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 OMP_NUM_THREADS=2 python -m pytest -q tests/test_orglab.py` — **6 passed**. The suite runs actual Random Forest fitting, actual GraphSAGE–GRU forward/training on CPU *unit-test fixtures*, and a checkpoint restore from epoch 1 followed by epoch 2.
- `python -m orglab.composegen --nodes 20 --topology departmental ...` — **PASS**: 26 Compose services, five `internal: true` networks.
- `python -m orglab.composegen --nodes 50 --topology departmental ...` — **PASS**: 56 Compose services, five `internal: true` networks.
- Generated Compose JSON parses successfully in Python. No service has a published host port; all employee images are shared `python:3.12-slim` with CPU/memory/process limits.

## NOT executed / NOT verified

- Actual Docker Compose `config` and `up` — Docker daemon/CLI unavailable in this sandbox.
- A new 20- or 50-container network run — **not started** on the university machine.
- New capture sidecar packet capture, real Zeek processing, and cross-sensor alignment — **not run**.
- GPU CUDA run of new graph model — **not run**; only local CPU test.
- Main staged run capture fix/timeout resolution — live university code not available.
- Detection of genuine attacks, external zero-day exploits, cross-topology transfer and statistical significance — **not established**.

The new controller generates real HTTP traffic only after Docker deployment. Its profile names indicate controlled harmless anomalous behaviours rather than actual attacks. The game selector is heuristic EXP3, not detector-feedback adversarial training. Apply the runbook's capture/Zeek gates and independent held-out evaluation before using any future output as research findings.
