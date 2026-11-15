# Adaptive Network Intrusion Detection and Early Warning — Phase 3 starter

**Status: IMPLEMENTATION FOUNDATION, NOT A COMPLETED PHASE 3 STUDY.** This package creates a small bounded network observation lab and the first testable model-comparison pipeline, grounded in the replacement Phase 2 methodology. The original AIOps repository is NOT modified.

## Research question

Can bounded game-theoretic scenario selection improve the detection and **pre-milestone early warning** of previously unseen multi-stage network communication behaviours relative to fixed and random selection, under equal budgets and independent test episodes?

**Mandatory:** detection + early warning. **Later:** genuinely independent topology holdouts, stronger graph-temporal model, full Zeek PCAP sensor validation, properly powered experiments, ablations and uncertainty.

The adapted development rules are in [`AGENTS.md`](AGENTS.md) and [`SKILLS.md`](SKILLS.md).

## Project organisation

```
compose.yaml                         Two internal networks; gateway bridging clients / services
lab/http_service.py                 Actual HTTP services, gateway observation log
lab/generate.py                     Seeded, bounded scenario episodes + ground truth
src/code/game.py                    Transparent two-player bounded EXP3 game
src/code/ingest.py                  Validated gateway or Zeek conn.log JSON ingestion
src/code/features.py                Causal window features (no episode/scenario IDs)
src/code/early_warning.py           Lead time, coverage, false alarm outcomes
src/code/models.py                  Random Forest, Isolation Forest, optional Optuna
src/code/pipeline.py                Episode-disjoint train/val + frozen shared test
src/code/figures.py                 Plot empirical results after valid input
src/data/raw/                       Captures and manifests (local, ignored by Git)
src/data/processed/                 Derived datasets (local, ignored by Git)
baselineReproduction/               Baseline reproduction modules (later)
outputs/                            Results/models/HPO (local, ignored by Git)
researchPapers/                     Phase 1/2 reviews and references when copied in
setup/                               Commands for local smoke/Zeek processing
configs/                             Versioned proposed experiment defaults
tests/                               Pure-unit validation and leakage checks
```

## 1. Prepare your WSL or Linux host (Bash)

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
./setup/preflight.sh
```

**This environment:** Docker and Zeek were not installed and therefore their runtime cannot be claimed to have passed. Local tests and loopback smoke verify code paths but do NOT validate container isolation or packet capture.

## 2. Non-isolated LOOPBACK SMOKE (software verification ONLY)

```bash
python -m setup.run_local_smoke --episodes 4
```

This runs real HTTP requests between services bound to 127.0.0.1, captures application-level timings and produces a result JSON. It is NOT an isolated experiment and its scores must not be submitted as research findings. The smoke uses controlled non-malicious traffic: `incident` is simply an experimental label for unusual scenario activity and an inert test milestone.

## 3. Isolated Docker Compose lab

With Docker Compose available and its image dependencies provisioned:

```bash
docker compose -f compose.yaml config --quiet
docker compose -f compose.yaml up -d server_a server_b gateway
docker compose -f compose.yaml --profile runner run --rm runner
```

The Compose project defines `clients` and `services` with `internal: true`; only the gateway spans both. It has no published host ports, no privileged containers and no external traffic generator. Verify actual isolation on YOUR machine before recording experiments. No exploit or malware code is provided.

A run refuses to overwrite an existing `src/data/raw/episodes.jsonl`. For additional independent runs, move the raw directory to a new timestamped experiment location and empty only *after* preserving the original and its SHA-256 hashes.

## 4. Build feature windows, train baselines, assess early warnings

```bash
python -m src.code.pipeline --manifest src/data/raw/episodes.jsonl --events src/data/raw/gateway_requests.jsonl --output outputs/results/first_real_lab_run --source gateway --trials 0
python -m src.code.figures --results outputs/results/first_real_lab_run/results.json --output outputs/figs/first_real_lab_run
```

For actual supervised research, rerun with an unused output directory and `--trials 10` (or more) for persistent Optuna TPE HPO. All test episodes belong to `policy=test`. Neither detector tuning nor the repeated game sees their outcomes during development. The shared test is reused unchanged for all three training policies. Thresholds are selected on validation episodes subject to the allowed false-alarm episode rate; `threshold_unavailable_under_constraint` is a legitimate failure, not a suppressed result.

### Alternate Zeek input

After recording an authorised lab PCAP by a correctly configured sensor, convert it to JSON connection logs using:

```bash
./setup/zeek_from_pcap.sh path/to/capture.pcap outputs/logs/zeek_run_01
python -m src.code.pipeline --manifest src/data/raw/episodes.jsonl --events outputs/logs/zeek_run_01/conn.log --source zeek --output outputs/results/zeek_01
```

**Caution:** A Zeek connection record may describe different traffic than an application-gateway request. Zeek episode assignment uses timestamp intervals, assumes sequential non-overlapping episodes, and must be separately verified against packet captures, interface visibility and flow timeouts. Do NOT mix gateway and Zeek records into one evaluation silently.

## 5. Definitions that protect research validity

- `onset_ts`: start of a controlled incident-like communication scenario, not proof of actual compromise.
- `milestone_ts`: time immediately before the final harmless dummy-data transfer in the experiment.
- `T_lead = milestone_ts - first_valid_alert_ts`, counted only if alert is **before** milestone.
- False alarms are evaluated independently on benign episodes.
- Incidents with no valid early warning count as zero in coverage-adjusted lead-time.
- A higher conditional mean lead time alone cannot establish improvement: always report warning coverage and false positives.
- All feature windows are causal and episode-contained; scenario labels and policy IDs are NEVER model features.
- An `incident` episode does **not** mean a real attack/zero-day exploit was executed. Avoid security performance claims from harmless traffic profiles.

## 6. Validate output structure

```bash
python -m tools.validate_outputs --results-directory outputs/results/first_real_lab_run
```

This checks invariants, not scientific validity.

## 7. What remains for research-grade Phase 3

See [docs/IMPLEMENTATION_PLAN.md](docs/IMPLEMENTATION_PLAN.md) and [docs/VALIDITY.md](docs/VALIDITY.md). Next step is to validate network capture (PCAP -> Zeek), capture richer truly independent multi-stage sequences, use unseen protocol/workload/topology conditions, build meaningful temporal host graph sequences, implement graph/temporal baseline and all ablations, and compare to published research only on comparable datasets and protocols.
