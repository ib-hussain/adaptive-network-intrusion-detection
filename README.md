# Adaptive Network Intrusion Detection and Early Warning — Phase 3

**Status: COMPLETED Phase 3 study (exploratory, two collection seeds).** A real,
sensor-validated CPU experiment was collected and evaluated on this machine.
The canonical write-up is
[`outputs/reports/cpu_v3_main_v2_20261115T164430Z/PHASE3_REPORT.md`](outputs/reports/cpu_v3_main_v2_20261115T164430Z/PHASE3_REPORT.md),
with a submission-ready copy under
[`deliverables/phase3_submission/`](deliverables/phase3_submission/).

| Item | Value |
|---|---|
| Primary run | `cpu_v3_main_v2_20261115T164430Z` (seed `20261115`) |
| Replication run | `cpu_v3_main_v2_seed2_20261115T165949Z` (seed `20261116`) |
| Evidence tag | `SENSOR_VALIDATED` for both (strict 7-check gate) |
| Scale | 192 episodes, 3,840 HTTP requests, 13.4 MB PCAP (107,628 packets), 7,688 Zeek connections |
| Report number check | 102 quoted values re-read from stored artefacts, 0 mismatches |
| Tests | 53 passed |

The result is **deliberately bounded**: it is an isolated synthetic lab with
harmless traffic profiles. It makes no malware, zero-day, enterprise or
production-NIDS claim, and the two-seed comparison does **not** establish a
stable ranking of the collection policies. Read
[`docs/VALIDITY.md`](docs/VALIDITY.md) and §9 of the report before citing any
number.

## What this project answers

Can bounded game-theoretic (EXP3-style) scenario selection improve the
detection and **pre-milestone early warning** of previously unseen multi-stage
network communication behaviours relative to fixed and random selection, under
equal budgets and independent test episodes?

**Mandatory:** detection + early warning. **Implemented:** a bounded scenario
controller, fixed/random/strategic policies, isolated clients/gateway/services,
an independent ground-truth journal, a restricted PCAP capture re-read by Zeek,
an application-gateway sensor, causal episode-safe features, rule / Isolation
Forest / Random Forest baselines, a compact CPU GRU, a frozen common test set,
early-warning metrics with episode-bootstrap intervals, and five real
ablations. **Not implemented (explicit limitations):** a graph neural network,
topology generalisation and future-stage prediction — see §9 of the report.

The adapted development rules are in [`AGENTS.md`](AGENTS.md) and
[`SKILLS.md`](SKILLS.md).

## Two ways to use this repository

### A. Review the existing evidence (no collection needed)

Everything needed to read and check the results is committed, or supplied in
the submission evidence bundle:

```bash
# 1. the canonical report
less outputs/reports/cpu_v3_main_v2_20261115T164430Z/PHASE3_REPORT.md

# 2. the claim -> artefact map and the seed comparison
column -s, -t < outputs/reports/cpu_v3_main_v2_20261115T164430Z/claim_artifact_table.csv
column -s, -t < outputs/reports/cpu_v3_main_v2_20261115T164430Z/seed_comparison.csv

# 3. re-verify every quoted number against the stored artefacts
. .venv/bin/activate
python -m setup.verify_report_numbers \
  --zeek-study outputs/studies/cpu_v3_main_v2_20261115T164430Z_zeek_20261115T165446Z \
  --gateway-study outputs/studies/cpu_v3_main_v2_20261115T164430Z_gateway_20261115T165446Z \
  --gru-csv outputs/reports/cpu_v3_main_v2_20261115T164430Z/gru_metrics.csv \
  --audit outputs/audits/cpu_v3_main_v2_20261115T164430Z/sensor_audit.json \
  --inventory outputs/reports/cpu_v3_main_v2_20261115T164430Z/run_inventory.json \
  --seed2-study outputs/studies/cpu_v3_main_v2_seed2_20261115T165949Z_zeek_20261115T170436Z \
  --seed2-gru-csv outputs/reports/cpu_v3_main_v2_seed2_20261115T165949Z/gru_metrics.csv
# -> {"checks_performed": 102, "mismatches": [], "status": "PASS"}
```

### B. Reproduce from scratch (collects new traffic)

This needs Docker (Compose) and Zeek. It creates a **new** run ID; existing
runs are never overwritten. Raw PCAPs and run directories are intentionally
Git-ignored, so a fresh reproduction regenerates them rather than fetching them.

```bash
python3 -m venv .venv && . .venv/bin/activate
python -m pip install -r requirements.txt
./setup/preflight.sh

export PATH="/opt/zeek/bin:$PATH" PYTHONUNBUFFERED=1 PYTHONHASHSEED=20261115 CUDA_VISIBLE_DEVICES=""
export OMP_NUM_THREADS=2 MKL_NUM_THREADS=2 OPENBLAS_NUM_THREADS=2 NUMEXPR_NUM_THREADS=2

RUN="cpu_v3_main_v2_$(date -u +%Y%m%dT%H%M%SZ)"
./setup/staged_collect_v3.sh --run-id "$RUN" --rounds 24 --test-rounds 24 --seed 20261115 --capture \
  2>&1 | tee "outputs/logs/collection_${RUN}.log"
python -m setup.staged_sensor_gate --run "$RUN" \
  --output "outputs/audits/$RUN/sensor_audit.json" --require-validated
python -m src.code.study --run "$RUN" --source zeek \
  --zeek-conn "outputs/audits/$RUN/zeek/repaired_strict_000/conn.log" \
  --output "outputs/studies/${RUN}_zeek" --seed 20261115 --evidence-tag SENSOR_VALIDATED
```

The full sequence, including the gateway study, GRU, figures and packaging, is
in §10.2 of the report and in [`docs/RUNBOOK.md`](docs/RUNBOOK.md). The
reproducibility bundle for the submitted results is built with
`python -m setup.package_phase3_submission`; it fails closed if any raw
artefact is missing.

## Project organisation

```
compose.yaml                         Two internal networks; gateway bridging clients / services
lab/staged_generate.py              Scenario controller: policies, profiles, independent journal
lab/http_service.py                 Actual HTTP services, gateway observation log
src/code/game.py                    Transparent two-player bounded EXP3 game
src/code/ingest.py                  Validated gateway or Zeek conn.log JSON ingestion
src/code/features.py                Causal window features (no episode/scenario IDs)
src/code/early_warning.py           Lead time, coverage, strict first-alert, false alarms
src/code/models.py                  Rule/rate baseline, Isolation Forest, Random Forest
src/code/study.py                   Leakage-safe preprocessing, splits, baselines, ablations
src/code/temporal_gru_sprint.py     Compact CPU GRU (temporal, NOT a graph model)
src/code/report_figures.py          Figures generated from saved metrics
setup/                              Collection, sensor gate, checksum repair, audits, packaging
outputs/reports/<run>/              Report, figures + source data, claim map, inventories
outputs/studies/<run>_*/            Derived dataset, metrics, ablations, results
outputs/audits/<run>/               sensor_audit.json plus strict/repaired Zeek logs
src/data/raw/runs/<run_id>/         Raw journals, gateway log, PCAPs (Git-ignored)
deliverables/phase3_submission/     Final Markdown report, figures, verification log
docs/                               Runbooks, validity notes and sensor-validation guide
tests/                               Focused regression tests
```

## Definitions that protect research validity

- `onset_ts`: start of a controlled incident-like communication scenario, not proof of actual compromise.
- `milestone_ts`: time immediately before the final harmless dummy-data transfer in the experiment.
- `T_lead = milestone_ts - first_valid_alert_ts`, counted only if the alert is **on or after onset and before** the milestone.
- A pre-onset alert is not a valid early warning; a post-milestone alert is a late detection; no alert is a miss.
- False alarms are evaluated independently on benign episodes.
- Incidents with no valid early warning count as zero in coverage-adjusted lead time.
- All feature windows are causal and episode-contained; scenario labels and policy IDs are NEVER model features.
- An `incident` episode does **not** mean a real attack or zero-day exploit was executed.

## Validate output structure

```bash
python -m tools.validate_outputs --results-directory outputs/results/<run>
```

This checks invariants, not scientific validity.

## Further reading

- [`docs/VALIDITY.md`](docs/VALIDITY.md) — what the evidence does and does not support.
- [`docs/SENSOR_VALIDATION.md`](docs/SENSOR_VALIDATION.md) — the strict gate and checksum-repair rationale.
- [`docs/RUNBOOK.md`](docs/RUNBOOK.md) — operational sequence.
- [`MEMORY.md`](MEMORY.md) — verified project history and evidence log.
