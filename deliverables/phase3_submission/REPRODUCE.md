# Reproduction guide (submission pack)

Canonical source: `outputs/reports/cpu_v3_main_v2_20261115T164430Z/PHASE3_REPORT.md` in the repository.
This directory is a copy; the repository copy is authoritative.

* `PHASE3_REPORT.md` / `.html` — the final report (10 sections).
* `figures/` — PNG figures and their `.data.json` source data.
* `claim_artifact_table.csv` — every reported value mapped to its artefact.
* `seed_comparison.csv` — seed 1 versus seed 2.
* `report_number_verification.json` — machine check of the report's numbers.
* `final_verification/` — the verification run (compileall, shell syntax, tests).
* `literature_comparison.csv`, `runtime_resources.csv`, `run_inventory.json`.

To re-verify the numbers against the stored artefacts:

```bash
python -m setup.verify_report_numbers \
  --zeek-study outputs/studies/cpu_v3_main_v2_20261115T164430Z_zeek_20261115T165446Z \
  --gateway-study outputs/studies/cpu_v3_main_v2_20261115T164430Z_gateway_20261115T165446Z \
  --gru-csv outputs/reports/cpu_v3_main_v2_20261115T164430Z/gru_metrics.csv \
  --audit outputs/audits/cpu_v3_main_v2_20261115T164430Z/sensor_audit.json \
  --inventory outputs/reports/cpu_v3_main_v2_20261115T164430Z/run_inventory.json \
  --seed2-study outputs/studies/cpu_v3_main_v2_seed2_20261115T165949Z_zeek_20261115T170436Z \
  --seed2-gru-csv outputs/reports/cpu_v3_main_v2_seed2_20261115T165949Z/gru_metrics.csv
```

Raw PCAPs and run directories are Git-ignored by design and travel in the
submission evidence bundle built by `setup/package_phase3_submission.py`.
