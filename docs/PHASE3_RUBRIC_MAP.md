# Mapping to the official Phase 3 instructions

| Phase 3 requirement | Starter implementation | Missing before final submission |
|---|---|---|
| Proposed methodology | `lab/generate.py`, `src/code/game.py`, `src/code/early_warning.py` | Validate true network attack analogue; meaningful adversarial game and full early-warning episode design |
| Dataset, preprocessing, experimental splits | `src/code/ingest.py`, `src/code/features.py`, `src/code/pipeline.py` | Real independent network telemetry/PCAP; dataset inventory and held-out scenario/topology validation |
| Baseline evaluation | Random Forest, Isolation Forest and reference detection rules | Full tuning, graph/temporal baselines, calibrated thresholds, repeated results |
| Graphical results | `src/code/figures.py` | Run on verified research data; stage-timeline figures, uncertainty figures, topology graphs |
| Comparison with existing research | Source PDFs available in user's Phase 1/2 documents | Reproduce benchmark(s) under comparable settings, no claims based on incompatible metrics |
| Ablations | Fixed/random/strategic control supported in architecture | Train equal-budget repeated policies; no temporal / no graph / policy ablation with independent repetitions |
| Results discussion | JSON results plus code assertions | Real empirical analysis, uncertainty intervals, errors and limits; final report |

This package is an **MVP starting point**, not a Phase 3 deliverable ready for submission.
