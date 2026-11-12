# Phase 3 implementation tracker

## Completed in this starter (software, not experiment)

- [x] Versioned repository tree, .gitignore/.gitattributes; no Git LFS.
- [x] Compose declaration for two internal networks, no published ports, separated services / clients.
- [x] Harmless controlled HTTP traffic generator: benign, paced, bursty, fanout; inert milestone.
- [x] Independent timestamped ground-truth episode manifest (not based on IDS alerts).
- [x] Fixed / uniform / bounded strategic scenario selection with explicit bandit-game actions, rewards and no test feedback.
- [x] Application request records and offline Zeek conn.log JSON importer (do not confuse the two formats).
- [x] Episode-isolated windows with temporal and host-communication summary features.
- [x] RF / IsolationForest baselines, optional Optuna TPE tuning and saved study.
- [x] Validation-only warning threshold, pre-impact coverage, T_lead, benign false-alarm metrics.
- [x] Frozen test episodes shared by three collection-policy models; per-episode classification metrics.
- [x] CLI, unit tests, local loopback smoke, results JSON, optional plots.

## REQUIRED before Phase 3 final report

- [ ] Verify Docker Compose run and isolation with on-host routing/interface inspection (not available in packaging runtime).
- [ ] Collect actual network PCAP and validate bidirectional Zeek conn.log against lab gateway records.
- [ ] Build a meaningful independent multi-stage network incident schedule and independent pre-impact precursor labels.
- [ ] Increase ordinary benign traffic diversity (periodic traffic, transfers, legitimate bursts) to challenge false-positive control.
- [ ] Hold out an *entire* scenario family (not just random independent episodes) and verify positive milestones in the test set.
- [ ] Build >=2 genuine topology variations, hold out one; current MVP supports only one logical topology.
- [ ] Add temporal no-graph baseline and graph topology encoder (only if graph has meaningful relational variation).
- [ ] Repeat runs with multiple seeds, matched traffic/time/episode budgets and empirical bootstrap CIs.
- [ ] Evaluate ablations (no strategic policy / no time / no graph / altered windows) and failures.
- [ ] Check model threshold calibration, stable false-alarm rate, prior probability, and operational runtimes.
- [ ] Run appropriately comparable published baseline code/datasets; report incompatibility honestly.
- [ ] Make final Phase 3 figures, results analysis, limitations and experiment logs from genuinely completed runs.

## Known scientific limitation

The current safe HTTP scenarios are **not attacks**. They verify a functioning network data pipeline and adaptive scenario selection under bounded observable behaviour. If the team later uses a verified authorised dataset of true labelled malicious traffic for model evaluation, report it separately from these lab traffic profiles, and never assert the model can identify an actual zero-day from these controls alone.
