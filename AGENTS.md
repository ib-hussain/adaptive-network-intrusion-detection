# AGENTS.md — Adaptive Network Intrusion Detection and Early Warning

This file adapts the reusable engineering constraints from the former AIOps repository. The retired AIOps architecture, old paper-reproduction modules, financial-app UI guidance and prior model artifacts DO NOT define the new project.

## Research identity

- Domain: Computer Networks, network telemetry, game-theoretic scenario selection, detection and pre-milestone early warning.
- Required: independently observed network behaviour, valid event timeline, detection, early-warning coverage and lead time subject to false alarms.
- Optional only after core experiment is established: response, future-stage prediction, temporal GNN.
- Prohibited project scope: real self-propagating malware, autonomous exploitation/zero-day discovery, uncontrolled attacks, Kubernetes and production SIEM.

## Engineering rules

1. **Inspect before edits:** resolve the active repository, inspect git status (including ignored files), runtime, data and consumers. Do not overwrite any existing project.
2. **Treat datasets and predictions as evidence:** no fabricated experimental data or validation claims. Controlled lab traces are genuine observed traffic but not automatically representative of attacks.
3. **Maintain independent ground truth:** never assign attack labels from model/Suricata alerts. Scenario IDs/policies/milestones are prohibited as model features.
4. **Never look ahead:** feature timestamps must be at or before prediction timestamps. An early warning occurs only before an independent predefined milestone.
5. **Split by episode before windowing:** no session, scenario run or derived window may appear in both training and final test. Hold out complete scenario families and topologies for final research claims.
6. **Use comparable budgets:** match number of scenarios, duration, source network/load and model-selection budgets when comparing fixed/random/strategic approaches. Disclose mismatches.
7. **Compile, test, smoke, HPO, train, validate, export, document.** Prefer Optuna TPE SQLite studies and explicit resumption. Avoid starting expensive work before a valid real-data smoke.
8. **Preserve state:** protect local raw/processed data, PCAPs, checkpoints, Optuna DBs, model exports, `.env`, credentials and reproducibility logs. No Git LFS. Do not commit large model/data files.
9. **CPU/CUDA:** inspect hardware; prefer CUDA for supported deep models, retain reasonable CPU paths. Never assume old hardware specifications.
10. **Commands:** prefer copyable one-line Bash; use Python module CLIs. For any fix include precise filename, content and execution/verification commands.
11. **Transparency:** distinguish code compilation, unit tests, loopback software smoke, isolated lab tests and research-grade held-out results. Do not claim success prematurely.
12. **Security:** keep services private, no published ports, validate routing and interface captures before running test scenarios. Container isolation is not a VM security boundary.

## Standard loop

Inspect repo -> inspect runtime -> inspect real data -> trace dependencies -> minimal change -> compile -> tests -> real traffic smoke -> verify valid splits -> HPO -> train/export -> held-out evaluation -> bootstrap/ablation -> inspect git diff -> document -> commit small understood changes.
