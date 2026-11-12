# SKILLS.md — Practical Phase 3 workflow

## Skill 1: Environment

`./setup/preflight.sh` reports Python, available packages, Torch/CUDA, Docker and Zeek, compiles modules and runs unit tests. Treat skipped Docker/Zeek checks as **unverified**, not passed.

## Skill 2: Safe network testbed

Use `compose.yaml` with two internal networks, no host ports and bounded non-destructive HTTP scenarios. Manually verify container/host routing before collecting official data. `lab.generate` preserves the first experiment and refuses to overwrite its manifest.

## Skill 3: Independent telemetry and labels

The scenario controller creates JSONL episode metadata: `episode_id`, `start_ts`, `onset_ts`, `milestone_ts`, `end_ts`, `condition`, `policy`, `profile`, `topology`, `seed`. Gateway request records are application observations. To obtain actual packet evidence, capture a verified PCAP and use `./setup/zeek_from_pcap.sh` to create `conn.log` JSON. Validate sensor visibility and flow-vs-request semantic differences.

## Skill 4: Causal features and safe partitioning

`src.code.ingest` validates input schema, overlap and numeric finiteness. `src.code.features` creates window features from past-observed records in the same episode. The pipeline holds out `policy=test` from every training/tuning and policy feedback update. Do not insert a scenario ID, policy, profile or milestone timestamp into model inputs.

## Skill 5: Explicit game

The attacker chooses among `paced`, `bursty`, and `fanout`; defender references `rate` and `spread`. A bounded EXP3 two-player game updates from *previous* episode outcomes only. This is an experimental mixed-strategy baseline, **not** an equilibrium proof or a real offensive agent. Record reward/decisions for auditing.

## Skill 6: Detection and early warning

Use `python -m src.code.pipeline` to train RF and Isolation Forest per generation policy against the same frozen test episodes. Pick threshold on independent validation. Report episode-level precision/recall/F1/AP, alert coverage, conditional and coverage-adjusted lead-time, and false alarms. Misses contribute zero to coverage-adjusted lead-time. Do not optimise just conditional lead-time.

## Skill 7: Training state

Full training uses optional Optuna persistent SQLite HPO: `--trials 10`. Save model with feature schema metadata. No repeated expensive training on a broken schema. Preserve output directories; use unique directories for separate runs.

## Skill 8: Graph evidence

A true graph-temporal model should use stable host/time graph definitions, multiple meaningful network configurations, causality-respecting edges and held-out topology evaluation. `unique_links` alone does not make a model a GNN. Implement graph model only after independent Zeek capture and testable graph semantics exist.

## Skill 9: Validity

Use `python -m tools.validate_outputs --results-directory <dir>` to check invariant structure. Then independently audit PCAP/Zeek and the label timeline. Run ablations, multiple seeds and episode-level bootstrap intervals before writing Phase 3 results. Keep negative and failed outcomes, never conceal them.
