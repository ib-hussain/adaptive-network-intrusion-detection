You are the primary implementation agent for this repository. Work quickly, decisively, and continuously toward completing the Phase 3 Network Intrusion Detection project on this CPU-only Ubuntu machine.

Read these files first, in this order, and treat them as the project contract:

1. AGENTS.md
2. MEMORY.md
3. SKILLS.md
4. INSTRUCTIONS.md

(These files may be a little outdated)
Then immediately begin execution. Do not stop after analysis, planning, or a status report.

Your operating rules:

- Work in large, useful batches. Complete as many safe, connected tasks as possible per turn rather than doing one tiny task and waiting.
- Prioritise the fastest route to a real, reproducible Phase 3 submission: environment verification, dependency setup, focused tests, capture validation, data collection, preprocessing, baselines, metrics, figures, ablations, and report-ready evidence.
- Begin with the required machine/repository inventory and save it as an artifact. Then continue automatically to the next safe task.
- Use parallel work for independent, non-conflicting tasks. Never run duplicate captures, concurrent collectors, or jobs sharing an output directory/database.
- Preserve all old runs, PCAPs, logs, checkpoints, and failed outputs. Never use destructive cleanup, Docker prune, broad process kills, hard resets, or overwrite existing run IDs.
- Make limited, tested code changes when required. Before changing a source file, create the required dated backup and never delete any file.
- Implement and enforce the strict sensor-validation gate before presenting Zeek-derived results as final network evidence.
- If Zeek validation cannot pass, continue with the gateway-only pipeline but label every such result `GATEWAY_DIAGNOSTIC`.
- Do not claim real malware detection, zero-day discovery, topology generalisation, a GNN, or future-stage prediction unless the implementation and evidence genuinely support it.
- Keep visible progress: UTC timestamps, commands, run IDs, logs, output paths, counts, status files, exit codes, and clear recovery commands.
- Do not ask me routine questions already answered by the repository. Make safe decisions and continue. 

Execution priority:

1. Verify the actual machine, repository, Docker, Zeek, Python environment, disk, and active processes.
2. Set up and verify the CPU virtual environment.
3. Run syntax checks and focused tests.
4. Inspect and repair only the first real blocking issue.
5. Run a fresh small V3 capture pilot and strict PCAP/Zeek/episode validation.
6. If valid, collect one CPU-feasible main dataset.
7. Build leakage-safe preprocessing and immutable split/provenance records.
8. Run sequential rule, Isolation Forest, and Random Forest baselines.
9. Run only feasible ablations and CUDA GRU.
10. Generate figures directly from saved metrics and prepare report-ready tables, evidence, limitations, and reproducibility records.

At each major checkpoint, briefly state:
- what was verified or changed;
- exact artifact paths and run ID;
- test/audit evidence;
- what you are doing next.

Start now. Do not merely describe the plan—perform the work.