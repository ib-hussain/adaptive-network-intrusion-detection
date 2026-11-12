# Threats to validity and experiment protocol

1. **Source provenance:** Gateway records are application instrumentation; Zeek records are observations of actual TCP/UDP connections. They are not interchangeable. Keep sensor and field units documented.
2. **Independent labels:** Ground-truth milestones are recorded in `episodes.jsonl` by a scenario controller, not deduced from alert scores.
3. **Causality:** Feature windows end at or before the alert decision; no feature uses a later milestone, scenario ID, class or defender outcome.
4. **Group splits:** Split on complete episode IDs before windowing. In the prototype `policy=test` is the sole shared held-out set. Independent family/topology holdout remains unfinished.
5. **Equal training budget:** Fixed/random/strategic policies generate the same episode count. For paper-quality work additionally equalise observation duration, number of flow events, benign ratio, and decision/tuning budget. Current profile timings vary: **full budget parity not yet achieved**.
6. **Warning definition:** A positive lead is accepted only if a warning precedes the scenario's predefined milestone. Detection after milestone is a *late* alert; no warning is a miss.
7. **Coverage bias:** Conditional average lead time only includes alerted incidents; coverage-adjusted lead time assigns zero to misses. Report both plus false-positive rate.
8. **Short benign observations:** False alarms per benign hour extrapolate from seconds-long runs; emphasise episode false-alarm fraction until substantial benign hours are captured.
9. **Unseen behaviour:** Independent random seeds are not evidence of generalisation to unseen attack families or previously unseen topologies.
10. **Game-theoretic claim:** EXP3 is a bounded online mixed-strategy learner; it is not a computed Nash equilibrium. The utilities and defender actions are explicit and must be evaluated for scientific relevance.
11. **Security:** This is an authorised, non-destructive experimental lab. Never route any vulnerable service or traffic generator to the public Internet. Compose networking is an isolation control but not a virtual-machine security boundary.
12. **Success claims:** A compilation/unit test/loopback smoke cannot establish cyber threat detection performance. Only independently labelled real network experiments and proper comparative evaluation can do so.
