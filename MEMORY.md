# MEMORY.md — Adaptive Network Intrusion Detection & Early Warning

> **Project memory snapshot: 14 November 2026 (Asia/Karachi).** This is an evidence-qualified handover to a terminal-bound agent such as OpenCode. It is **not** a claim to know the university machine's current state after the final log provided. Inspect the live working tree, processes and artefacts before taking action. Cross-read [`AGENTS.md`](AGENTS.md), [`SKILLS.md`](SKILLS.md), and [`INSTRUCTIONS.md`](INSTRUCTIONS.md).

## 1. Identity, intent and authority

- **Owner / course:** Ibrahim Hussain; Computer Networks semester research project. Earlier project collaboration included Sameer Khan. Do not confuse this project with the separate ADAS, teaching, document forgery or other users' projects.
- **Active project:** **Adaptive Network Intrusion Detection and Early Warning through Game-Theoretic Scenario Generation and Temporal Network Analysis**.
- **Current Linux repository, as last reported:** `/home/fastlab/deepFakeDetection/adaptive-network-intrusion-detection` on a university Ubuntu workstation. User has a laptop/WSL copy as well. **Always resolve the actual current root rather than hardcode this path.**
- **Original historical repository:** `Network-Anomally-Detection_Root-Cause-Localization_Generalisation` (older AIOps/GNN network anomaly and root-cause-localisation project). Its general engineering rules and directory conventions carry over; its scientific objectives, architectures, results and old training assumptions **do not**.
- **Research decision:** Complete pivot (**Option A**) chosen. Phase 1 and Phase 2 were rewritten for the new topic; Phase 3 must implement/evaluate **that new research question**. The owner prefers independent, decisive execution, does not want repeated deadline questions, and places urgency on getting real work done with verified results.
- **Time constraint historically stated:** one night for both literature reviews, then three days for implementation/evaluation. This is a planning constraint, not evidence that the study has been completed.

## 2. Approved scientific objective

**Central question:** Can game-theoretic selection/generation of **controlled adversarial network scenarios** improve **detection** and **causally valid pre-milestone early warning** of previously unseen multi-stage network communication behaviour, relative to fixed/uniform-random scenarios at equal data budgets and on identical held-out conditions?

Computer Networks is the central discipline: directed host-to-host communication, TCP/UDP flows, DNS/HTTP where observable, packet/byte volumes and direction, inter-arrival timing, burstiness, changing communication graphs, inter-segment activity, and topology/traffic shifts. Cybersecurity supplies bounded, authorised test narratives; ML and statistical inference supply detectors; game theory supplies scenario/defence strategies.

**Mandatory outputs:** (1) detection; (2) early warning. **Optional/bonus:** controlled response/containment recommendation and properly evaluated next-stage prediction. We seek to **maximise useful early-warning lead time** while constraining false alarms and maintaining incident recall; never optimise lead time alone.

For incident episode `e`, with independent scenario onset `t0,e`, predeclared later event/milestone `tm,e`, and first valid model alert `ta,e`:

```text
valid early alert iff t0,e <= ta,e < tm,e, using observations available no later than ta,e
T_lead,e = tm,e - ta,e     (only for a valid early alert)
```

Report pre-milestone warning coverage = warned incidents / **all** incident episodes, conditional median and mean lead time, coverage-adjusted lead time (misses contribute zero), false-positive episodes and false alarms **per benign hour**, recall/precision/F1/PR-AUC, computational cost and uncertainty. A pre-onset warning is not a valid early alert; a post-milestone detection is late. Where no future-positive test examples exist, **do not report predictive performance**.

**Terminology:** A previously unseen/held-out, non-destructive laboratory network pattern may be described as *zero-day-like behavioural novelty*, **not a verified zero-day exploit**, genuine malware propagation, actual data exfiltration, or protection from real attacks. Record that lab HTTP traffic is real observed traffic from synthetic experimental scenarios; it is **not automatically representative enterprise intrusion data**.

## 3. Boundaries agreed with the owner

Permanently excluded from the current course implementation: Kubernetes, uncontrolled/real malware, self-propagating code, real zero-day exploit creation/discovery, autonomous offensive exploitation, multi-LLM coordination, attacks against external/production hosts, and production-scale SIEM/dashboard. Do not reintroduce these as prerequisites or create exposed vulnerable public services. Containers share the host kernel: they are **not** VMs and should not be used to isolate real malware. A small local LLM was discussed only as a possible extension, **not** an authorised core dependency.

Use isolated, private, bounded Docker services and harmless traffic profiles. Confirm `internal: true` on the actual Compose networks, no unintended published ports or egress routes, and sensor visibility. University machine belongs to an institutional lab; apply system-level changes only with permission. Docker group membership implies broad host privilege.

## 4. Literature and course deliverables

### Official assessment

- **Phase 1:** exactly three directly related **2026 Q1 journal research articles**; one-page critical synthesis, cross-paper table (title/year/dataset/preprocessing/model/metrics/results/limitations), at least three evidence-backed research gaps.
- **Phase 2:** eight to ten **additional 2025–2026** eligible studies; comparison, refined/justified gap, detailed **12-step** methodology and architecture diagram.
- **Phase 3:** implement the Phase 2 method, document data/preprocessing/splits, baseline evaluation, visualisations, fair literature comparison, ablations, critical results/discussion and reproducibility. No unsupported comparison across incompatible datasets.

**Current submitted-style research files** (look in `researchPapers/` and use the university's real filenames): `Phase_1_Adaptive_Network_Intrusion.pdf`, `Phase_2_Adaptive_Network_Intrusion.pdf`. LaTeX versions were previously produced; those PDFs are authoritative for methodology context, not executable code or experimental evidence. The older PDFs (`Phase_1_Literature_Review.pdf`, `Phase2_GNN_AIOps_Research_Methodology.pdf`) are **historical layout/engineering references only**.

### Three primary 2026 Phase 1 papers

1. P. Deepanramkumar & A. Helen Sharmila, **GraphINR-IDS: Graph-Topology-Aware Implicit Neural Reconstruction for Zero-Day Intrusion Detection in Encrypted Network Traffic**, *Journal of King Saud University – Computer and Information Sciences*, DOI **10.1007/s44443-026-01260-x**. Benign-only graph/temporal anomaly reconstruction, UNSW-NB15 + CIC-IDS2017. Paper-linked code candidate: `https://github.com/Deepan777/GraphINR-IDS`. Chronological calibration drift and absent pre-impact validation matter.
2. T. J. Bala et al., **Temporal Flow-Based Dynamic Graph Neural Network with Robustness Interpretation for DoS/DDoS IoT Intrusion Detection**, *Defence Technology*, DOI **10.1016/j.dt.2026.06.002**. ToN-IoT directed temporal flow graphs, GATv2, feature-level adversarial robustness. Paper-linked notebooks candidate: `https://github.com/jencyyyyy/TF-GATv2`. High headline scores do not establish pre-impact warning or cross-topology transfer.
3. W. Afrifah et al., **Multi-stage Attack Detection in IIoT Supply Chains Using Graph Neural Networks**, *International Journal of Information Security*, DOI **10.1007/s10207-026-01340-z**. ToN-IoT + Edge-IIoTset; GAT/GraphSAGE/Random Forest stage detection. Critically, paper's held-out pre-impact forecasting set had **no positive cases**, so authors did not claim forecasting. Candidate code: `https://github.com/AfrifaW/Multi-Stage-Attack-Detection` (independent execution/access not established).

Paper code/data links are **leads**, not proof that an exact author implementation or dataset version is runnable. Check licence, commit, archive and hashes. Other Phase 2 studies include: Nayeri & Rezvani (TGNE-TA, 10.1016/j.jnca.2026.104455); Ioannou et al. (adaptive RL-driven NIDS defence, 10.1016/j.jisa.2026.104496); Ding et al. (GT-CSAT, 10.3390/app16083944); Eren et al. (distributional drift, 10.3390/electronics15112307); Mishra et al. (CrossHIDS, 10.1371/journal.pone.0346982); Nune et al. (STAR-IDS, 10.1038/s41598-026-78200-2); Wang et al. (IDNet, 10.1016/j.comnet.2026.112336); Yao & Koirala (DTGNN-FIDS, 10.1007/s10586-026-06037-5); Javed et al. (HECATE-IDS, 10.1016/j.pmcj.2026.102302); Suharsono et al. (adaptive temporal GNN, 10.1007/s10791-026-10347-y). Read the Phase 2 PDF for the exact comparison, eligibility qualifications and references.

**Novelty is a hypothesis, not established:** strategic and RL-driven cyber-defence, early-alert forecasting, temporal GNNs and cross-dataset generalisation all have prior work. Test the *incremental value of matched-budget physical network-scenario selection for independent pre-milestone warning*, not 'first ever game-theoretic IDS'.

## 5. Architecture and experimentally intended protocol

```text
Bounded scenario controller / fixed vs random vs finite strategic (EXP3)
  -> isolated Docker clients + gateway + service subnet(s)
  -> independent ground-truth event journal / request timings / capture PCAP
  -> Zeek JSON conn.log + application gateway logs (distinct observation sources)
  -> episode-safe causal feature extraction / optional host-time communication graphs
  -> RF + IsolationForest + rule baseline; temporal GRU; graph model if justified
  -> frozen, common held-out test episodes
  -> detection + early-warning + false-alarm metrics, costs, CIs, ablations
```

**Crucial fairness requirements:** fixed, random and strategic policies receive matched episode/traffic/action budgets and identical test data; separate complete episodes before feature windowing; hold out scenario family and, when available, topology; validation-only thresholds/HPO; no feature/time leakage. Required graph ablations must preserve comparable information input and training budget. Do not recycle test alerts to train the game.

## 6. Actual implementation history and hard evidence

### Initial starter (12–13 November)

- A small `compose.yaml` lab with internal `clients` and `services` networks, `gateway`, `server_a`, `server_b`, runner. Safe HTTP request traffic.
- `src/code/{game,ingest,features,early_warning,models,pipeline,figures}.py`; RF/Isolation Forest; JSONL manifests, `policy=test` as common holdout. Laptop WSL Python 3.12.7 CPU-only preflight passed (13 tests); loopback smoke produced 32 episodes/384 requests. This was **software verification**, not network evidence.
- University Ubuntu 24.04 system: **NVIDIA RTX 4000 Ada Generation** with **20,475 MiB nominal VRAM**, driver **580.178.04** in later logs; Torch CUDA available; **28 logical CPUs**, about **31 GiB RAM** reported earlier. University `zeek --version` later reported **9.0.1**. Project filesystem `/home/fastlab/deepFakeDetection` ~**1.3 TB free**, but Docker root `/var/lib/docker` was on a separate, much smaller root partition with only **~17 GB free** in the November 13 check. Do not confuse the two storage limits.
- First university pilot `pilot_20261113T083155Z_61354`: **32 episodes**, **384 gateway requests**; after recovery, Zeek audit reported **384 connection records**, coverage of all **32 episodes**, bidirectional byte counts, **5,376 PCAP frames** and zero malformed frames in the saved audit. These counts are for this particular controlled pilot, not evidence of real malicious intrusion.
- `pilot_20261113T102813Z_79699`: **96 episodes**, **1,152 gateway observations** after recovered postprocessing; its Zeek logs earlier showed offloading/filtered-trace warnings. Some old collection processes and captures were left running; preserve files and inspect live PIDs before stopping them.
- First parallel sprint on the 32-episode pilot completed **90 Optuna trials** (30 for each training policy, SQLite) and **three GRU models at 60 epochs**, plus a Zeek audit. Some validation PR-AUC values reached **1.0 on tiny lab data**—these are diagnostic and probably too easy; do **not** cite as intrusion-detector effectiveness. The GRU is a temporal baseline, **not a GNN**.

### Stage V2 introduced 13–14 November

- New `lab/staged_generate.py`: **20 HTTP requests per episode**; **onset index 5**, **escalation index 12**, **dummy-transfer milestone index 19**. Each round contains **one benign and one controlled incident** episode.
- Policies: `fixed`, `random`, `strategic`, `test`; training profiles `rapid_repeat`, `destination_shift`, `jittered_burst`; withheld test profile `slow_ramp`; benign profiles `steady`, `maintenance_burst`, `service_fanout`, `approved_bulk`. Experimental two-segment topology remains **one topology**.
- Same seed/config must be used for resumed rounds. Per-round atomic `rounds/<policy>_<round>.json` bundles are authoritative; incomplete gateway requests may remain in shared raw log but are excluded from manifest-based data extraction. Generator strategy state is reconstructed by replaying completed round outcomes on resume.
- **Critical conceptual limitation:** `game_reward()` currently computes `rate`/`spread` heuristic outcomes from observed request gaps and destination count. It is **not** feedback from the trained NIDS, and EXP3 currently learns from those heuristics. The strategic-policy experiment cannot be described as adaptive to the actual deployed ML detector until this is redesigned and audited.
- Stage V2 pilot `staged_v2_check_01`: **24 complete episodes, 480 gateway observations** recovered. However, `traffic_20261114T051137Z_112948.pcap` was **24 bytes**, containing only a PCAP header and **zero packets**. The collection wrapper hung; `gateway_subset.jsonl` was recovered later. **This is application-only diagnostic data, NOT a valid captured network dataset.**
- V2 `staged_v2_main_01` configured for **96 episodes / 1,920 requests** but the failed capture never generated completed rounds in the logs supplied. Its initialised `scenario_config.json` must be preserved, and resumed with `--resume` only when validated.

### Stage V3 and immediate blocker (latest evidence: 14 November)

- V3 `setup/staged_collect_v3.sh` added explicit named Docker capture sidecar (gateway network namespace), capture probe, packet audit, UTC timestamped `collector_v3_*.log`, per-round `generator_*.log`, atomic collector status and periodic **HEARTBEAT**, bounded `docker stop`, live status script and fail-closed training gate.
- Existing V2 suspended launcher held a `flock`; it was eventually terminated. No lingering host `tcpdump` was reported immediately before the V3 attempt. An old Compose orphan warning still appeared (not automatically proof of a running capture).
- V3 `staged_v3_check_02` and `staged_v2_main_01` both **failed before any episodes were generated**. Docker capture container immediately logged:

  ```text
  tcpdump: Couldn't change to 'tcpdump' uid=100 gid=101: Operation not permitted
  ```

- Both resulting V3 PCAPs were **24-byte header-only**. `staged_v3_check_02`: zero completed rounds, zero gateway events, `FAILED_OR_INTERRUPTED`; V2 main still lacks a successful network capture. **Do not claim capture success.**
- Latest prepared but **not yet confirmed applied or run at university**: `Phase3_TCPDump_Privilege_Hotfix/fix_tcpdump_privileges.sh` changes the exact V3 invocation from `"$IMAGE" -i any ...` to `"$IMAGE" -Z root -i any ...` while retaining `--cap-drop ALL --cap-add NET_RAW --security-opt no-new-privileges:true`, internal network namespace and logging. This avoids tcpdump's user-switch attempt; **successful live packet capture has NOT yet been observed**. It must be verified through the probe, non-empty PCAP and Zeek/manifest alignment. On an institutional host, review the retained effective root identity inside this limited container with local policy.

## 7. Verified vs unverified project state

| Component | Last known status | Interpretation |
|---|---|---|
| Python environment / test suite | 18 Stage V2 tests and 7 V3-focused tests passed in prior runs | Unit/integration validation, not complete research |
| CUDA and university GPU | CUDA `True` on RTX 4000 Ada | Use for deep models; current RF/IsolationForest CPU-only |
| Initial pilot application + Zeek | Older 32-episode run with aligned Zeek flow counts | Limited diagnostic evidence |
| HPO / temporal GRU | Completed on tiny initial pilot | Not a GNN; cannot establish unseen-behaviour advantage |
| Stage V2 complete gateway-only pilot | 24 episodes, 480 requests; header-only PCAP | **Invalid as packet-based experiment** |
| Stage V3 capture | `tcpdump` privilege-switch failure | **Current blocking defect**; `-Z root` hotfix still unverified live |
| Stage V2 main run | Initialised, not shown complete | Preserve config; do not claim 96 network-observed episodes |
| GNN with real node/edge graph | Not demonstrated | Planned |
| Cross-topology/novel-attack scientific evaluation | Not demonstrated | Planned |
| Response/prediction beyond warnings | Not demonstrated | Optional |

### Integrity cautions

- The `complete_repo_upto_now.zip` uploaded on 13 November contained **149 entries** and reflected the laptop repository **before** Stage V2/V3 patch installation on the university host; it omitted some university-only PCAPs, model checkpoints, SQLite studies and data. It cannot override more recent live university files. **Inspect and merge, never blindly overwrite.**
- ZIP's `.gitignore` was not final/reliable (`.gitignore` itself appears ignored); verify Git tracking, `.gitignore`, `.gitattributes`, `git status --ignored` and tracked oversized files before committing.
- Public paper code and datasets are useful, but full reproduction is not guaranteed by a valid URL. Report provenance, commit/versions, missing data/code/config, and deviations faithfully. No Git LFS, no large data commits.
- Old process IDs (e.g. `74855`, `80058`, `94532`, `112948`) are historical and **must never** be reused in commands without verifying PID identity now.
- `tmux` survives SSH disconnections, **not physical shutdown**. Stage checkpoints and complete round bundles survive only if their filesystem is persistent; take an authorised backup to another storage location before shutdown.

## 8. Immediate next evidence and actions

1. Inspect actual live repo, git/ignored state, university-only files, active jobs, Docker groups/contexts, available disk, GPU, `zeek`, current V3 launcher and whether `-Z root` is already present.
2. Correct/validate the **minimal capture privilege failure** without weakening isolation beyond what the lab permits. Do not start model training yet; preflight with four harmless HTTP probe requests and verify actual packet records, both communication directions, and no unwanted egress.
3. Resume `staged_v3_check_02` with **identical** config only if it still has zero completed rounds; otherwise inspect round bundles. Stop on first real failure; record output and keep logs.
4. Reprocess valid, *closed* PCAP with Zeek JSON and validate matching to **every** episode and the observed gateway log; do not equate connection count with request count by assumption.
5. Only then start or resume `staged_v2_main_01` and parallel CPU/GPU analysis using the training capture/Zeek gates. Never run compute-heavy training concurrently with timing-sensitive collection unless explicitly controlled as an experiment.
6. Fix scientific shortcomings before final claims: enrich genuine independent traffic and multi-stage precursors; separate heuristic game rewards from actual detection outcomes; implement graph representation and meaningful GNN/temporal ablations, scenario-family/topology holdouts, matched budgets, repeated seeds, episode-bootstrap CIs, false alarm per benign hour and adjusted lead time.
7. Keep **live progress, time stamps, heartbeats, and persisted logs for every long job**. This is an explicit user instruction, not optional polish.

## 9. Memory maintenance contract

After each meaningful change, append a dated, evidence-backed entry under `## 10. Append-only progress log` below: action, exact revision/command, input run ID, output paths, observed counts/results, tests passed, failed tests, resume/rollback status, and unresolved blocker. Distinguish `VERIFIED`, `PENDING`, `FAILED`, and `PROPOSED`. Do not silently rewrite prior failures as successes. When older evidence conflicts with the current machine, prefer **fresh live artefacts** and preserve the prior observation as historical context.

## 10. Append-only progress log

- **2026-11-14 (handover):** University V3 sidecar's last known failure is tcpdump's `uid=100 gid=101` privilege-switch error. A `-Z root` hotfix has been prepared/tested on source syntax but no university test results were supplied after installing it. Current stage **BLOCKED ON LIVE CAPTURE PREFLIGHT**. Older 32/96-episode pilot diagnostics and completed HPO/GRU outputs remain useful but are not evidence of real intrusion detection.

## 11. Primary project references and official tool docs

- Research: `researchPapers/Phase_1_Adaptive_Network_Intrusion.pdf`, `researchPapers/Phase_2_Adaptive_Network_Intrusion.pdf`; original course Phase 3 brief if present.
- Code: `lab/staged_generate.py`, `src/code/pipeline.py`, `src/code/early_warning.py`, `src/code/temporal_gru_sprint.py`, `setup/staged_collect_v3.sh`, `setup/staged_capture_audit.py`, `setup/staged_train_guard_v3.sh`, `setup/staged_v3_status.sh`.
- Docker Compose interpolation: https://docs.docker.com/compose/how-tos/environment-variables/variable-interpolation/ ; Docker security: https://docs.docker.com/engine/security/ .
- `tcpdump` privilege drop (`-Z`): https://man7.org/linux/man-pages/man1/tcpdump.1.html .
- Zeek PCAP and JSON logs: https://docs.zeek.org/en/current/quickstart.html .
- Optuna SQLite resume caveat: https://optuna.readthedocs.io/en/stable/tutorial/20_recipes/001_rdb.html .
- PyTorch resume/checkpoint state: https://docs.pytorch.org/tutorials/beginner/saving_loading_models.html .
