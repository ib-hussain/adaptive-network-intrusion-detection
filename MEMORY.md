# MEMORY.md — Network_Intrusion_Detection

> **Canonical project handoff / historical record**  
> **Updated:** 17 November 2026 (Asia/Karachi)  
> **Scope:** This file concerns the **Computer Networks / Adaptive Network Intrusion Detection** project only. It deliberately excludes the separate Data Warehousing, Multi-Agent Systems, DeepDocForgery, and other unrelated projects.  
> **Purpose:** Preserve the project story, research decisions, technical architecture, actual/reported experimentation, known failures, outcomes, deliverables, user requirements, and unresolved items so later work can resume without reconstructing the discussion.

## 0. Evidence status and how to read this file

This is a **reconstructed project memory**, not a verbatim export of every message or a fresh checkout of the remote repository. It consolidates:

- **[SOURCE]** The two project PDFs accessible in this session: `Phase_1_Adaptive_Network_Intrusion.pdf` (4 pp.) and `Phase_2_Adaptive_Network_Intrusion.pdf` (9 pp.). Their actual contents were reviewed.
- **[HISTORY]** Prior project conversations and their recovered summaries, including user instructions, engineering logs, earlier assistant assessments, and descriptions/excerpts of Phase 3 artifacts.
- **[REPORT]** Detailed numerical excerpts recovered from the previously produced `Phase3_Adaptive_NIDS_Academic_Report.pdf` and `Phase3_Adaptive_NIDS_Academic_Report_ArchitectureFixed.pdf`. These Phase 3 report files were referenced in conversation history but were **not mounted as readable PDFs in this session**.
- **[UNVERIFIED]** Claims about repository/ZIP contents or completion not independently re-executed in this session. The live GitHub URL could not be retrieved during this compilation, so a Nov. 17 remote HEAD cannot be asserted.

A result with a status of **completed/reported** means it was reported by a historical run/report; it does not mean the experiment was rerun here. The original conversation transcripts, environment logs, manifests, checksums, repository commit, and artifacts remain the authoritative evidence where available. **Do not upgrade a plan, pilot, user desire, or previous assistant claim into a newly verified fact.**

### Fast status snapshot

| Area | Status as of last recovered work | Important qualification |
|---|---|---|
| Research topic and scope | Settled, revised 11–12 Nov 2026 | Computer Networks, not generic AIOps or real-world exploitation |
| Phase 1 | Four-page LaTeX/PDF delivered | Three focal 2026 papers; literature, not project experiments |
| Phase 2 | Nine-page LaTeX/PDF delivered | Ten additional papers; twelve-step **proposed** methodology |
| Phase 3 lab and controlled data | **Reported implemented and run** | Final CPU study was an isolated synthetic laboratory |
| Evaluation | **Reported complete for the implemented models** | Fixed/random/strategic, rule/IF/RF/GRU, two seeds, ablations |
| Best primary balanced result | Random-policy GRU | F1 0.889; PR-AUC 0.965; strict warning coverage 0.833; FP episode rate 0.042 |
| Robust proof that game policy wins | **Not established** | Policy rankings change; the scientific result is conditional |
| True graph neural network | **Not demonstrated** | Proposed GraphSAGE/GRU branch remained conditional/unimplemented in final study |
| Unseen topology transfer | **Not demonstrated** | Final experimental evidence concerned one topology |
| Next-stage prediction and response | Optional, not implemented in final claim | Never describe these as completed |
| Academic report | Seven-page LaTeX PDF **reported delivered** 15 Nov | Later image/diagram correction and draw.io work followed |
| Source repository | Last reported finalized commit `5f87663` | The actual latest remote commit was not verified on 17 Nov |
| Final archive | Approximately 90 MB ZIP **reported delivered** | Contents and checksum must be checked against actual artifact |
| Master project memory | **This file** | Preserve/update it as the project evolves |

---

## 1. Canonical identity and research contract

**Project name:** *Adaptive Network Intrusion Detection and Early Warning through Game-Theoretic Scenario Generation and Temporal Network Analysis*.

**Project/context name:** `Network_Intrusion_Detection`.

**GitHub repository previously supplied by user:** `https://github.com/ib-hussain/adaptive-network-intrusion-detection`.

**Academic context:** University **Computer Networks** semester research project with three phases: Phase 1 literature review and research gap; Phase 2 extended literature review plus research methodology; Phase 3 implementation and experimental evaluation.

**Research question (canonical form, Phase 2):**

> Can game-theoretic selection of controlled adversarial network scenarios improve causal detection and pre-milestone early warning for previously unseen multi-stage communication behaviours, compared with fixed and uniformly random scenario selection under equal budgets and held-out network conditions?

The fundamental research variable is **how controlled network scenarios are selected for generating training observations**. The study asks whether a strategic finite/repeated-game selector produces better evidence for an intrusion detector than fixed or uniform-random selection under otherwise identical collection budgets. Model architecture alone is not the novelty claim.

**Mandatory outputs:** (1) detection of current suspicious/malicious-looking communication, and (2) experimentally valid **early warnings** before independently recorded subsequent milestones.

**Optional, not required for success:** response/containment, attack-stage forecasting beyond the measured warning score, more advanced defender adaptation, a Graph Neural Network branch if identity-safe graph data justify one, and a UI/dashboard.

**Explicit scope exclusions:** no uncontrolled malware; no real zero-day exploit or claims of authentic zero-day detection; no autonomous exploit discovery; no self-propagation; no public attack endpoints; no uncontrolled outbound malicious traffic; no Kubernetes requirement; no production-grade intrusion prevention or large-scale infrastructure claims. “Zero-day-like” means **a previously unseen/held-out behavioural profile** only.

**Computing/network perspective:** measured TCP/UDP flows, protocol metadata, packet/byte counts, bidirectional connections, communication-graph structure, temporal behaviour, network segments, and controlled data transfer. Cybersecurity provides bounded abnormal-traffic scenarios; ML supplies analytical detection models.

## 2. Chronological project evolution and conversation decisions

### Before 11 November 2026 — previous direction

Earlier Phase 1/2 work existed and was already considered for submission. The project originally had an **AIOps-related direction** (the full original proposal and exact pre-pivot research chronology were **not recovered**). Later conversations made it explicit that the abandoned AIOps approach should **not** be conflated with the present network-centric research study.

### 11 November — decision to pivot and rebuild

- User reevaluated the existing project, demanded that the Computer Networks foundation be central and the project be achievable on a short academic schedule.
- Working language included *Game-Theoretic Adaptive Network Anomaly Detection and Early Warning in a Controlled Cyber Range*, before settling on the canonical longer title.
- The decision was to **redo Phase 1 and Phase 2** rather than merely edit an unrelated earlier methodology.
- Fixed priorities: usable intrusion **detection + early warning**; operational response and additional forecasting only as bonus work.
- Feasibility assumptions discussed: roughly one night for rewritten literature and three days for implementation/evaluation. These were planning constraints, not a scientific performance result.

### 12 November — Phase 1 and Phase 2 rewritten

- User requested both phases in properly formatted **LaTeX-derived PDFs**, preferably retaining the older assignment-document visual structure, with editable `.tex` and a ZIP of deliverables.
- Requirements included genuinely relevant 2025–2026 journal literature and Q1/Q2 eligibility; code and dataset availability were useful selection criteria. The work was to avoid exaggerated novelty and unsupported results.
- **Phase 1 (4 pages):** critical comparison of three 2026 focal papers, cross-paper table, four research gaps, explicit research question, references/reproducibility notes.
- **Phase 2 (9 pages):** ten **additional** 2026 papers, comparisons and critical synthesis, hypotheses, a twelve-step methodology, validity/feasibility limitations, architecture figure, references.
- No local Phase 3 outcomes were available when those PDFs were written. All metrics cited within the literature review belong to **external authors**, not our project.
- Initial Phase 3 starter was reportedly built later on 12 Nov: a Docker lab, independent ground truth, three scenario policies, Random Forest / Isolation Forest baselines and early-warning evaluation. A historical assistant reply reported **12/12 tests** and a **384-request local pilot**, which should be treated as an initial engineering milestone rather than the final study.

### 13 November — university GPU lab, pilots, scientific pipeline

- The reported university workstation ran **Ubuntu 24.04**, with **28 CPUs**, an **NVIDIA RTX 4000 Ada** (~20 GiB VRAM), `CUDA=True`, and >1 TB free project disk; Docker's root storage had far less free space (~17 GB). The high-capacity GPU workstation is **not the same** as the final CPU-only host.
- Docker group permissions initially blocked execution. Historical logs indicate `newgrp docker` resolved Docker access.
- Real lab pilots were attempted with isolated Docker networking, a gateway on TCP port 8080, capture on a lab bridge, Zeek analysis, and independent episode manifests.
- Representative pilot identifiers seen in prior records:
  - `pilot_20261113T102813Z_79699` — 12 episodes; tcpdump graceful-stop timeout required forced termination.
  - `pilot_20261113T110555Z_94176` — Zeek completed with return code 0 and yielded **384 `conn.log` records** covering **32 episodes**, with positive origin/response bytes in the recovered check.
- Subsequent reviewed evidence described an initial **32-episode / 384-request** pilot; RF hyperparameter search of **90 Optuna trials**; GPU GRU training of **60 epochs per policy**; and an expanded **96-episode / 1,152-observation** pilot. An apparent **RF PR-AUC of 1.0** was expressly recognized as **non-conclusive** (simple or leaky pilot conditions are not valid evidence of generalization).
- A V2 experiment patch and a parallel research sprint kit were developed/referred to historically: `Phase3_Staged_Network_Research_V2.zip`, `Phase3_Parallel_Research_Sprint.zip`. Do not assume these files are mounted or part of the final archive without inspection.

### 14 November — V2/V3 recovery, sensor debugging, scale ambition

- The user requested faster research/training, use of parallel jobs and the substantial hardware, and asked to scale toward **20–50 Docker nodes** where feasible; one evaluation mentioned 28 logical cores. This was an **aspiration/test generator** and not proof of a validated 20- or 50-container live experiment.
- Historical V2/V3 diagnostics:
  - A V2 collection produced **24 episodes and 480 gateway events** but a **24-byte header-only PCAP**. Gateway traffic alone could not be treated as successful packet capture.
  - V3 introduced explicit timestamps, heartbeats, run statuses and audit information so long experiments were observable and recoverable.
  - The first V3 capture sidecar failed before collecting useful data: `tcpdump` could not change user/group (`Operation not permitted`). Repair included retaining the correct permissions/capabilities (`SETUID`/`SETGID`) or a verified `-Z root` workaround as appropriate to the particular image/runtime.
  - A V3 probe timeout of **45 seconds** caused another false/operational failure; timing logic was revised.
  - A simultaneous older V2 run was suspended to eliminate contention.
  - A long main run encountered an `exit 124` timeout and could not be counted as complete on that occasion.
  - OrgLab Zeek checks later encountered packet checksum/offload effects and Docker address-pool exhaustion; topology/capture behavior required repair rather than bypassing validation.
- Local add-on/smoke tests were reported as passing (examples: **six local tests**, and a separate V2 preflight reporting **18 tests**). Such tests did **not** independently demonstrate that large live runs or the GPU environment passed after patching.
- When responding to specific logs at this stage, the user requested **exact sequential commands**, little extra narration, and **no unsolicited Markdown runbook files**. This was specific to the command-follow-up workflow; later the user explicitly requested MEMORY.md and academic artifacts.

### 15 November — CPU-only scientific completion and repository audit

- User clarified the accessible finishing host was **CPU-only Ubuntu 26.04**, **Intel Core i5-6500**, ~**14.95 GiB RAM**, **Intel HD Graphics 530**, **Zeek 9.0.1** and **Docker 29.9.3**; it had **no CUDA GPU**. This superseded GPU assumptions for the final reported execution environment.
- A working **V3 pilot** was eventually reported: **24 episodes; 480 HTTP/gateway events; ~1.70 MB captured traffic; 13,550 packets; 960 Zeek connections**.
- A larger primary CPU V3 experiment and an independent second-seed run were carried out, producing the reported final Phase 3 evaluation detailed below.
- User explicitly required a fresh audit of `https://github.com/ib-hussain/adaptive-network-intrusion-detection`, comparison to earlier versions, careful identification of incomplete functionality, and an **extended OpenCode/opencode implementation prompt** when useful.
- One audit identified commit **`4ecdbec`** and substantial completed work, but also important issues: **raw evidence was Git-ignored**, documentation lagged behind code, `instructions_temp.md` was unsafe/stale, academic report was Markdown-only, and graph/topology ablations had not been established. The assistant supplied a finalization/reproducibility-oriented OpenCode prompt.
- A later final handoff was reported at clean commit **`5f87663`**, with a **~90 MB complete archive**, **seven-page academic LaTeX PDF**, editable sources, plots/data, reproducibility/verification records, **53 tests passed**, and **102 report-value checks with zero mismatches**. The historically reported ZIP SHA-256 was `9fab0fee9a3a9b213cc012df9f22959005032d2320913293ab336ce03207af1e`; **recheck the hash of the actual archive** before claiming a match.
- User insisted every PDF be produced from **LaTeX**, be academically written, concise but comprehensive, and include substantiated figures/numbers and critical limitations. No invented results, claims of unexplained graph capability, or misleading “best” metrics.

### 15 November late — architecture redraw and handoff refinement

- User supplied `Phase3_Adaptive_NIDS_Academic_Report.tex` and requested compilation to a professional PDF with `fig07_architecture.png` improved and correctly inserted.
- The graphic/editing task was then narrowed to “just reproduce this image properly and nothing else.” When image reproduction was unsatisfactory, the final instruction became: **provide draw.io XML; user would render the diagram themselves**.
- A prior assistant response reportedly supplied full draw.io XML containing the scenario controller, Docker laboratory, PCAP/Zeek sensors, strict gate, processing, three policies, baselines, frozen test, detection/early warning and results. The exact XML text is **not present here**; do not claim a new XML file exists in this session.
- Historically referenced assets: `fig07_architecture.png`, `Phase3_Adaptive_NIDS_Academic_Report.tex`, `Phase3_Adaptive_NIDS_Academic_Report.pdf`, `Phase3_Adaptive_NIDS_Academic_Report_ArchitectureFixed.tex`, `Phase3_Adaptive_NIDS_Academic_Report_ArchitectureFixed.pdf`.

### 16–17 November — continuing context

- Prior chat context retained follow-up discussion about archive/report/architecture; the most recent specifically recoverable artifact-level action was the draw.io XML response.
- **17 November 2026:** user requested this **comprehensive `MEMORY.md`** summarizing **all project conversations and progress**, not merely a short status note. This file is that handoff. It does **not** imply a new code run, remote repository sync, or replacement of previous report artifacts.

---
## 3. Phase 1 — confirmed literature review and gap

**Source file reviewed now:** `Phase_1_Adaptive_Network_Intrusion.pdf`, four pages. It is a literature review, not a set of new experiments.

### The three focal papers

| ID | Publication | Problem/method | Source-paper result and why it matters |
|---|---|---|---|
| P1 | Deepanramkumar & Sharmila (2026), *GraphINR-IDS: Graph-Topology-Aware Implicit Neural Reconstruction for Zero-Day Intrusion Detection in Encrypted Network Traffic*, DOI `10.1007/s44443-026-01260-x` | Benign-only implicit reconstruction using graph Laplacian coordinates, time encodings and SIREN; UNSW-NB15 and CIC-IDS2017 | Reported F1 **99.06 ± 0.12%**, AUROC **99.66%**, AUPRC **99.88%**, FPR **5.13%** under its specified primary protocol. Calibration drift, unseen endpoints and lack of pre-milestone labels remain relevant. |
| P2 | Bala et al. (2026), *Temporal Flow-Based Dynamic Graph Neural Network with Robustness Interpretation for DoS/DDoS IoT Intrusion Detection*, DOI `10.1016/j.dt.2026.06.002` | Temporal directed flow graphs, GATv2, adversarial perturbation/PGD training, ToN-IoT | Reported balanced accuracy **0.9996**, macro-F1 **0.9979** in its specified test. Narrow DoS/DDoS/normal classes, class-prevalence sensitivity and perturbed-feature realism prevent a verified early-warning conclusion. |
| P3 | Afrifah, Epiphaniou, Lallie & Maple (2026), *Multi-stage Attack Detection in IIoT Supply Chains Using Graph Neural Networks*, DOI `10.1007/s10207-026-01340-z` | Attack-stage mapping and RF/GCN/GAT/GraphSAGE comparisons, ToN-IoT/Edge-IIoTset | ToN-IoT corrected GAT macro-F1 **0.687 ± 0.041**; Edge-IIoTset RF macro-F1 **0.615**. Among **21,313** candidate pre-impact records there were just **five positives**, all in training; none held out. Thus prospective warning was **not validated**. |

The literature scores above are **not mutually comparable**: datasets, labels, split designs and prevalence differ. No single paper solves the project's controlled, independently timestamped, matched-budget question.

### Four Phase 1 gaps

1. **Validated early warning:** an alert must fall strictly after an independent episode onset and **before** a separately observed milestone; retrospectively classifying an “impact” stage is not predictive warning.
2. **Strategic scenario selection:** compare fixed, uniformly random and game-selected *network episodes*, with the same action menu, number of episodes and collection budget; avoid treating synthetic feature perturbation as a physical traffic episode.
3. **Unfamiliar communication conditions:** hold out complete behaviour families and, resources permitting, whole topology/network variants, rather than training/testing on overlapping flows or identities.
4. **Scientific validity of “zero-day-like”:** use precise held-out behavioural-novelty terminology, keep ground truth and uncertainty, and never imply that harmless emulation discovers real exploits.

The paper listed associated code/dataset sources for reproducibility leads (not proven full reproductions):

- GraphINR-IDS: `https://github.com/Deepan777/GraphINR-IDS`.
- TF-GATv2: `https://github.com/jencyyyyy/TF-GATv2`.
- Multi-stage study: `https://github.com/AfrifaW/Multi-Stage-Attack-Detection` (availability/execution not independently established in the Phase 1 document).

## 4. Phase 2 — confirmed methodology and research hypotheses

**Source file reviewed now:** `Phase_2_Adaptive_Network_Intrusion.pdf`, nine pages. Its final statement explicitly says **no project experiment had been run when this proposal was written**. Therefore do not copy future-tense methodology language and present it as completed until cross-checked against Phase 3 evidence.

### Extended literature: 10 additional, distinct papers

| # | Short name / research stream | Reference, DOI | Methodological lesson / gap |
|---|---|---|---|
| 1 | TGNE-TA / future alert links | Nayeri & Rezvani, *Journal of Network and Computer Applications* (2026), `10.1016/j.jnca.2026.104455` | Forecasts attacker–victim alerts, not measured pre-milestone warnings from independently manifested flows. |
| 2 | RL-driven active NIDS | Ioannou et al., *Journal of Information Security and Applications* (2026), `10.1016/j.jisa.2026.104496` | Adaptive attackers/defenders already exist; feature-level RL games do not prove matched physical episode generation. |
| 3 | GT-CSAT | Ding, Shen & Liu, *Applied Sciences* (2026), `10.3390/app16083944` | Cost-sensitive game-theoretic robust training already exists: **do not claim game theory + IDS as a first**. |
| 4 | IoT distribution shift | Eren et al., *Electronics* (2026), `10.3390/electronics15112307` | Within-dataset accuracy often fails under cross-dataset drift. |
| 5 | CrossHIDS | Mishra et al., *PLOS ONE* (2026), `10.1371/journal.pone.0346982` | Leakage-safe preparation, feature harmonization and statistical validation matter. |
| 6 | STAR-IDS | Nune et al., *Scientific Reports* (2026; noted “article in press”), `10.1038/s41598-026-78200-2` | Graph structure and node identities can reverse rankings; graphs do not automatically beat tabular baselines. |
| 7 | IDNet | Wang et al., *Computer Networks* (2026), `10.1016/j.comnet.2026.112336` | Resource-aware inference/model routing is different from strategic scenario generation. |
| 8 | DTGNN-FIDS | Yao & Koirala, *Cluster Computing* (2026), `10.1007/s10586-026-06037-5` | Temporal GNNs under failures/perturbations are useful comparators but lack matched-budget pre-milestone games. |
| 9 | HECATE-IDS | Javed et al., *Pervasive and Mobile Computing* (2026; accepted pre-proof), `10.1016/j.pmcj.2026.102302` | Continual/temporal learning exists, but prospective held-out milestone evaluation is distinct. |
| 10 | Multi-stage enterprise GNN | Suharsono et al., *Discover Computing* (2026), `10.1007/s10791-026-10347-y` | Retrospective multi-stage graph detection without measured warning lead time. The proposal documented SJR Q2 versus JCR Q3 classification caveat. |

The Phase 2 document uses 2025 **SJR/JCR category-specific journal quartiles**; eligibility remains subject to the instructor/university's prescribed database. The proposal distinguishes author-reported statistics from our results and recorded code/repository access as research leads, not proof of reproduction.

### Hypotheses (not findings)

- **H1:** Strategic scenario selection improves held-out incident recall and/or PR-AUC over equal-budget fixed/uniform collection.
- **H2:** Strategic collection improves the fraction of incidents warned before impact and/or useful lead time under a fixed false-alarm budget.
- **H3:** Causal temporal and relational features improve over flow-only statistics on at least some independent conditions.

All three are **testable**, not guaranteed. A null or negative result—especially a simple classifier beating a GNN—is academically acceptable if controls are sound.

### Twelve methodological steps from Phase 2

1. **Research input / labels:** observe a causal directed communication multigraph `G_t=(V_t,E_t)` over look-back `[t-W,t)` with host/service nodes, flow edges and packet/byte/duration/protocol attributes. Define incident onset `t0,e` and a later independent milestone `tm,e` per episode.
2. **Controlled acquisition:** isolated two-segment Docker Compose environment with allowed benign and abnormal **harmless** web/API, DNS, approved authentication/discovery and staged dummy transfers; record PCAP and Zeek (`conn.log`, optionally DNS/HTTP), independent orchestration manifest. Optional Suricata **comparator**, never the ground truth.
3. **Preprocessing:** UTC/capture clock consistency, documented flow-to-manifest joins, duplicate/non-finite cleaning, timeout handling, train-only feature scalers/imputers; **split whole episodes before windowing**. Exclude scenario IDs, absolute IPs and labels masquerading as features.
4. **Feature engineering:** flow durations, packets/bytes/rates, protocol/TCP state, connection frequency and interarrival statistics, bursts/deltas, distinct neighbours and directed degrees; missing-visibility masks. Pilot `W=30 s` with 15/60-second sensitivity checks, only validated if run.
5. **Models + policy + warning:** suspicion score `s_t`; validation-selected sustained alert threshold `τ`; finite repeated attacker–defender policy that selects allowed traffic *profiles/orderings*, not exploit code; EXP3/weighted-regret style selection acceptable. Retrain separate fixed, random and game corpora and assess them on one frozen independent test. Optional distinct horizon-risk head only if valid prospective labels exist.
6. **Baselines:** simple rules, benign-trained Isolation Forest, supervised Random Forest/XGBoost, same classifier with temporal/graph summaries, and optional compact GraphSAGE/GRU if graph data support it; equalize features/tuning opportunities/collection budget in policy comparisons.
7. **Experimental partitions:** pilot and audit, varied seeds/workloads/behaviour, full episode-disjoint train/validation/test, independent held-out behavioural family and ideally a distinct topology configuration; no tuning on final test outcomes.
8. **Metrics:** positive precision/recall, macro-F1, PR-AUC, ROC-AUC when defined, false alarms per benign hour, latency; early-warning coverage, conditional lead time, coverage-adjusted lead time, warning false alarms; resource requirements.
9. **Statistics:** paired differences on independent episodes rather than correlated flow windows, episode-bootstrap 95% CIs, paired run-level/episode-level tests only when valid, disclosure of actual number of independent repetitions.
10. **Ablation:** policy versus uniform, remove time features, remove graph summary/structure, change validation threshold/persistence, held-out behaviour/topology, window duration, workload mix, and optional adaptation.
11. **Error analysis:** low-rate misses, benign bursts, late detection, missing bidirectional sensor data, checksum/offload and flow-timeout issues, timestamp boundary joins, graph/ID shortcuts, pre-onset false warnings.
12. **Artifacts:** runnable topology specification, benign-scenario controller, configurations, raw/derivative recordings, explicit manifests/splits, code and reward traces, results/plots/ablation/error records, environment and limitations. Scientific research prototype, not production IPS.

### Exact early-warning definition and integrity constraints

For incident episode `e`, let `t_a,e` be the **first sustained alert after onset and strictly before its independently logged later milestone**:

```text
valid_warning(e) ⇔ t0,e ≤ ta,e < tm,e
T_lead,e = tm,e − ta,e          (only for a valid warning)
warning_coverage = N_validly_warned_episodes / N_incident_episodes
coverage_adjusted_lead = Σ_e[T_lead,e if valid, else 0] / N_incident_episodes
```

- An alert **before onset** is a false/pre-onset warning, not additional lead time.
- An alert **at or after the milestone** is late detection, not early warning.
- An incident that has no valid alert **must stay in the denominator** (zero adjusted lead); do not report lead time only for the easiest successes and call it universal effectiveness.
- A high episode-level or window-level F1 score by itself **does not prove early warning**.
- False-alarm/hour thresholds must be selected on validation data, not retroactively optimized on the frozen test set.

## 5. Architecture: designed versus actually evaluated

### Intended research pipeline

```text
Fixed / Uniform Random / Strategic scenario controller
                        |
      Isolated Docker network: client segment <-> service segment
                        |
    Benign workloads + safe staged abnormal network behaviours
                        |
     Independent episode manifest + packet/flow observation
              (onset, milestone)  (PCAP / Zeek)
                        |
            Fail-closed sensor and label validation
                        |
      Episode-disjoint, causal feature/window construction
                        |
          Train separate model sets by selection policy
                        |
           Rule / Isolation Forest / Random Forest / GRU
            [optional graph/GNN branch if justified]
                        |
         Fixed validation threshold + frozen common test
                        |
       Current detection | Strict pre-milestone early warning
                        |
      Paired results, errors, ablations, uncertainty, figures
```

This is a **conceptual system diagram**. Some components are explicitly optional or proposal-only. In the final evidence we have, standard/temporal classifiers and episode-safe flow features were evaluated. Do **not** label the project as having trained a functioning GNN merely because the Phase 2 figure mentions GraphSAGE/GRU.

### Final Phase 3 implementation (as described in historical report)

- Two-segment isolated virtual Docker environment; controlled bounded harmless HTTP activities and defined incident-like phases.
- Orchestrator independent of the detector writes episode IDs, scenario choices, seeds, onset and later milestones; the detector does not manufacture labels by reading its own alerts.
- Explicit, restricted packet capture (sidecar), PCAP-based sensor evidence, Zeek conversion to connections, and a **seven-check fail-closed validation gate**. Invalid/header-only capture is a failed collection, not a silent success.
- Connection/window features produced with causal time ordering and episode-disjoint partitions; a common frozen test intended to compare policy-derived training corpora fairly.
- Three scenario selection modes: **fixed**, **uniform-random**, and **EXP3-style strategic**; game policy must be understood as a bounded **scenario scheduler**, not as an autonomous hacking agent or comprehensive game-theory equilibrium solver.
- Actual reported evaluated detectors: deterministic/rate **rule**, **Isolation Forest (IF)**, **Random Forest (RF)**, and a non-graph **GRU temporal model**.
- Final data and reports included performance and warning metrics, a held-out slow-ramp behaviour family, ablations, second-seed replication, figures and cross-checked report values.
- Later diagram repair request specifically focused on displaying **scenario controller → network lab → sensors/PCAP → Zeek → strict gate → processing → models → frozen test → detection/early warning** cleanly and without accidental arrows that imply the detector generated ground truth.

### Security and scientific invariants for future modifications

1. Isolated, non-public traffic by default; no unapproved live targets.
2. Sensor and controller clocks documented; a network event must be visible in raw evidence before making a claim.
3. Capture and Zeek **fail closed**; zero connections/header-only PCAP cannot count as a successful run.
4. Ground-truth times are independent of features, IDS alerts and training labels.
5. Whole episode identity isolation across partitions; fit all preprocessing only on training data.
6. Same frozen test set for fixed/random/strategic comparators and no test-driven hyperparameter selection.
7. Strict warning metric pre-onset/late penalties remain visible rather than dropped.
8. Full command, seed, code revision, environment, data checksums and run manifests should accompany every claimed result.
9. Keep policy selection cost, run cost, false alarms and uncertainties alongside classification scores.
10. Keep research statements conservative: conditional improvements, not unproven “zero-day” or state-of-the-art claims.

---

## 6. Phase 3 hardware, runs, datasets, artifacts, and verification

### Distinct environments (do not merge them)

| Environment | Recovered specification | Role/qualification |
|---|---|---|
| University GPU workstation, 13–14 Nov | Ubuntu 24.04; RTX 4000 Ada GPU (~20 GiB); CUDA available; 28 CPUs; project disk with ~1.3 TB free and constrained Docker root | Parallel V2/V3 development, RF HPO and GRU GPU pilots. Some capture and timed-out runs failed. |
| Local CPU-only workstation, 15 Nov | Ubuntu 26.04; Core i5-6500; 14.95 GiB RAM; Intel HD 530; Zeek 9.0.1; Docker 29.9.3; **no CUDA** | The reported final credible CPU-only Phase 3 main/replication evaluation. |
| Session producing this file, 17 Nov | Mounted Phase 1 and Phase 2 PDFs only; no repository checkout or raw Phase 3 logs | Used for history consolidation, **not** new training or confirmation of remote HEAD. |

### Important recovered run names and counts

| Run/stage | State | Recovered counts |
|---|---|---|
| Initial Docker/gateway/Zeek local tests | Pilot | 12 or 32 episodes depending on run; verified later pilot included **384 Zeek records / 32 episodes** |
| Expanded early research pilot | Pilot | **96 episodes, 1,152 observations**; RF 90-trial HPO and GPU GRU 60-epoch training were discussed |
| V2 bad-capture pilot | Invalid sensor evidence | **24 episodes / 480 gateway events**, but **24-byte PCAP**; did not satisfy real capture validation |
| Recovered V3 pilot | Sensor-validated (historically reported) | **24 episodes; 480 events; ~1.70 MB PCAP; 13,550 packets; 960 Zeek connections** |
| Primary final CPU study | Completed/reported | Run ID `cpu_v3_main_v2_20261115T164430Z`; **192 episodes**; **3,840 gateway events**; **107,628 packets**; **7,688 Zeek TCP connections** |
| Independent second-seed study | Completed/reported | Run ID `cpu_v3_main_v2_seed2_20261115T165949Z`; reported paired comparison, but exact full second-seed numeric table not recovered here |

**Primary study labels and splits recovered from final report:**

- Episodes: **192 total = 96 benign + 96 incident**.
- Derived causal windows: **6,336 = 3,168 training + 1,584 validation + 1,584 test**.
- Frozen test: **48 episodes = 24 benign + 24 incident**.
- Incident test set: reported as equally divided between the already observed behaviour families and held-out **slow-ramp** family; this implies **12 in each** if the reported equal split and 24 incidents are unchanged.
- This is one particular simulated topology; topology transfer was not independently tested.

### Verification and code state

- Primary audit around commit **`4ecdbec`** reported **102 machine-checked report values, zero mismatches**.
- Later clean final commit was reported as **`5f87663`**.
- Final handoff reported **53 passing tests**, successful Python bytecode/shell syntax validation, **102 report-value checks with zero mismatches**, and a seven-page LaTeX PDF. These are **historical verification records**, not tests rerun in this session.
- An earlier locally verified 20-/50-node **Compose generator** is **not evidence** that real 20-/50-node collections were fully executed. Resource constraints, address pools and traffic/Zeek visibility matter.
- A historical `LOCAL_VERIFICATION_REPORT.md` described **20/50-node definition generation tests** but not real scaled runtime or new GPU runs.

### Publication/reproducibility inventory expected in the final handoff

The prior final deliverables were described as including the source snapshot/commit, LaTeX PDF/`.tex`, architecture and result figures, dataset derivatives, model/policy output tables, evaluation CSV/JSON, experiment descriptions/configurations, ablations and second-seed results, a claim-to-evidence map, reproducibility and validation records and the archive hash. **Inspect the actual archive before asserting that every named component is present.** Raw PCAPs were previously **Git-ignored** and not reproducibly available from a Git clone alone unless included elsewhere or safely regenerable.

---
## 7. Phase 3 numerical evidence and interpretation

The tables below preserve **reported** values from historical Phase 3 report excerpts; their units and metrics should be rechecked against the original CSV/JSON when conducting a new audit. In particular, **ordinary detection coverage and strict pre-milestone warning coverage are different**, and a detector with excellent PR-AUC can produce many disqualifying pre-onset alerts.

### 7.1 Primary study: GRU comparison

| Scenario training policy | Validation-selected threshold | Episode F1 | PR-AUC | Incident alert coverage | **Strict early-warning coverage** | Reported lead (seconds; report metric) | FP episode rate | Pre-onset warning count |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Fixed | 0.60 | 0.778 | 0.933 | 0.875 | **0.875** | 0.353 | 0.375 | 0 |
| **Uniform random** | **0.75** | **0.889** | **0.965** | **0.833** | **0.833** | **0.440** | **0.042** | **0** |
| Strategic (game/EXP3 style) | 0.75 | 0.667 | 0.869 | 0.500 | **0.500** | 0.199 | **0.000** | 0 |

Interpretation: In this **primary CPU study**, **random-policy GRU** provided the most attractive reported trade-off of classification performance, valid early warning and few false-positive episodes. **Strategic-policy GRU** was more conservative and generated fewer false-positive episodes but missed many incidents, reducing strict coverage. This is **not proof that strategic selection never helps**, nor is it evidence that strategic universally wins.

### 7.2 Primary study: rule, IF and RF comparison

Metric order below is maintained from the prior report excerpt. `alert_cov` is raw alert coverage, `strict_cov` is valid pre-milestone coverage, `pre_onset` is count of invalid pre-onset warnings, and `missed` is reported missed-incident count.

| Policy/model | Threshold | Episode F1 | PR-AUC | alert_cov | **strict_cov** | lead (s) | FP episode rate | pre_onset | missed |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Fixed / Rule | .900 | .432 | .749 | .333 | **.333** | .116 | .208 | 0 | 16 |
| Fixed / IF | .999 | .000 | .835 | .000 | **.000** | .000 | .000 | 0 | 24 |
| Fixed / RF | .850 | .742 | .863 | .958 | **.917** | .664 | .625 | 1 | 1 |
| Random / Rule | .900 | .457 | .749 | .333 | **.333** | .115 | .125 | 0 | 16 |
| Random / IF | .999 | .000 | .789 | .000 | **.000** | .000 | .000 | 0 | 24 |
| Random / RF | .900 | .588 | .844 | .833 | **.833** | .567 | 1.000 | 0 | 4 |
| Strategic / Rule | .850 | .432 | .749 | .333 | **.333** | .158 | .208 | 0 | 16 |
| Strategic / IF | .999 | .000 | .793 | .000 | **.000** | .000 | .000 | 0 | 24 |
| Strategic / RF | .900 | **.960** | **1.000** | **1.000** | **.042** | .627 | .083 | **23** | 0 |

**Crucial scientific caution:** strategic/RF looks nearly perfect by episode F1 and PR-AUC, yet **23 pre-onset warning cases** leave strict early-warning coverage at approximately **0.042**. This example makes the project’s central methodological distinction concrete: **high detection accuracy is not the same as causal warning**. Do not cite the strategic/RF score without its pre-onset/strict coverage failure. Likewise, random/RF's FP episode rate `1.000` matters even though its strict warning coverage was `0.833`.

### 7.3 Held-out family, ablations, second seed and statistical strength

- The **held-out slow-ramp incident family** was specifically used as a behavioural novelty test. In recovered snippets, the rule detector's coverage on this family was **0.000**, versus **0.667** on observed families for the fixed-policy rule. IF was reported **0.000** on both. RF held-out slow-ramp coverage was reported as **fixed 0.917 / random 0.667 / strategic 1.000**. These are context-specific results, **not** an assertion of universally successful generalization.
- A second independently seeded CPU run was reported. Across both seeds, **relative policy rankings changed**. **No statistically robust global superiority** of the strategic selector has been demonstrated.
- Ablation analyses and figures were reported as produced. Recovered conversation history confirms they existed but **does not provide their full numeric tables**. Do not invent their magnitudes. Check original ablation CSV/JSON and results figures before re-quoting precise effects.
- Exact episode-bootstrap intervals, significance tests and detailed error-case numerics are **not fully recovered in this context**. Two seeds are small evidence for external validity, regardless of within-run test counts.
- Avoid conflating window counts with independent sample size. The primary frozen test has **48 independent episodes**; its **1,584 windows** are correlated within episodes and do not support treating n=1,584 as independent runs.
- A “GNN ablation” or “unseen-topology transfer” must be marked **not evaluated** rather than fabricated with a synthetic number.

### 7.4 Appropriate academic conclusion

> The study demonstrates a controlled, reproducible way to collect network telemetry with independently timestamped incident milestones and to measure the difference between accurate detection and genuinely early warning. Under the reported primary holdout, a random-policy GRU produced the best overall balance among the evaluated temporal models. A strategic selection policy did not exhibit consistent superiority across the two evaluated seeds; observed outcomes are conditioned on the small benign/incident test environment, thresholds, and synthetic scenario design.

A defensible Phase 3 contribution is the **evaluation protocol, ground-truth independence, capture validation, matched policy comparison and distinction between detection and warning**, not a claim that an innovative GNN or universal adaptive protection system has been proven.

## 8. Engineering failures, repairs, and recurring operational risks

| Failure/risk encountered | Historical observation | Repair/lesson for future work |
|---|---|---|
| Docker permissions | API socket permission denied on university workstation | `docker` group/permission context required refresh; historical use of `newgrp docker`. Validate permissions before blaming model code. |
| Tcpdump shutdown | Initial pilot could not always stop capture gracefully | Explicit process tracking and bounded shutdown, preserving a complete/trustworthy PCAP and real status record. |
| Header-only capture | V2 had 480 gateway events but PCAP only 24 bytes | **Fail closed**: HTTP request counts alone do not demonstrate network evidence. Check packet count, actual bytes, Zeek records and bidirectionality. |
| Tcpdump UID switch | V3 sidecar failed: `Operation not permitted` | Review `SETUID`/`SETGID` and `tcpdump -Z root` in the specific container configuration; rerun live capture audit. |
| Probe timeout | V3 probe prematurely failed around 45 s | Adjust timeout/startup logic, explicitly log component readiness. Do not disguise timeouts by increasing them blindly. |
| Old run contention | V2 job left suspended while V3 executing | Audit PIDs/tmux/jobs to avoid running conflicting resource-heavy phases concurrently. |
| Long main experiment timeout | `exit 124` on one historical larger run | Split/restart from persisted checkpoint, keep per-episode progress/heartbeat; do not claim unfinished run as complete. |
| OrgLab Zeek failures | Checksum/offloading caused Zeek-gate concerns | Inspect NIC/virtual bridge offload handling and decode errors; validate direction, clocks and counts with raw PCAP. |
| Docker address-pool exhaustion | Repeated networks consumed available address space | Clean isolated project resources carefully; create stable network allocations without deleting unrelated Docker assets. |
| GPU vs CPU confusion | University had RTX 4000 Ada; final local host was CPU-only | Do not issue CUDA commands for the final CPU environment; verify platform before providing command sequences. |
| Graph ambition vs data | Earlier code/report had no genuine GNN training | Keep temporal GRU distinct from graph-convolution/GraphSAGE/GAT models. Graph branch requires independently justified identity-safe graph data. |
| Misleading high score | Pilot RF PR-AUC 1.0; strategic/RF strong F1 but many pre-onset alerts | Enforce strict warning semantics, held-out partitioning and prevalence/false alarm reporting. |
| Documentation drift | README / `instructions_temp.md` contained stale or unsafe instructions per audit | Verify against last working commands, remove obsolete instructions, avoid overwriting known-good runs. |
| Incomplete Git evidence | Raw PCAP often Git-ignored | Publish carefully sized evidence archive / hashes / regeneration procedure; do not claim a bare clone contains raw captures. |
| Scope creep | Requests for 20–50 Docker nodes and advanced GNN | Clearly distinguish verified generator/smoke tests from real multi-node packet capture + inference; preserve core study validity first. |
| Architecture figure | `fig07_architecture.png` was visually unsatisfactory | User chose **draw.io XML** as the preferred editable representation; align arrows and labels with actual implemented pipeline. |

## 9. Known artifacts, paths and handoff references

### Source PDFs accessible in this conversation

- `/mnt/data/Phase_1_Adaptive_Network_Intrusion.pdf` — 4-page finalized Phase 1 document.
- `/mnt/data/Phase_2_Adaptive_Network_Intrusion.pdf` — 9-page finalized Phase 2 document.
- `/mnt/data/MEMORY.md` — this consolidated handoff.

### Previously mentioned files (not guaranteed mounted now)

- `Phase_1_New_Network_Intrusion_Research.pdf` and various Phase 1 LaTeX `.tex` editions.
- `Phase_2_New_Network_Intrusion_Methodology.pdf` / `.docx` and Phase 2 LaTeX editions.
- `Phase3_Staged_Network_Research_V2.zip`, `Phase3_Parallel_Research_Sprint.zip`.
- `Phase3_Adaptive_NIDS_Academic_Report.tex`, `Phase3_Adaptive_NIDS_Academic_Report.pdf`.
- `Phase3_Adaptive_NIDS_Academic_Report_ArchitectureFixed.tex`, `Phase3_Adaptive_NIDS_Academic_Report_ArchitectureFixed.pdf`.
- `fig07_architecture.png` and prior draw.io XML pasted into a conversation.
- `MEMORY(1).md`, `INSTRUCTIONS(1).md`, `LOCAL_VERIFICATION_REPORT.md`, `instructions_temp.md` referenced in previous context. These should **not** silently override the present handoff or be called current without timestamp/diff checks.
- Historically provided `.txt` logs and repository snapshots/archives; exact contents are accessible only if uploaded or retrieved again.

### Historical repository revisions and archive

- Repository: `https://github.com/ib-hussain/adaptive-network-intrusion-detection`.
- **Earlier audited revision**: `4ecdbec`.
- **Later finalized revision as reported**: `5f87663`.
- **Final deliverables archive**: described as **about 90 MB**, with SHA-256 `9fab0fee9a3a9b213cc012df9f22959005032d2320913293ab336ce03207af1e` from the historical handoff. Exact archive **filename not recovered** here; do not invent it or assume the file is at a new sandbox path.
- **Do not assume `HEAD == 5f87663` today**; remote history can advance. An attempted 17 Nov web retrieval of the URL did not provide a usable repository page, and the session container could not resolve GitHub. No fresh repository or raw-evidence inspection was performed while constructing this memory.
- A past execution path of the project was reported as `/home/fastlab/deepFakeDetection/adaptive-network-intrusion-detection`; this was an environment-specific location, not the canonical location for all machines. Check `pwd` before using it.

### What should accompany any new Phase 3 report or ZIP

- Academic LaTeX source, compiled PDF, working figure files (`.drawio`/XML or final PNG/PDF), no broken references.
- Exact Git revision, clean status, dependency lock/tool versions, OS/hardware and seed/configuration file.
- Commands and logs for real collection, Zeek ingestion, valid sensor gate, feature assembly, train/validation/test selection, training, evaluation, figures and verification.
- Manifests and evidence hashes; raw PCAPs and Zeek logs where distributable; explanation when large raw evidence must instead be regenerated.
- Frozen test membership, expected denominators, metrics generated from CSV/JSON rather than typed by hand.
- Policy action/reward/probability logs, corresponding datasets, model artifacts, and honest run-cost accounting.
- Test and checker results including warnings, failed/unsupported experiments, and reproducer instructions.
- Consistent definitions of detection, late detection, pre-onset false warning and strict pre-milestone alert.

## 10. Project writing/presentation and interaction preferences

These requirements were repeatedly communicated and should be treated as active unless superseded:

1. **Accuracy first:** “make no mistakes,” do not invent values, run outcomes, article claims, trained models, benchmark validity, unexplained infrastructure, or certainty about missing files.
2. **Stay within the requested project:** Computer Networks core, genuine observed network traffic, controlled harmless scenarios, measured detection + early warning; do not revert to abandoned AIOps work or mix unrelated course projects.
3. **LaTeX for every generated academic PDF**, with journal/course-appropriate formal academic prose, sensible figures/tables, clear methodology, reproducibility, citations and carefully delimited conclusions. PDF must look like a report, not converted Markdown-like chat text.
4. **Keep it concise but complete:** eliminate filler, repetitive statements and gratuitous visual embellishments; show meaningful evidence, methodology and critical limitations rather than pages of generic explanation.
5. **Follow the user's explicit instructions over suggestions**; previous Phase 1/2 PDFs remain source references and formatting guides, but later user requirements take precedence.
6. **Build actual deliverables when asked:** compiled LaTeX PDF, editable `.tex`, accompanying plots/draw.io and a complete ZIP only when actually created and verified. Link concrete existing paths; never fabricate downloadable filenames.
7. **When the user requests code or fixes**, inspect current files, logs, exact error conditions and the real runtime; deliver practical patches/commands. During the Nov 14 terminal-log workflow, sequential precise shell commands were preferred to explanatory runbooks.
8. **Do not overstate novelty:** preexisting work already covers GNN IDS, RL attackers/defenders, game-theoretic training and alert forecasting; our specific question is the matched network-level scenario selection / timestamped warning protocol.
9. **Distinguish what is planned, coded, tested, measured and independently reproduced.** In particular, do not claim 20–50-node runtime, CUDA experiments on the CPU machine, true GNN training or cross-topology transfer without fresh evidence.
10. **When diagram quality matters**, supply accurate editable **draw.io XML** if requested, with readable flow, correct connectors, appropriate labeling and no inferred physical/ground-truth relationships.

## 11. Status, limitations, and honest unresolved work

### Reported complete as of 15 November

- Literature reviews, research gap, hypotheses and methodological plan.
- Safe two-segment Docker lab, controller ground-truth timestamps and bounded traffic scenarios.
- Validated packet-capture/Zeek evidence and fail-closed sensor checks (after V2/V3 fixes).
- Episode-disjoint causal preprocessing and fixed common test partition.
- Fixed/uniform-random/strategic scenario collection and rule/Isolation Forest/RF/GRU evaluation.
- Primary and second-seed CPU comparisons; early-warning metrics, selected ablation analyses and results/architecture figures; academic LaTeX report and complete archive **reported delivered**.
- A finalized clean revision and machine-value consistency checks **historically reported**.

### Not proven or not completed in recovered evidence

- A real graph neural network (GraphSAGE/GAT) model trained/evaluated on sufficiently independent topology-sensitive graph observations.
- Independent holdout of a **whole network topology** and robust real-world transfer conclusions.
- Authenticated real zero-day exploits, actual malware, multi-stage compromise beyond the controlled harmless scenarios, or deployed network defense.
- An independent next-stage forecast head or automatic containment and operator response service.
- Verified full live training/evaluation on **20 or 50 Docker nodes**; only definition-generation tests were previously reported.
- Stable strategic policy superiority, statistically definitive causality beyond the limited controlled setup, or general deployment feasibility.
- Actual presence of **all raw PCAPs** in a fresh Git clone; they were reported ignored/not version-controlled.
- New current remote commit/re-run as of Nov 17. Previous test metrics do not establish current CI health without verification.
- Exhaustive recovery of every historical message and all older artifact bytes. Some original files/dialogue fragments remain unavailable in this session.

### Next-work priorities, ordered by evidence value

1. **Verify current repository state**: fetch `HEAD`, branch, tag, working tree and diffs after `5f87663`; compare reported results/manifests and README to latest files; never assume remote matches historical snapshot.
2. **Verify actual handoff archive**: locate the delivered ~90 MB ZIP, check SHA-256 and list contents; unpack in a clean directory and confirm the report, raw/derived evidence, figures, policy logs and reproducibility instructions.
3. **Rerun integrity checks** on the exact archived revision with actual available tools; compare checker counts (historically 53 tests and 102 value checks) and inspect warning/failure output.
4. **Review data validity**: packet/Zeek bidirectionality, timestamp joins, label independence, episode-disjoint splits, threshold validation provenance, duplicate/identity leakage, held-out slow-ramp membership and strict warning denominators.
5. **Review Phase 3 figures/report**: regenerate from machine-readable results, verify especially strategic/RF pre-onset failure and two-seed ordering variability; ensure all reported figures are correctly sized/rendered and claims scoped.
6. **Repair/maintain architecture** using editable draw.io representation of the **implemented** system (optional graph/forecast/response explicitly marked as future rather than completed).
7. **Only after core reproduction**, consider new independent seeds, higher diversity in benign load, a second topology, a genuine graph baseline and formal episode-level confidence intervals. Report null findings as such.
8. **Update `MEMORY.md` whenever new verified work is performed**, including date, commit, command, new artifact names/checksums, changed metrics, limitations and any reversals of prior conclusions.

### Rules for continuity in a future chat or code assistant

- Read **this entire `MEMORY.md`** first, then the actual Phase 1/2 PDFs, then repository README/architecture, source, experiment manifests, logs, results, reports and any newer user directions.
- Use the newest **verified** evidence, not the most optimistic prior assistant message.
- For a result, record **`[DATE] [COMMIT] [RUN_ID] [DATA_HASH] [TEST] [METRIC] [CAVEAT]`**.
- Do not wipe, overwrite or silently regenerate previous experimental results. Use timestamped paths/checkpoints; preserve reproducibility.
- If a former statement conflicts with source artifacts, correct the record transparently instead of concealing the discrepancy.
- Do not treat this memory as an executable specification; inspect the running code because the real repository may have changed.

---

## 12. Provenance index and future memory updates

| Evidence | Where it was available | Weight |
|---|---|---|
| Phase 1 final review | Actual `Phase_1_Adaptive_Network_Intrusion.pdf` mounted 17 Nov; 4 pages | High for Phase 1's *written content* |
| Phase 2 final methodology | Actual `Phase_2_Adaptive_Network_Intrusion.pdf` mounted 17 Nov; 9 pages | High for Phase 2's *proposed content* |
| Nov 11–15 user decisions | Retrieved conversation history and project summaries | High for general intent, moderate for exact wording |
| Nov 13–15 pilot details | Retrieved prior chat and pasted execution-log summaries | Moderate; recheck primary log files to rerun |
| Phase 3 model tables and counts | Retrieved detailed excerpts from historical Phase 3 report | Moderate to high as *reported* results, not independently rerun here |
| Commit/archive checksum/test counts | Historical assistant handoff and report summaries | Moderate; authenticate against actual repository/ZIP |
| Current remote HEAD | Retrieval attempted 17 Nov without success | **Not established** |
| Original early AIOps topic, every old message, full diagram XML | Not comprehensively recovered | **Do not reconstruct speculatively** |

**Append-only update template:**

```markdown
### YYYY-MM-DD — Short description
- Scope: [component, phase]
- Repository revision: [commit, branch, clean/dirty]
- Environment: [OS, CPU/GPU, Docker/Zeek/Python versions]
- Inputs: [config, seed, source hashes, run IDs]
- Change: [files/modules changed and why]
- Validation: [actual commands, count of passes/fails, evidence paths]
- Results: [metrics, units, split/denominators, uncertainty]
- Limitations: [not run, known errors, interpretation]
- Artifacts: [actual filenames, links, checksums]
- Next action: [specific outstanding item]
```

**END OF PROJECT MEMORY — 17 November 2026.**
