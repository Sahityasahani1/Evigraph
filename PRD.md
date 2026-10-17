# EviGraph: Product Requirements Document (PRD)

**Title:** Explainable, Evidence-Grounded GNN Framework for Network Forensic Detection, Attack Reconstruction, and Verified Incident Reporting  
**Version:** 1.0 | **Status:** Approved Draft | **Date:** October 2026 | **Companion:** ARCHITECTURE.md

---

## 1. Overview

### 1.1 Purpose
This document defines what EviGraph must do, for whom, and how success is measured. It covers scope, personas, functional and non-functional requirements, evaluation criteria, risks, and delivery milestones.

### 1.2 Problem Statement
Existing AI intrusion detectors output isolated alerts and class labels. A forensic analyst needs substantially more: *who attacked whom, in what sequence, why the system believes it, and what raw evidence proves it*. Today analysts manually stitch together PCAPs, flow logs, and SIEM consoles—a process that is slow, error-prone, hard to reproduce, and difficult to defend in legal or regulatory audits.

### 1.3 Product Vision
EviGraph turns raw network telemetry into a defensible, evidence-linked forensic case: detected malicious activity, a reconstructed attack chain mapped to MITRE ATT&CK, transparent explanations for each verdict, and a report in which every claim cites verifiable evidence.

### 1.4 Goals
* **G1:** Detect malicious and anomalous activity at flow, host, and subgraph level, including unseen zero-day behavior.
* **G2:** Group related alerts into incidents and reconstruct an ordered attack chain with confidence scores.
* **G3:** Explain every verdict in terms an analyst can verify.
* **G4:** Preserve evidence integrity so every result is traceable and reproducible.
* **G5:** Generate incident reports where no claim lacks a valid evidence citation.
* **G6:** Measure forensic quality, not merely detection accuracy.

### 1.5 Non-Goals
* Real-time inline blocking or active prevention (EviGraph is an investigation and forensics tool, not an IPS).
* Decrypting TLS or encrypted payloads.
* Endpoint agent development (endpoint logs are an optional extension input).
* Legal certification of evidence for court proceedings.
* Production-scale enterprise deployment in release 1.0.

---

## 2. Personas & User Stories

### 2.1 Personas
* **SOC Analyst (Tier 1/2):** Needs fast triage, clear rationale for alerts, and grouped incidents instead of alert floods.
* **Incident Responder / Forensic Investigator:** Needs attack timelines, entry points, affected hosts, evidence trails, and exportable case files.
* **Security Manager / Auditor:** Needs human-readable summaries, confidence levels, and verifiable proof that conclusions are evidence-backed.
* **Researcher / Student (Project Owner):** Needs a reproducible pipeline, benchmarks, ablations, and publishable evaluations.

### 2.2 Primary User Stories
1. *As an analyst*, I upload a PCAP or flow file and receive a ranked list of incidents.
2. *As an investigator*, I open an incident and see an interactive attack graph and timeline.
3. *As an investigator*, I click any alert or edge and inspect the exact flows, timestamps, and hashes behind it.
4. *As an analyst*, I inspect why a flow was flagged (top features, counterfactuals) and assess explanation stability.
5. *As a manager*, I export a report whose every statement links to verifiable raw evidence.
6. *As a researcher*, I rerun an experiment from stored parameters and manifest hashes and achieve identical results.

---

## 3. Scope

### 3.1 In Scope (MVP & Delivered Core)
* Evidence-integrity layer (SHA-256 hash chaining, audit logs, manifest files).
* Cleaned CICIDS2017 & flow pipeline with strict anti-leakage controls.
* Multi-model detection suite:
  * Supervised XGBoost baseline classifier with Platt probability calibration.
  * Native Scikit-Learn HistGradientBoosting detector.
  * Unsupervised PyTorch Deep Flow Autoencoder for zero-day anomaly detection.
  * PyTorch Geometric (PyG) Edge-GraphSAGE inductive topological edge classifier.
  * Tri-Pillar Meta-Ensemble (`EnsembleFuser`) with learned probability calibration.
* Time-windowed host communication multigraph.
* Scalable inverted-host alert correlation and incident clustering engine.
* Structured JSON incident cases handoff for reasoning agents (`outputs/incident_cases.json`).
* Standardized 340k train/val/test reproducible parquet split caching.
* Multi-source external benchmark generation (APT-C2, DDoS2019, UNSW-NB15).

### 3.2 In Scope (Downstream Extensions)
* LLM forensic narrative generation with strict Citation Validator.
* Interactive Cytoscape.js visual dashboard.
* Adversarial flow perturbation robustness evaluation.

---

## 4. Functional Requirements

*Status Key: **Implemented** | **In Progress** | **Planned***

| ID | Requirement | Priority | Status | Module |
| :--- | :--- | :--- | :--- | :--- |
| **FR-1.1** | Accept PCAP, Zeek logs, and NetFlow/flow CSV/Parquet inputs | **P0** | **Implemented** | Ingestion |
| **FR-1.2** | Compute and store SHA-256 hashes of every input file at ingestion | **P0** | **Implemented** | Ingestion |
| **FR-1.3** | Assign unique, stable IDs to every flow (`flow_id`), alert, and incident | **P0** | **Implemented** | Ingestion |
| **FR-1.4** | Maintain append-only audit log of transformations with hash chain | **P0** | **Implemented** | Ingestion |
| **FR-1.5** | Construct RFC-6962 binary Merkle tree & generate verifiable inclusion proofs for cited evidence | **P0** | **Implemented** | Integrity |
| **FR-2.1** | Extract canonical flow features (duration, byte/packet stats, flags, IAT) | **P0** | **Implemented** | Features |
| **FR-2.2** | Compute host behavior features (fan-out, degrees, unique ports, bytes out vs in) | **P0** | **Implemented** | Features |
| **FR-2.5** | Clean CICIDS2017: drop duplicates, drop NaN/Inf, fix flow termination errors | **P0** | **Implemented** | Features |
| **FR-3.1** | Supervised baseline classifier (XGBoost) with calibrated $[0, 1]$ risk scores | **P0** | **Implemented** | Detection |
| **FR-3.2** | Edge-classification GNN on time-windowed host graphs (PyG Edge-GraphSAGE) | **P1** | **Implemented** | Detection |
| **FR-3.3** | Native lightweight HistGradientBoosting classifier for low-latency scoring | **P1** | **Implemented** | Detection |
| **FR-3.4** | Multi-model score fusion (Tri-Pillar Ensemble) producing calibrated risk score | **P0** | **Implemented** | Detection |
| **FR-3.5** | Unsupervised deep autoencoder for zero-day anomaly detection via MSE | **P1** | **Implemented** | Detection |
| **FR-4.1** | Cluster alerts by shared hosts, time proximity ($\Delta t$), and graph connectivity | **P0** | **Implemented** | Correlation |
| **FR-4.2** | Score each incident by composite severity, host spread, and duration | **P0** | **Implemented** | Correlation |
| **FR-4.3** | Standardized 340k cached benchmark split and external multi-suite generator | **P1** | **Implemented** | Telemetry |
| **FR-5.1** | Build time-ordered event graph per incident | **P0** | **Implemented** | Reconstruction |
| **FR-5.2** | Map behaviors to attack stages: Reconnaissance, Initial Access, Lateral Movement, C2, Exfiltration | **P0** | **Implemented** | Reconstruction |
| **FR-5.3** | Identify suspected entry point and victim hosts via graph path search | **P0** | **Implemented** | Reconstruction |
| **FR-5.5** | Map stages to MITRE ATT&CK tactics and techniques | **P1** | **Implemented** | Reconstruction |
| **FR-6.1** | Generate local and global SHAP explanations for tabular predictions | **P0** | **Implemented** | Explainability |
| **FR-7.1** | Generate templated report: summary, timeline, affected hosts, evidence table | **P0** | **Implemented** | Reporting |
| **FR-7.2** | Every statement in the report references at least one existing evidence ID | **P0** | **Implemented** | Reporting |
| **FR-7.4** | Citation validator removes or flags any unsupported LLM sentence | **P2** | **Implemented** | Reporting |
| **FR-7.5** | Dual-Agent Adversarial Courtroom Cross-Examiner verifying Merkle roots, Layer-4 protocols, Causal DAGs & facts | **P0** | **Implemented** | Courtroom |
| **FR-7.6** | Autonomous Surgical Containment & Blast-Radius Engine synthesizing zero-downtime firewall rules via Min-Cut | **P0** | **Implemented** | Containment |
| **FR-7.7** | Privacy-Preserving Redacted Proof Engine providing zero-topology-leakage intrusion certificates | **P0** | **Implemented** | Integrity |
| **FR-7.8** | Counterfactual "What-If" Resilience Simulator computing Defensive Resilience Index (DRI) & discovering SPOFs | **P0** | **Implemented** | Simulation |
| **FR-8.1** | Interactive dashboard: incident ranking, Cytoscape attack graph, timeline | **P0** | Planned | Dashboard |

---

## 5. Non-Functional Requirements

* **NFR-1 (Integrity):** Raw evidence files are immutable (read-only); hash check fails loudly on mismatch.
* **NFR-1.1 (Merkle Chain-of-Custody):** RFC-6962 binary Merkle tree with $O(\log N)$ inclusion proofs for every cited flow.
* **NFR-1.2 (Courtroom Admissibility):** Federal Rules of Evidence Rule 902(13)/(14) & ISO/IEC 27037 digital forensic certification with composite admissibility score $\ge 0.95$.
* **NFR-2 (Reproducibility):** Fixed seeds, pinned library versions, stored manifests; re-runs produce identical outputs.
* **NFR-3 (Performance):** Process a 1,000,000-flow dataset into incidents within 30 minutes on a single workstation.
* **NFR-4 (Latency):** Dashboard interactions respond in under 2 seconds for incidents with up to 10,000 edges.
* **NFR-5 (Scalability):** Windowed graph construction and inverted indexing keep memory bounded as data grows.
* **NFR-6 (Privacy & Zero-Leakage):** Support IP pseudonymization via keyed HMAC-SHA-256; selective disclosure with zero topology leakage under SEC Item 1.05 and GDPR Art. 33.
* **NFR-7 (Security):** LLM runs locally; log strings are sanitized before prompting; dashboard requires authentication.

---

## 6. Target Success Thresholds

1. **Detection Performance:** Calibrated XGBoost baseline achieves macro-F1 $\ge 0.85$ under temporal split on CICIDS2017.
2. **Forensic Quality:** Attack-chain recovery rate $\ge 80\%$ on multi-stage attack scenarios.
3. **Report Faithfulness:** $100\%$ of claims in templated reports and $\ge 95\%$ of claims in LLM reports cite verified evidence IDs (currently 100.0%).
4. **Leakage Elimination:** $0\%$ feature reliance on raw IP addresses or absolute timestamps in tabular detectors.
5. **Courtroom Admissibility:** $100\%$ of evaluated cases achieve $\ge 0.95$ admissibility score with $0$ sustained objections across cryptographic, protocol, causal, and factual gates.
6. **Zero-Downtime Containment:** Surgical Min-Cut rules maintain production uptime on critical ports ($\ge 0.65$ blast radius) while terminating 100% of adversarial transit edges.
7. **Zero-Topology Leakage Verification:** 100% of redacted intrusion proofs verify against session Merkle roots with complete masking of internal host IPs.
