# EviGraph: End-to-End System & Data Flow Specification

> **Comprehensive operational, architectural, and dataflow lifecycle for the EviGraph Network Forensic Framework.**  
> *Companion Documents:* [`ARCHITECTURE.md`](file:///c:/sahityaa/CN%20project/ARCHITECTURE.md) | [`PRD.md`](file:///c:/sahityaa/CN%20project/PRD.md) | [`DESIGN_SYSTEM.md`](file:///c:/sahityaa/CN%20project/DESIGN_SYSTEM.md)

---

## 1. Executive Pipeline Architecture

EviGraph executes an 8-stage end-to-end pipeline that transforms raw, unindexed packet captures and flow logs into defensible, evidence-grounded forensic incident cases:

```mermaid
flowchart TD
    subgraph S1 ["Stage 1: Ingestion & Integrity"]
        RAW["Raw PCAP / NetFlow / Parquet / CSV<br/>(2.64M+ Enterprise Flows)"] --> HASH["SHA-256 Hash Chain & Audit Log"]
        HASH --> CLEAN["Deduplication, NaN/Inf Sanitization & Schema Canonicalization"]
    end

    subgraph S2 ["Stage 2: Anti-Leakage Feature Extraction"]
        CLEAN --> SPLIT["Stratified Chronological Split<br/>(60% Train / 20% Val / 20% Test)"]
        SPLIT --> META["Metadata Isolation (IPs, Ports, Timestamps)"]
        SPLIT --> FEATS["77 Statistical Numerical Features (Lengths, IAT, Flags, Rates)"]
    end

    subgraph S3 ["Stage 3: Multi-Model Detection & Risk Fusion"]
        FEATS --> MOD_ENS["Tri-Pillar Defense Ensemble (Default)<br/>[XGBoost + HistGB + Deep Autoencoder]"]
        FEATS -.-> MOD_XGB["XGBoost Multi-Class (GPU Hist)"]
        FEATS -.-> MOD_AE["PyTorch Deep Autoencoder (Zero-Day Anomaly)"]
        FEATS -.-> MOD_HGB["Scikit-Learn HistGradientBoosting"]
        FEATS -.-> MOD_GNN["PyG Edge-GraphSAGE Topological GNN"]
        MOD_ENS --> CALIB["Learned Logistic Probability Calibration"]
        CALIB --> THRESH["Validation F1 Threshold Optimization<br/>(Alert Cutoff tau = 0.475)"]
    end

    subgraph S4 ["Stage 4: Test Scoring & Alert Generation"]
        THRESH --> SCORE["Held-Out Test Flow Scoring (470k Flows)"]
        SCORE --> ALERTS["High-Risk Alerts Flagged (Risk >= tau)"]
    end

    subgraph S5 ["Stage 5: Host Graph Construction"]
        SCORE --> H_GRAPH["Host Communication MultiDiGraph<br/>(Nodes = Hosts, Edges = Flows)"]
        H_GRAPH --> NODE_STATS["Vectorized Node Behavioral Analytics<br/>(Degrees, Fan-out, Port Diversity, Bytes)"]
    end

    subgraph S6 ["Stage 6: Correlation & Incident Clustering"]
        ALERTS --> INV_IDX["Inverted Host Indexing<br/>(O(N) Temporal Lookup Window Delta-t <= 300s)"]
        INV_IDX --> COMP["Connected Components & Single-Pass Incident Grouping"]
        COMP --> SEV["Composite Incident Severity Scoring & Entry Point Deduction"]
    end

    subgraph S7 ["Stage 7: Forensic Subgraph & Case Packaging"]
        SEV --> SUB["1-Hop Suspicious Subgraph Extraction (Bounded UI Topology)"]
        SUB --> JSON["outputs/incident_cases.json<br/>(Numpy-Safe Inter-Agent Hand-off Bundle)"]
        JSON --> MERKLE["Merkle Evidence Engine (USP)<br/>(Binary Tree & Inclusion Proofs)"]
        MERKLE --> CERT["outputs/forensic_merkle_certificate.json<br/>(Anchored Session Root Hash)"]
    end

    subgraph S8 ["Stage 8: Downstream Forensic Reasoning"]
        MERKLE --> FSM["Agent 3: Attack Stage FSM & MITRE ATT&CK Mapping"]
        JSON --> CIT["Strict Citation Validator (Links Findings to Flow IDs)"]
        FSM --> REP["Verified Forensic Incident Report Markdown"]
        JSON --> UI["Agent 4: Cytoscape.js Graph Dashboard & Timelines"]
    end
```

---

## 2. Detailed Stage-by-Stage Lifecycle

```mermaid
sequenceDiagram
    autonumber
    participant D as Data Layer (data_loader.py)
    participant M as Detection Engine (baseline_detector.py)
    participant G as Graph Engine (graph_engine.py)
    participant C as Clustering Engine (incident_cluster.py)
    participant O as Forensic Hand-Off (incident_cases.json)
    participant A3 as Forensic Agent 3 (LLM & FSM)

    D->>D: 1. Ingest 7 Parquet/CSV attack slices (2.64M flows)
    D->>D: 2. Cast float64 to float32 & remove duplicate records
    D->>D: 3. Stratified Chronological Split (60% Train / 20% Val / 20% Test)
    D->>M: 4. Pass leak-free X_train, X_val, y_train, y_val
    Note over M: Train GPU Hist XGBoost (299 iters)<br/>Fit Platt Logistic Calibrator<br/>Optimize alert threshold tau = 0.475
    M->>M: 5. Score 470,134 test flows with calibrated posterior risk
    M->>G: 6. Pass scored test DataFrame (8,006 hosts, 291k edges)
    Note over G: Vectorized bulk add_edges_from()<br/>Groupby node behavioral aggregations
    M->>C: 7. Pass 123,424 flagged alerts (risk >= 0.475)
    Note over C: Build inverted host temporal index<br/>Cluster connected components<br/>Compute incident severity scores
    C->>G: 8. Request 1-hop bounded induced subgraphs
    G-->>C: 9. Return Cytoscape-compatible topology
    C->>O: 10. Export serialized incident_cases.json (165 MB)
    O->>A3: 11. Feed structured case bundle to Forensic LLM
    Note over A3: Attack Stage FSM reconstruction<br/>Citation Validator checks [E:flw_id]
```

---

### Stage 1: Data Ingestion & Integrity Preservation
* **Source Telemetry:** Processes heterogeneous captures including full CICIDS2017 Parquet files (DDoS, PortScan, WebAttacks, Patator brute force) and modern 2025 Remote Code Execution (RCE) / Infiltration CSV datasets.
* **Integrity Guard:** Every capture file is read-only, maintaining cryptographic SHA-256 digests.
* **Normalization:** Canonicalizes messy column headers into standardized snake_case identifiers (e.g., `Total Length of Fwd Packets` $\to$ `totlen_fwd_pkts`).
* **Memory Optimization:** Converts 64-bit floating point columns into `float32` and standardizes integer port fields, reducing RAM utilization by over 50%.

---

### Stage 2: Anti-Leakage Feature Extraction & Temporal Partitioning
To adhere strictly to forensic anti-leakage rules (TRD Section 3.2):
* **Identity Isolation:** Raw IP addresses (`src_ip`, `dst_ip`), MAC addresses, and transport port numbers are **strictly barred** from tabular model training features to prevent the algorithm from memorizing network topologies.
* **77 Pure Statistical Features:** Retains packet length statistics, inter-arrival times (IAT), TCP flag counters, segment sizes, and rate indicators.
* **Chronological Stratified Splitting (`per_class=True`):**
  * Rather than a random shuffle (which leaks future behavior into historical models), flows are sorted chronologically by timestamp within each attack class.
  * **60% Train (1,410,379 flows):** Model learning.
  * **20% Validation (470,127 flows):** Calibration and threshold tuning.
  * **20% Held-Out Test (470,134 flows):** Unseen forensic evaluation.

---

### Stage 3: Multi-Model Detection, Zero-Day Anomaly Scoring & Risk Fusion
EviGraph provides 5 selectable detection paradigms (`--model`), defaulting to the **Tri-Pillar Defense-in-Depth Ensemble**:

1. **Tri-Pillar Meta-Ensemble (`src/detectors/ensemble_fuser.py` — Default):**
   * Stacks three distinct inductive biases:
     * **XGBoost:** High-precision supervised gradient boosting on 77 statistical flow metrics.
     * **HistGradientBoosting:** Fast scikit-learn native boosting with zero-nan penalty.
     * **Deep Flow Autoencoder:** Unsupervised PyTorch reconstruction model detecting zero-day traffic shifts.
   * A calibrated stacking logistic fuser merges model risk signals into a defensible posterior probability $P(\text{Malicious} \mid \mathbf{x})$.
2. **Supervised Baseline Classifier (`src/baseline_detector.py`):**
   * Multi-class `xgboost.XGBClassifier` with `tree_method='hist'` and balanced sample weights:
     $$w_c = \frac{N}{C \cdot N_c}$$
   * Calibrated using Platt Scaling / Logistic Regression on decision margins:
     $$P(\text{Malicious} \mid \mathbf{x}) = \frac{1}{1 + \exp(A \cdot \text{margin}(\mathbf{x}) + B)}$$
3. **Unsupervised Zero-Day Autoencoder (`src/detectors/autoencoder_detector.py`):**
   * 4-layer symmetric MLP trained solely on benign flows ($D_{\text{in}} \to 48 \to 24 \to 8 \to 24 \to 48 \to D_{\text{in}}$).
   * Computes per-flow reconstruction Mean Squared Error (MSE); scores above the benign baseline indicate novel attack behavior.
4. **Native HistGradientBoosting (`src/detectors/hist_gb_detector.py`):**
   * Ultra-fast histogram decision trees with Platt risk calibration.
5. **Inductive PyG Edge-GraphSAGE (`src/gnn_detector.py`):**
   * 2-layer GraphSAGE message passing over host-to-host multi-edge subgraphs.
* **Operational Threshold Tuning:** Sweeps cutoffs across validation data to maximize the F1-score, establishing the operational threshold $\tau \approx 0.475 - 0.65$.

---

### Stage 4: Test Scoring & Alert Flagging
* Evaluates the held-out 470,134 test flows.
* Per-flow calibrated risk scores:
  $$\text{Risk}(e) = 1.0 - P(\text{BENIGN} \mid e)$$
* Flagged as **Alert** when $\text{Risk}(e) \ge \tau$.
* Test Metrics: **99.47% Recall**, **89.65% Precision**, **0.9430 F1-Score**, **0.9980 ROC-AUC**.

---

### Stage 5: Host-Communication Graph Construction
* Constructs a directed multigraph $G = (V, E)$ using NetworkX:
  * **Vertices ($V$):** 8,006 unique host IP addresses.
  * **Edges ($E$):** 291,721 flow instances directed from $\text{src\_ip} \to \text{dst\_ip}$.
* **Vectorized Node Metrics:**
  * In-degree ($\text{deg}^-$) and Out-degree ($\text{deg}^+$)
  * Fan-out (unique destination IPs contacted) and Fan-in
  * Destination port diversity (number of unique ports targeted)
  * Byte volume transmitted/received
  * Count of alerts sent and received

---

### Stage 6: Alert Correlation & Incident Clustering
* **Inverted Host Index:** Alerts are indexed by participating host IP addresses rather than $O(N^2)$ pairwise checking:
  $$\text{Index}[\text{IP}] = [(\text{alert\_id}_1, t_1), (\text{alert\_id}_2, t_2), \dots]$$
* **Temporal Edge Rule:** Alerts are linked if they share an IP and occur within $\Delta t \le 300\text{ seconds}$:
  $$\text{Weight}(A_1, A_2) = \frac{1.0}{1.0 + \Delta t / 60.0}$$
* **Incident Grouping:** Connected components cluster the 123,424 alerts into **75 distinct attack incidents**.
* **Composite Incident Severity Score:**
  $$\text{Score} = 0.40 \cdot \max(\text{risk}) + 0.30 \cdot \overline{\text{risk}} + 0.15 \cdot \min\left(1.0, \frac{|V_{\text{affected}}|}{5}\right) + 0.15 \cdot \min\left(1.0, \frac{|C_{\text{attacks}}|}{3}\right)$$
* **Suspected Entry Point Deduction:** Identifies the initiating source IP of the chronologically earliest alert in the cluster.

---

### Stage 7: Subgraph Extraction & Case Bundle Export
* Extracts the 1-hop induced neighborhood around participating attack hosts.
* Caps serialized edges at 300 to ensure responsive interactive rendering in Cytoscape.js.
* Applies a numpy-safe serializer (`np.integer`, `np.floating`, `np.bool_`) to generate [`outputs/incident_cases.json`](file:///c:/sahityaa/CN%20project/outputs/incident_cases.json).

---

### Stage 8: Cryptographic Merkle Evidence Ledger (Core USP)
* Constructs an RFC-6962 compliant binary SHA-256 Merkle tree hashing every raw NetFlow record into tamper-evident leaf digests.
* Enriches each alert edge with its leaf hash and verification status.
* Computes $O(\log N)$ sibling audit inclusion proofs for every cited flow.
* Generates [`outputs/forensic_merkle_certificate.json`](file:///c:/sahityaa/CN%20project/outputs/forensic_merkle_certificate.json) anchoring the session Merkle Root Hash.

---

### Stage 9: Temporal Causal Provenance DAG & MITRE FSM (Core USP)
* Imposes Lamport strictly monotonic time ($t_1 < t_2$) on flow transitions, preventing backwards-in-time hallucinations and mathematically guaranteeing DAG acyclicity.
* Evaluates direct expansion and lateral pivot dwell times ($0.05\text{s} \le \Delta t \le 600\text{s}$).
* Traverses the 6-stage MITRE ATT&CK progression FSM ($Recon \to Access \to Credential \to Lateral \to C2 \to Exfiltration$).
* Discovers the exact **Primary Attack Chain** via topological dynamic programming.

---

### Stage 10: Downstream Forensic Reasoning & Strict Citation Validation
* Invoked via `python main.py --agent` or `python -m src.agent.forensic_agent`.
* Interprets incident cases, maps tactics, queries telemetry tools (`get_flow_count`, `get_flow_evidence`), and writes verified markdown reports.
* **Strict Citation Validator:** Scans report text for `[E:<flow_id>]` tags and cross-references them against `outputs/incident_cases.json`. Enforces $\ge 95\%$ evidence faithfulness (achieving 100.0% with 0 hallucinations).

---

### Stage 11: Dual-Agent Adversarial Courtroom Cross-Examiner (Core USP)
* Automated defense counsel (`src/agent/courtroom_auditor.py`) subjecting the report to **4 Orthogonal Verification Gates**:
  1. **Gate 1 (Cryptographic Admissibility):** Recomputes Merkle root along RFC-6962 audit paths for all cited flow IDs.
  2. **Gate 2 (Protocol Feasibility):** Verifies RFC Layer-4 port and transport protocol consistency (e.g. SSH must be TCP/22, not UDP).
  3. **Gate 3 (Temporal Causal DAG):** Enforces Lamport monotonicity and verifies topological ingress-to-egress pivot paths.
  4. **Gate 4 (Telemetry Fact-Checking):** Validates alert counts, host sets, and risk scores against raw telemetry, flagging ungrounded assertions.
* Issues certified legal verdict (`outputs/certified_forensic_verdict.json`) and cross-examination transcript (`outputs/courtroom_cross_examination.md`) under **FRE 902(13)/(14)** and **ISO/IEC 27037**.

---

### Stage 12: Autonomous Surgical Containment & Blast-Radius Engine (Core USP)
* Analyzes Causal DAGs to formulate a mathematical **Min-Cut Graph Bottleneck**:
  * Identifies minimal edges required to sever adversary entry points from internal victim hosts.
  * Calculates operational Blast-Radius scores (evaluating active services like DNS, LDAP, HTTP, SQL) to prevent self-inflicted production outages.
  * Compiles copy-pasteable firewall commands across Linux `iptables`/`nftables`, Windows Defender PowerShell, Cisco ACL, and Cloud SG.
  * Generates [`outputs/countermeasure_plan.json`](file:///c:/sahityaa/CN%20project/outputs/countermeasure_plan.json) and [`outputs/incident_containment_advisory.md`](file:///c:/sahityaa/CN%20project/outputs/incident_containment_advisory.md).

---

### Stage 13: Privacy-Preserving Redacted Proof Engine (Core USP)
* Compiles zero-topology-leakage intrusion certificates under SEC Item 1.05 and GDPR Art. 33:
  * Masks internal IP addresses and proprietary subnets with Salted HMAC Commitments.
  * Enables third-party insurers and regulators to verify mathematical ascent to the session Merkle Root without learning internal network architecture.
  * Generates [`outputs/privacy_preserving_proof_certificate.json`](file:///c:/sahityaa/CN%20project/outputs/privacy_preserving_proof_certificate.json).

---

### Stage 14: Counterfactual "What-If" Resilience Simulator (Core USP)
* Evaluates proactive security policies by perturbing the Causal Provenance DAG:
  * Simulates port blocks, host quarantines, and perimeter drops.
  * Re-runs topological dynamic programming to test if alternate attack paths exist.
  * Quantifies the Defensive Resilience Index (DRI $\in [0.0, 1.0]$) and identifies architectural Single Points of Failure (SPOF).
  * Generates [`outputs/counterfactual_simulation_results.json`](file:///c:/sahityaa/CN%20project/outputs/counterfactual_simulation_results.json) and [`outputs/resilience_simulation_report.md`](file:///c:/sahityaa/CN%20project/outputs/resilience_simulation_report.md).

---

## 3. Data Transformation Matrix

```
+---------------------------------------------------------------------------------------------------------+
| RAW PACKETS / PARQUET FLOWS                                                                             |
| [src_ip, dst_ip, src_port, dst_port, timestamp, flow_duration, tot_fwd_pkts, flags, ... (84 columns)]   |
+---------------------------------------------------------------------------------------------------------+
                                                     |
                                                     v (data_loader.py)
+---------------------------------------------------------------------------------------------------------+
| CANONICAL TEMPORAL PARTITIONS (60% Train / 20% Val / 20% Test)                                          |
| X_feat: 77 statistical columns (float32) | meta_df: [flow_id, timestamp, src_ip, dst_ip, ports, label]  |
+---------------------------------------------------------------------------------------------------------+
                                                     |
                                                     v (baseline_detector.py & ensemble_fuser.py)
+---------------------------------------------------------------------------------------------------------+
| SCORED TEST FLOWS & TREE-SHAP ATTR                                                                      |
| [flow_id, src_ip, dst_ip, timestamp, risk_score (0.0-1.0), predicted_class, is_alert (True/False)]      |
+---------------------------------------------------------------------------------------------------------+
                          |                                                  |
                          v (graph_engine.py)                                v (incident_cluster.py)
+-----------------------------------------+       +-------------------------------------------------------+
| HOST MULTIDIGRAPH                       |       | INCIDENT CLUSTERS                                     |
| Nodes: 8,006 hosts with behavioral stats|       | 75 Incidents: [INC-0001 ... INC-0075]                 |
| Edges: 291,721 communication flows      |       | Entry Points, Durations, Severity Scores, Alert Lists |
+-----------------------------------------+       +-------------------------------------------------------+
                          \                                                  /
                           -----------------------   ------------------------
                                                  v
+---------------------------------------------------------------------------------------------------------+
| CRYPTOGRAPHIC MERKLE EVIDENCE LEDGER (src/integrity/merkle_engine.py)                                   |
| - RFC-6962 SHA-256 Binary Tree | Session Merkle Root Hash | O(log N) Audit Inclusion Proofs            |
+---------------------------------------------------------------------------------------------------------+
                                                  |
                                                  v
+---------------------------------------------------------------------------------------------------------+
| TEMPORAL CAUSAL PROVENANCE DAG (src/causal_provenance.py)                                               |
| - Monotonic Lamport Causality (t_1 < t_2) | 6-Stage MITRE FSM | Longest Topological Primary Chain       |
+---------------------------------------------------------------------------------------------------------+
                                                  |
                                                  v
+---------------------------------------------------------------------------------------------------------+
| INTER-AGENT CASE BUNDLE (outputs/incident_cases.json)                                                   |
| - Incidents: { id, score, entry_point, duration, affected_hosts, attack_classes, flow_ids, merkle_root }|
| - Causal DAG: { nodes_count, edges_count, primary_attack_chain, is_acyclic: True }                      |
+---------------------------------------------------------------------------------------------------------+
                                                  |
                                                  v
+---------------------------------------------------------------------------------------------------------+
| PROSECUTING FORENSIC AGENT & CITATION VALIDATOR (src/agent/forensic_agent.py)                           |
| - Grounded Tool-Calling Narrative | Evidence Citations [E:<flow_id>] | Faithfulness Target: >= 95%      |
+---------------------------------------------------------------------------------------------------------+
                                                  |
                                                  v
+---------------------------------------------------------------------------------------------------------+
| DUAL-AGENT ADVERSARIAL COURTROOM AUDITOR (src/agent/courtroom_auditor.py)                               |
| - FRE 902(13)/(14) & ISO 27037 Cross-Examination over 4 Defense Gates (Verdict: ADMISSIBLE_IN_COURT)     |
+---------------------------------------------------------------------------------------------------------+
         |                                        |                                        |
         v                                        v                                        v
+-----------------------+              +-----------------------+              +---------------------------+
| SURGICAL CONTAINMENT  |              | PRIVACY PROOFS        |              | WHAT-IF SIMULATOR         |
| Min-Cut Firewall Rules|              | Salted HMAC Masking   |              | Defensive Resilience (DRI)|
| Blast-Radius Advisory |              | Zero-Topology Leakage |              | SPOF Chokepoint Discovery |
+-----------------------+              +-----------------------+              +---------------------------+
```

---

## 4. Execution & Verification Guide

### 1. Rapid Sample Verification (Default: Tri-Pillar Ensemble)
Run on the synthetic multi-stage test fixture:
```bash
python main.py
```

### 2. Choose Detection Architecture
Run any of the 5 supported model options:
```bash
# Tri-Pillar Meta-Ensemble (Default - XGBoost + HistGB + Deep Autoencoder)
python main.py --model ensemble

# Supervised XGBoost Baseline Classifier
python main.py --model xgb

# Unsupervised PyTorch Deep Autoencoder (Zero-Day Anomaly Detection)
python main.py --model autoencoder

# Scikit-Learn Native HistGradientBoosting
python main.py --model histgb

# PyTorch Geometric Inductive Edge-GraphSAGE
python main.py --model gnn
```

### 3. Execution on Scaled Telemetry & Benchmarks
```bash
# Fast evaluation on preprocessed 340k benchmark partition (data/processed/):
python main.py --data processed

# Full end-to-end execution on all 2.64M enterprise captures with CUDA acceleration:
python -u main.py --data all

# Cross-dataset evaluation on external benchmark suite (APT-C2, DDoS2019, UNSW-NB15):
python main.py --data new_benchmark

# Rapid evaluation with flow capping:
python main.py --data data/raw/Tuesday-WorkingHours.pcap_ISCX.csv.parquet --max-rows 50000
```

### 4. Inspecting Generated Incidents
Inspect the generated hand-off bundle:
```bash
python -c "import json; d=json.load(open('outputs/incident_cases.json')); print(f'Total Incidents: {d[\"total_incidents\"]}'); print('Top incident:', d['incidents'][0]['incident_id'], d['incidents'][0]['incident_score'], d['incidents'][0]['attack_classes'])"
```

### 5. Executing Member 3: Downstream Forensic Reasoning & RAG
Run the integrated pipeline with the autonomous reasoning agent enabled:
```bash
# Automated end-to-end detection, graph correlation, and verified reporting:
python main.py --agent

# Or run the forensic agent independently on an existing case package:
python -m src.agent.forensic_agent
```
Outputs are exported to `outputs/forensic_incident_report.md` with verifiable `[E:<flow_id>]` evidence citations, verified by `CitationValidator` (`outputs/citation_validation_results.json`).

### 6. Verifying Ollama & Running Unit Tests
```bash
# Verify local Ollama runtime and tool-calling:
python tests/check_ollama.py

# Run the complete test suite:
python -m unittest discover -s tests
```
