# EviGraph: End-to-End System & Data Flow Specification

> **Comprehensive operational, architectural, and dataflow lifecycle for the EviGraph Network Forensic Framework.**  
> *Companion Documents:* [`ARCHITECTURE.md`](file:///c:/sahityaa/CN%20project/ARCHITECTURE.md) | [`PRD.md`](file:///c:/sahityaa/CN%20project/PRD.md) | [`AGENTS.md`](file:///c:/sahityaa/CN%20project/AGENTS.md)

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

    subgraph S3 ["Stage 3: Detection & Probability Calibration"]
        FEATS --> XGB["Multi-Class XGBoost Classifier<br/>(CUDA GPU Acceleration, Class-Balanced Weights)"]
        FEATS -.-> GNN["PyG Edge-GraphSAGE GNN<br/>(Optional Structural Detector)"]
        XGB --> PLATT["Platt Scaling Risk Calibration<br/>(Logistic Regression on Decision Margins)"]
        PLATT --> THRESH["Validation F1 Threshold Optimization<br/>(Alert Cutoff tau = 0.475)"]
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
    end

    subgraph S8 ["Stage 8: Downstream Forensic Reasoning"]
        JSON --> FSM["Agent 3: Attack Stage FSM & MITRE ATT&CK Mapping"]
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

### Stage 3: Supervised Detection & Risk Calibration
* **Model:** Multi-class `xgboost.XGBClassifier` utilizing `tree_method='hist'` with NVIDIA CUDA hardware acceleration.
* **Balanced Sample Weighting:** Addresses severe class imbalance (e.g., Benign vs. Heartbleed):
  $$w_c = \frac{N}{C \cdot N_c}$$
* **Platt Scaling Probability Calibration:** Raw tree decision margins are calibrated using a logistic regression estimator:
  $$P(\text{Malicious} \mid \mathbf{x}) = \frac{1}{1 + \exp(A \cdot \text{margin}(\mathbf{x}) + B)}$$
* **Threshold Tuning:** Sweeps cutoffs across validation data to maximize the F1-score, establishing the operational threshold $\tau = 0.475$.

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

### Stage 8: Downstream Forensic Reasoning & Reporting
* Consumed directly by **Agent 3 (Forensic LLM & FSM)**:
  * Reconstructs attack progression (Reconnaissance $\to$ Initial Access $\to$ Lateral Movement $\to$ Exfiltration).
  * Maps attack vectors to MITRE ATT&CK techniques.
* **Strict Citation Validator:** Verifies that every claim in the generated forensic report links back to an immutable `[E:flow_id]` tag matching the ground-truth metadata in `incident_cases.json`.

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
                                                     v (baseline_detector.py)
+---------------------------------------------------------------------------------------------------------+
| SCORED TEST FLOWS                                                                                       |
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
| INTER-AGENT CASE BUNDLE (outputs/incident_cases.json)                                                   |
| - Total Incidents: 75                                                                                   |
| - Incident Schema: { id, score, entry_point, duration, affected_hosts, attack_classes, flow_ids }       |
| - Forensic Subgraph: { nodes: [id, role, degrees], edges: [flow_id, src, dst, port, risk, alert] }      |
+---------------------------------------------------------------------------------------------------------+
```

---

## 4. Execution & Verification Guide

### 1. Rapid Sample Verification
Run on the synthetic multi-stage test fixture:
```bash
python main.py
```

### 2. Full 2.64M Enterprise Pipeline Execution
Run end-to-end on all raw parquet and CSV captures with CUDA GPU acceleration:
```bash
python -u main.py --data all
```

### 3. PyTorch Geometric GNN Alternative
Train the 2-layer Edge-GraphSAGE topological edge classifier:
```bash
python -u main.py --data all --model gnn
```

### 4. Inspecting Generated Incidents
Inspect the generated hand-off bundle:
```bash
python -c "import json; d=json.load(open('outputs/incident_cases.json')); print(f'Total Incidents: {d[\"total_incidents\"]}'); print('Top incident:', d['incidents'][0]['incident_id'], d['incidents'][0]['incident_score'], d['incidents'][0]['attack_classes'])"
```
