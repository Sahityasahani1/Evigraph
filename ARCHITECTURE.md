# EviGraph: Technical Architecture & System Specification

**Version:** 1.0 | **Status:** Implementation Baseline | **Companion Document:** PRD.md

---

## 1. Logical Pipeline Architecture

EviGraph processes network traffic through eight modular stages:

```mermaid
flowchart TD
    subgraph DataPlane ["Data Ingestion & Integrity"]
        P1["PCAP / Zeek / NetFlow / Parquet"] --> S1["[1] Ingestion & Integrity Layer<br/>(SHA-256 Hash Chain & Audit Log)"]
        S1 --> S2["[2] Normalization & Feature Pipeline<br/>(Anti-Leakage Isolation)"]
    end

    subgraph DetectionPlane ["Member 2: Detection & Graph Engine"]
        S2 --> S3A["[3a] Tabular Detector<br/>(XGBoost + CalibratedClassifierCV)"]
        S2 --> S3B["[3b] Host Graph Builder<br/>(Time-Windowed MultiDiGraph)"]
        S3A -->|Calibrated Risk Scores| S4["[4] Alert Correlation & Incident Clustering<br/>(Inverted Host Index + Community Detection)"]
        S3B -->|Graph Topology & Node Metrics| S4
        S4 --> S4_OUT["Incident Cases Package<br/>(outputs/incident_cases.json)"]
    end

    subgraph ReasoningPlane ["Forensic Reasoning & Reporting"]
        S4_OUT --> S5["[5] Attack Reconstruction<br/>(Stage FSM + Path Search + ATT&CK)"]
        S3A --> S6["[6] Explainability Engine<br/>(TreeSHAP + Fidelity Metrics)"]
        S5 --> S7["[7] Verified Reporting Engine<br/>(Templated Jinja2 + Citation Validator)"]
        S6 --> S7
    end

    subgraph PresentationPlane ["User Interface & API"]
        S4_OUT --> S8["[8] REST API (FastAPI) & Dashboard<br/>(Cytoscape.js + Incident Timeline)"]
        S7 --> S8
    end
```

---

## 2. Component Design & Implementation

### 2.1 Ingestion & Integrity Layer (Stage 1)
* **Hash Integrity:** Every raw input file (PCAP, CSV, Parquet) is streamed into the evidence store in read-only mode while calculating its SHA-256 digest.
* **Audit Chain:** Transformations generate an append-only audit trail where each entry records:
  $$\text{Entry Hash}_k = \text{SHA256}(\text{actor} \,\|\, \text{action} \,\|\, \text{params} \,\|\, \text{input\_hashes} \,\|\, \text{Entry Hash}_{k-1})$$

### 2.2 Normalization & Anti-Leakage Feature Extraction (Stage 2)
* **Strict Anti-Leakage Rules (TRD Sec 3.2):**
  * Raw IP addresses (`src_ip`, `dst_ip`) and ports (`src_port`, `dst_port`) are strictly excluded from tabular model features to prevent memorizing network topologies.
  * Absolute timestamps are stripped; only relative durations, inter-arrival times (IAT), and rates are retained as numeric features.
  * IPs and ports are retained exclusively as **metadata** for graph node identity.

---

### 2.3 Detection & Graph Engine (Stage 3 & 4 — Member 2)

#### 1. Baseline Tabular Detector (`src/baseline_detector.py`)
* **Classifier:** `xgboost.XGBClassifier(eval_metric='mlogloss', n_estimators=100, max_depth=5)`.
* **Class Weighting:** Automatically adjusts for extreme benign-to-attack imbalance:
  $$w_c = \frac{N}{C \cdot N_c}$$
* **Probability Calibration:**
  * Uses `CalibratedClassifierCV(method='sigmoid' | 'isotonic')` wrapped with `FrozenEstimator` to map raw decision margins into true posterior probabilities.
  * **Calibrated Risk Score:** Defined as $P(\text{malicious}) = 1.0 - P(\text{BENIGN})$.
  * **Alert Threshold:** Flagged when $\text{Risk} \ge 0.65$.

#### 2. Host-Communication Graph Builder (`src/graph_engine.py`)
* Constructs a directed multigraph $G = (V, E)$ over time window $\Delta W$:
  * **Vertices ($V$):** Host IP addresses.
  * **Node Behavioral Attributes:**
    * In-degree ($\text{deg}^-$), Out-degree ($\text{deg}^+$)
    * Fan-out (count of unique destination IPs)
    * Fan-in (count of unique source IPs)
    * Port diversity (count of distinct destination ports contacted)
    * Total bytes transmitted and received
    * Total alerts sent and received
  * **Edges ($E$):** Flow instances directed from $src\_ip \to dst\_ip$ with edge attributes: `flow_id`, `src_port`, `dst_port`, `protocol`, `risk_score`, `predicted_class`, `is_alert`.
* **Suspicious Subgraph Extraction:**
  * Extracts the 1-hop induced neighborhood around all hosts involved in alert flows.
  * Bounded serialization: caps exported edges at 300 to ensure fast JSON rendering for Cytoscape.js.

#### 3. Alert Correlation & Incident Clustering (`src/incident_cluster.py`)
* **Inverted Host Indexing:** Instead of naive $O(N^2)$ pairwise checking, alerts are indexed by host:
  $$\text{Index}[\text{IP}] = [(\text{alert\_id}_1, t_1), (\text{alert\_id}_2, t_2), \dots]$$
* **Edge Linking Rule:** An edge is created between Alert $A_1$ and Alert $A_2$ if:
  $$\text{shared\_hosts}(A_1, A_2) \neq \emptyset \quad \land \quad |t_2 - t_1| \le \Delta t_{\text{correlation}} \; (300\text{ seconds})$$
  $$\text{Weight}(A_1, A_2) = \frac{1.0}{1.0 + \Delta t / 60.0}$$
* **Clustering:** Connected components (and optional Louvain community detection) cluster correlated alerts into incident candidates.
* **Incident Severity Score:**
  $$\text{Incident Score} = 0.40 \cdot \max(\text{risk}) + 0.30 \cdot \overline{\text{risk}} + 0.15 \cdot \min\left(1.0, \frac{|V_{\text{affected}}|}{5}\right) + 0.15 \cdot \min\left(1.0, \frac{|C_{\text{attacks}}|}{3}\right)$$

---

## 3. Data Schema & Contracts

### 3.1 Canonical Flow Schema (Parquet & In-Memory DataFrame)

| Column | Type | Category | Description |
| :--- | :--- | :--- | :--- |
| `flow_id` | String | Metadata | Unique immutable identifier (e.g. `flw_001928`) |
| `evidence_id` | String | Metadata | Hash/identifier of source capture file |
| `timestamp` | Datetime | Metadata | UTC start time of the flow |
| `src_ip` | String | Metadata | Source IPv4/IPv6 address |
| `dst_ip` | String | Metadata | Destination IPv4/IPv6 address |
| `src_port` | Int32 | Metadata | Source transport port |
| `dst_port` | Int32 | Metadata | Destination transport port |
| `protocol` | Int32 | Metadata | IP Protocol (6=TCP, 17=UDP) |
| `flow_duration` | Float32 | Feature | Microseconds elapsed |
| `tot_fwd_pkts` | Int32 | Feature | Number of forward packets |
| `tot_bwd_pkts` | Int32 | Feature | Number of backward packets |
| `tot_len_fwd_pkts` | Float32 | Feature | Total bytes transmitted forward |
| `tot_len_bwd_pkts` | Float32 | Feature | Total bytes transmitted backward |
| `flow_iat_mean` | Float32 | Feature | Mean inter-arrival time |
| `syn_flag_cnt` | Int32 | Feature | TCP SYN flag count |
| `rst_flag_cnt` | Int32 | Feature | TCP RST flag count |
| `label` | String | Target | Ground-truth or predicted class name |

---

## 4. Scalability & Big-Data Controls

1. **Parquet Column Pruning:** Reduces disk footprint by 85% compared to raw CSV and accelerates data loading from 45s down to 2s.
2. **Chunked Time-Window Ingestion:** Processes network data in sequential 5-minute sliding windows, ensuring memory utilization never exceeds $O(|V_W| + |E_W|)$.
3. **Host-Indexed Graph Search:** Correlates 100,000+ alerts into structured incidents in sub-second execution time.
