# Member 2 Contract Findings: Data Ingestion, Schema & Output Specifications

**Document:** Forensic Pipeline Inter-Member Contract Analysis  
**Author:** Member 1 (Data & Traffic Pipeline)  
**Target:** Member 2 (Detection & Graph Engine — `Evigraph`)  
**Status:** Complete Audit Baseline (Read-Only Analysis)  
**Date:** October 2026  

---

## 1. Executive Summary

This contract audit defines the exact data boundary between **Member 1 (Data & Traffic Pipeline)** and **Member 2 (Detection & Graph Engine)**. Member 2's codebase was audited in read-only mode across all data ingestion routines, feature selectors, graph builders, model inference pipelines, and JSON bundle exporters.

### Core Discoveries:
1. **Ingestion Mode:** Member 2 supports **Parquet** (`pd.read_parquet`) and **CSV** (`pd.read_csv` with auto-detected `,` vs `;` delimiter). There are **no SQL or database connections** in the codebase.
2. **Flow Referencing:** Member 2 references flows **strictly by unique string identifier (`flow_id`)**, never by row index. Downstream citation validation enforces `[E:<flow_id>]`.
3. **Internal Renaming Inconsistencies:** Member 2's `src/data_loader.py` renames raw CICFlowMeter columns into abbreviations (e.g., `totlen_fwd_pkts`), whereas `src/config.py`, `ARCHITECTURE.md`, `src/generate_sample_data.py`, and `src/graph_engine.py` use `tot_len_fwd_pkts`. In `src/gnn_detector.py`, a silent fallback bug exists where feeding `tot_len_fwd_pkts` causes byte statistics to default to 0.0.
4. **Feature Isolation Rule:** Member 2 dynamically treats **any numeric column not in `METADATA_COLS` as a training feature**. Member 1 must ensure no numeric identifiers (e.g. `sensor_id`, `vlan_id`) are passed without being registered in `METADATA_COLS`.

---

## 2. Inventory of Data Loading Locations

Below is the exhaustive list of every location in Member 2's codebase where data is loaded:

| File | Line(s) | Call / Method | File Formats | Purpose |
| :--- | :--- | :--- | :--- | :--- |
| [`src/data_loader.py`](file:///c:/coding/college/CN%20Project/Evigraph/src/data_loader.py#L207) | 206–212 | `pd.read_parquet(file_path)`<br/>`pd.read_csv(file_path, sep=sep)` | `.parquet`, `.csv` | Primary ingestion engine in `load_dataset()`. Auto-detects `,` vs `;`. Strips column whitespace, applies `COLUMN_CANONICAL_MAP`, sanitizes `label`. |
| [`src/data_loader.py`](file:///c:/coding/college/CN%20Project/Evigraph/src/data_loader.py#L260-L262) | 260–262 | `pd.read_parquet(train_path)`<br/>`pd.read_parquet(val_path)`<br/>`pd.read_parquet(test_path)` | `.parquet` | `load_processed_splits()` loads pre-partitioned train/val/test splits from `data/processed/`. |
| [`src/data_loader.py`](file:///c:/coding/college/CN%20Project/Evigraph/src/data_loader.py#L302) | 302 | `self.load_dataset(f)` in loop | `.parquet`, `.csv` | `load_combined_dataset()` iterates over all `.parquet` and `.csv` files in `data/raw/` or custom paths, performing stratified sampling. |
| [`main.py`](file:///c:/coding/college/CN%20Project/Evigraph/main.py#L45) | 45 | `loader.load_dataset(data_path, max_rows)` | `.parquet`, `.csv` | CLI single-file entrypoint when `--data <path>` is supplied. |
| [`main.py`](file:///c:/coding/college/CN%20Project/Evigraph/main.py#L191) | 191 | `loader.load_combined_dataset(...)` | `.parquet`, `.csv` | CLI batch entrypoint when `--data all` is passed. |
| [`main.py`](file:///c:/coding/college/CN%20Project/Evigraph/main.py#L197) | 197 | `pd.read_parquet(full_proc_path)` | `.parquet` | CLI benchmark entrypoint when `--data processed` is passed (`data/processed/benchmark_full_340k.parquet`). |
| [`main.py`](file:///c:/coding/college/CN%20Project/Evigraph/main.py#L213) | 213 | `loader.load_combined_dataset(file_paths=...)` | `.parquet`, `.csv` | CLI benchmark entrypoint when `--data new_benchmark` is passed. |
| [`src/inspect_data.py`](file:///c:/coding/college/CN%20Project/Evigraph/src/inspect_data.py#L25-L30) | 25, 30 | `pd.read_parquet()`, `pd.read_csv()` | `.parquet`, `.csv` | Telemetry inspector analyzing file size, RAM footprint, attack distributions, and IP cardinality. |
| [`src/export_training_data.py`](file:///c:/coding/college/CN%20Project/Evigraph/src/export_training_data.py#L44) | 44, 117, 122 | `loader.load_combined_dataset(...)`<br/>`pd.read_parquet()`, `pd.read_csv(nrows=100)` | `.parquet`, `.csv` | Manifest generator and split exporter creating reproducible benchmark splits in `data/processed/`. |
| [`src/baseline_detector.py`](file:///c:/coding/college/CN%20Project/Evigraph/src/baseline_detector.py#L258-L261) | 258–261 | `joblib.load(model_path)`<br/>`joblib.load(meta_path)` | `.joblib` | Model checkpoint loader restoring trained weights, label classes, and feature lists. |
| [`src/detectors/autoencoder_detector.py`](file:///c:/coding/college/CN%20Project/Evigraph/src/detectors/autoencoder_detector.py#L215-L218) | 215, 218 | `torch.load()`, `joblib.load()` | `.pt`, `.joblib` | PyTorch model checkpoint loader for unsupervised autoencoder. |
| [`src/detectors/hist_gb_detector.py`](file:///c:/coding/college/CN%20Project/Evigraph/src/detectors/hist_gb_detector.py#L120-L123) | 120–123 | `joblib.load()` | `.joblib` | Scikit-Learn HistGradientBoosting checkpoint loader. |
| [`src/gnn_detector.py`](file:///c:/coding/college/CN%20Project/Evigraph/src/gnn_detector.py#L286-L289) | 286, 289 | `torch.load()`, `joblib.load()` | `.pt`, `.joblib` | PyG Edge-GraphSAGE model weights and graph scaler loader. |
| [`src/graph_engine.py`](file:///c:/coding/college/CN%20Project/Evigraph/src/graph_engine.py#L20) | 20–66 | `build_graph_from_flows(flows_df)` | In-Memory `pd.DataFrame` | Builds NetworkX `MultiDiGraph` from scored flow records. |
| [`src/incident_cluster.py`](file:///c:/coding/college/CN%20Project/Evigraph/src/incident_cluster.py#L24) | 24–63 | `correlate_alerts(alerts_df)` | In-Memory `pd.DataFrame` | Correlates alerts into incidents using an inverted host index. |
| [`src/integrity/merkle_engine.py`](file:///c:/coding/college/CN%20Project/Evigraph/src/integrity/merkle_engine.py#L62) | 62, 203, 241 | `build_tree(flows)`<br/>`json.load()` | In-Memory `pd.DataFrame` & `.json` | Computes SHA-256 Merkle tree and enriches `outputs/incident_cases.json`. |
| [`src/causal_provenance.py`](file:///c:/coding/college/CN%20Project/Evigraph/src/causal_provenance.py#L331) | 331 | `json.load()` | `.json` | Reads and enriches `outputs/incident_cases.json` with Causal DAGs and attack chains. |
| **SQL / Database** | None | **None** | None | **Zero SQL usage.** No SQLite, PostgreSQL, MySQL, DuckDB, or SQLAlchemy. |

---

## 3. Exact Input Schema Expected by Member 2

### 3.1 Metadata & Identity Fields (`METADATA_COLS`)
These columns must be present in the dataset. They are **never used as tabular ML training features** (to prevent artificial identity leakage under TRD Sec 3.2):

| Column Name | Expected Dtype | Nullable? | Fallback / Default in Member 2 | Role in Member 2 |
| :--- | :--- | :--- | :--- | :--- |
| `flow_id` | `object` / `string` | **No** (Strict) | If missing, synthesizes `flw_{i:07d}` | Unique immutable flow ID. Used as edge key in graphs and Merkle tree leaf computation. |
| `timestamp` | `datetime64[ns]` or ISO string | **No** (Strict) | Coerced via `pd.to_datetime(..., format="mixed")` | Temporal sorting, train/val/test splits, graph time-windows ($\Delta W \le 300s$), causal DAG Lamport ordering. |
| `src_ip` | `string` | **No** (Strict) | Cast via `.astype(str)` | Graph source node key, host behavioral metrics (out-degree, fan-out, bytes sent). |
| `dst_ip` | `string` | **No** (Strict) | Cast via `.astype(str)` | Graph target node key, host behavioral metrics (in-degree, fan-in, bytes received). |
| `src_port` | `int32` / `int64` | Yes | Defaults to `0` | Metadata on graph edge, Merkle canonical string. |
| `dst_port` | `int32` / `int64` | Yes | Defaults to `0` | Destination service port, graph edge attribute, Merkle canonical string. |
| `protocol` | `int32` / `int64` | Yes | Defaults to `6` (TCP) | Layer-4 IANA protocol number (e.g. 6=TCP, 17=UDP). Merkle leaf canonical string. |
| `label` | `string` | Yes (for test) | Cleaned, `Normal` replaced with `BENIGN` | Supervised target for model training/evaluation. Binary split: `label != "BENIGN"`. |
| `evidence_id` | `string` | Yes | Defaults to `file_path.stem` | Identifier/hash of source PCAP/capture file. Carried into incident evidence files list. |
| `src_mac` | `string` | Yes | Optional metadata | In `METADATA_COLS` to prevent leakage; not used in graph edges. |
| `dst_mac` | `string` | Yes | Optional metadata | In `METADATA_COLS` to prevent leakage; not used in graph edges. |

### 3.2 Core Flow Statistical Features
Member 2 expects standard numeric flow features derived from network traffic. While `src/config.py` lists 35 canonical features, `src/data_loader.py` will automatically ingest **all numeric columns not in `METADATA_COLS`**:

```
flow_duration, tot_fwd_pkts, tot_bwd_pkts, tot_len_fwd_pkts (or totlen_fwd_pkts), 
tot_len_bwd_pkts (or totlen_bwd_pkts), fwd_pkt_len_max, fwd_pkt_len_min, fwd_pkt_len_mean, 
fwd_pkt_len_std, bwd_pkt_len_max, bwd_pkt_len_min, bwd_pkt_len_mean, bwd_pkt_len_std, 
flow_bytes_s (or flow_byts_s), flow_pkts_s, flow_iat_mean, flow_iat_std, flow_iat_max, 
flow_iat_min, fwd_iat_tot, bwd_iat_tot, fwd_psh_flags, bwd_psh_flags, fwd_urg_flags, 
bwd_urg_flags, fin_flag_cnt, syn_flag_cnt, rst_flag_cnt, psh_flag_cnt, ack_flag_cnt, 
urg_flag_cnt, down_up_ratio, pkt_size_avg, init_fwd_win_byts, init_bwd_win_byts
```
* **Required Dtype:** Numerical (`float32`, `float64`, `int32`, `int64`). Member 2 automatically downcasts `float64` to `float32`.
* **Missing Value Handling:** Infinite values (`inf`, `-inf`) are replaced with `nan`, and rows with `nan` in feature columns are dropped during `clean_dataset()`.

---

## 4. Exact JSON Outputs Produced by Member 2

Member 2's primary output contract is the case bundle exported to `outputs/incident_cases.json`, accompanied by `outputs/forensic_merkle_certificate.json`.

### 4.1 How Member 2 References Flows
* **Strict Flow ID Referencing:** Flows are **never referenced by row index or integer position**.
* Every alert, graph edge, causal chain step, and Merkle leaf references the exact string `flow_id` (e.g. `"flw_001928"` or `"flw_scan_0042"`).
* Downstream reasoning agents (Member 3) validate that all narrative citations match this exact pattern: `[E:<flow_id>]`.

### 4.2 Schema Structure of `outputs/incident_cases.json`

```json
{
  "version": "1.0",
  "generator": "EviGraph Member 2 (Detection & Graph Engine)",
  "generated_at": "ISO-8601 UTC Timestamp",
  "total_incidents": "int",
  "merkle_root": "64-character SHA-256 hex string",
  "merkle_leaves_count": "int",
  "cryptographic_standard": "SHA-256 Binary Merkle Tree (RFC 6962)",
  "causal_provenance_engine": "Lamport Temporal DAG & MITRE FSM v1.0",
  "incidents": [
    {
      "incident_id": "string (e.g. 'INC-0001')",
      "incident_score": "float (0.0 to 1.0, weighted composite severity)",
      "status": "string ('candidate')",
      "suspected_entry_point": "string (IPv4/IPv6 address of earliest alert source)",
      "start_time": "ISO-8601 string",
      "end_time": "ISO-8601 string",
      "duration_seconds": "float",
      "total_alerts": "int",
      "affected_hosts": ["list of IP strings"],
      "attack_classes": ["list of predicted attack families"],
      "evidence_flow_ids": ["list of flow_id strings"],
      "evidence_files": ["list of evidence_id strings"],
      "subgraph": {
        "node_count": "int",
        "edge_count": "int",
        "nodes": [
          {
            "id": "string (host IP)",
            "role": "string ('attacker' | 'victim' | 'context_host')",
            "in_degree": "int",
            "out_degree": "int",
            "fan_out": "int",
            "alerts_sent": "int",
            "alerts_received": "int"
          }
        ],
        "edges": [
          {
            "edge_id": "string (matches flow_id)",
            "source": "string (source host IP)",
            "target": "string (destination host IP)",
            "timestamp": "ISO-8601 string",
            "dst_port": "int",
            "protocol": "int",
            "risk_score": "float (0.0 to 1.0)",
            "predicted_class": "string",
            "is_alert": "bool",
            "shap_explanation": [
              {
                "feature": "string (top contributing feature name)",
                "importance": "float (absolute TreeSHAP value)"
              }
            ],
            "merkle_leaf_hash": "64-character SHA-256 string",
            "merkle_verified": "bool (true)"
          }
        ]
      },
      "causal_provenance": {
        "causal_dag_nodes_count": "int",
        "causal_dag_edges_count": "int",
        "root_cause_entry_flow": "string (flow_id of initial breach)",
        "campaign_duration_seconds": "float",
        "primary_attack_chain": [
          {
            "step": "int (1-indexed order)",
            "flow_id": "string",
            "source": "string (source host IP)",
            "target": "string (destination host IP)",
            "timestamp": "ISO-8601 string",
            "dst_port": "int",
            "predicted_class": "string",
            "attack_stage": "string ('Reconnaissance' | 'Initial Access' | 'Credential Access' | 'Lateral Movement' | 'Command and Control' | 'Exfiltration & Impact')",
            "risk_score": "float",
            "transition": "string (e.g. 'Campaign Expansion')",
            "latency_seconds": "float",
            "causal_confidence": "float"
          }
        ],
        "causal_edges": [
          {
            "source_flow": "string (flow_id)",
            "target_flow": "string (flow_id)",
            "transition": "string",
            "latency_seconds": "float",
            "causal_confidence": "float",
            "is_pivot": "bool"
          }
        ]
      },
      "primary_attack_chain": "alias to causal_provenance.primary_attack_chain",
      "root_cause_flow": "string (flow_id)"
    }
  ]
}
```

### 4.3 Schema Structure of `outputs/forensic_merkle_certificate.json`

```json
{
  "version": "1.0",
  "standard": "RFC-6962 Merkle Audit Path",
  "hash_algorithm": "SHA-256",
  "session_merkle_root": "64-character hex string",
  "total_telemetry_leaves": "int",
  "tree_depth": "int",
  "generated_at": "ISO-8601 string",
  "incident_evidence_proofs": {
    "INC-0001": [
      {
        "flow_id": "string",
        "leaf_hash": "64-character hex string",
        "leaf_index": "int",
        "root_hash": "64-character hex string",
        "canonical_repr": "flow_id=...|src_ip=...|dst_ip=...|src_port=...|dst_port=...|protocol=...|timestamp=...",
        "proof_steps": [
          {
            "sibling_hash": "64-character hex string",
            "position": "left | right"
          }
        ]
      }
    ]
  }
}
```

---

## 5. Schema Comparison: "Member 2 Expects" vs "Canonical Schema Planned by Member 1"

The table below contrasts Member 2's expectations against the planned canonical pipeline schema (based on `ARCHITECTURE.md` Section 3.1 & standard Zeek/NetFlow fields):

| Field / Feature | Member 2 Expected Name | Member 2 Expected Dtype | Canonical Schema Planned (Member 1) | Mismatch Status & Resolution |
| :--- | :--- | :--- | :--- | :--- |
| **Flow Identifier** | `flow_id` | `string` | `flow_id` (`string`) | **Match**. Must be unique per flow. |
| **Capture Identifier**| `evidence_id` | `string` | `evidence_id` (`string`) | **Match**. Member 1 must supply SHA-256 hash or file stem. |
| **Timestamp** | `timestamp` | `datetime64` / ISO string | `timestamp` (ISO-8601 string) | **Match**. Member 1 will output UTC ISO-8601 strings. |
| **Source IP** | `src_ip` | `string` | `src_ip` (`string`) | **Match**. Standard IPv4/IPv6 string. |
| **Destination IP** | `dst_ip` | `string` | `dst_ip` (`string`) | **Match**. Standard IPv4/IPv6 string. |
| **Source Port** | `src_port` | `int32` / `int64` | `src_port` (`int32`) | **Match**. Transport layer port (0–65535). |
| **Destination Port** | `dst_port` | `int32` / `int64` | `dst_port` (`int32`) | **Match**. Transport layer port (0–65535). |
| **Protocol** | `protocol` | `int32` (`6`=TCP, `17`=UDP) | `protocol` (`int32` or `string`?) | **Potential Mismatch**. Member 2 expects **integer IANA protocol numbers** (`6`, `17`, `1`). If Member 1 emits `"TCP"` or `"UDP"`, Member 2's int cast throws `ValueError`. |
| **Ground Truth Label**| `label` | `string` (`BENIGN` or attack) | `label` (`string`) | **Match**. Normal traffic must be strictly named `"BENIGN"`. |
| **Forward Bytes** | `tot_len_fwd_pkts` vs `totlen_fwd_pkts` | `float32` | `tot_len_fwd_pkts` (`float32`) | **CRITICAL INTERNAL MISMATCH IN MEMBER 2**. `src/data_loader.py` maps to `totlen_fwd_pkts`, but `config.py`, `ARCHITECTURE.md`, and `graph_engine.py` expect `tot_len_fwd_pkts`. In `gnn_detector.py` line 102, it looks only for `totlen_fwd_pkts`. Member 1 should emit `tot_len_fwd_pkts` and alias `totlen_fwd_pkts` to guarantee compatibility across all submodules. |
| **Backward Bytes** | `tot_len_bwd_pkts` vs `totlen_bwd_pkts` | `float32` | `tot_len_bwd_pkts` (`float32`) | **CRITICAL INTERNAL MISMATCH IN MEMBER 2**. Same as above. Emit both or standardize alias. |
| **Flow Duration** | `flow_duration` | `float32` (microseconds) | `flow_duration` (`float32` or seconds?) | **Scale Mismatch Risk**. Member 2 expects microseconds (CICFlowMeter convention). If Member 1 emits seconds, models will miscalculate. |
| **Forward Packets** | `tot_fwd_pkts` | `int32` / `float32` | `tot_fwd_pkts` (`int32`) | **Match**. Total forward packets count. |
| **Backward Packets** | `tot_bwd_pkts` | `int32` / `float32` | `tot_bwd_pkts` (`int32`) | **Match**. Total backward packets count. |
| **Flow Byte Rate** | `flow_bytes_s` vs `flow_byts_s` | `float32` | `flow_bytes_s` (`float32`) | **Internal Mismatch in Member 2**. `COLUMN_CANONICAL_MAP` produces `flow_byts_s`, but `CANONICAL_FEATURES` specifies `flow_bytes_s`. |
| **Flow Packet Rate** | `flow_pkts_s` | `float32` | `flow_pkts_s` (`float32`) | **Match**. |
| **TCP Flag Counts** | `syn_flag_cnt`, `fin_flag_cnt`, `rst_flag_cnt`, `ack_flag_cnt`, `psh_flag_cnt`, `urg_flag_cnt` | `int32` / `float32` | `syn_flag_cnt`, etc. | **Match**. |
| **Window Sizes** | `init_fwd_win_byts`, `init_bwd_win_byts` | `int32` / `float32` | `init_fwd_win_byts`, `init_bwd_win_byts` | **Match**. |
| **Additional Metadata**| `sensor_id`, `interface`, `vlan` | Not in `METADATA_COLS` | Extended telemetry fields | **Leakage Danger**. If Member 1 adds numeric columns not registered in `METADATA_COLS`, Member 2 treats them as training features! |

---

## 6. Discovered Inconsistencies & Open Questions

### Open Questions:
1. **Packet Length Naming Resolution:** Should Member 1 output `tot_len_fwd_pkts` (as in `ARCHITECTURE.md` and `config.py`) or `totlen_fwd_pkts` (as in `COLUMN_CANONICAL_MAP` and `gnn_detector.py`)?
   * *Recommendation for Member 1:* Include both columns (`tot_len_fwd_pkts` and an identical alias `totlen_fwd_pkts`) in the output DataFrame/Parquet so neither GNN nor tabular detectors fail.
2. **Protocol Representation:** Does Member 1's capture pipeline produce string protocol names (`"TCP"`, `"UDP"`, `"ICMP"`) or integer IANA protocol numbers (`6`, `17`, `1`)?
   * *Contract Requirement:* Member 1 must provide integer IANA codes in `protocol`.
3. **Flow Duration Units:** Are flow durations measured in microseconds (CICFlowMeter convention: $\sim 10^5 \mu s$) or seconds ($0.15s$)?
   * *Contract Requirement:* Member 2 models are calibrated on microseconds. Member 1 must output microseconds or apply an explicit scale conversion.
4. **Extra Telemetry Metadata Columns:** If Member 1 introduces additional metadata fields (e.g. `interface`, `vlan_id`, `country_code`, `sensor_id`), Member 2's `METADATA_COLS` list must be updated prior to model retraining to prevent numeric metadata from leaking into feature vectors.
5. **Format Choice for Data Hand-off:** Both Parquet and CSV work, but Parquet is strongly recommended: it preserves `float32` casting and loads in $<2$ seconds versus $45$ seconds for CSV.
