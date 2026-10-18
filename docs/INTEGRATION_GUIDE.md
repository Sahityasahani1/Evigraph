# EviGraph: Downstream Integration & Feature Reference Guide
**Author:** Member 1 (Data & Traffic Pipeline)  
**Target Audience:** Member 2 (Detection & Graph Engine), Member 3 (LLM Forensic Agent), Member 4 (Mitigation & UI Engine)  
**Location:** `data/` package  

This single guide provides everything you need to consume, query, and integrate network flow data, host graph metrics, and forensic evidence in EviGraph.

> [!IMPORTANT]
> **Authoritative Specification:** For complete schema definitions, untrusted fields policies, security boundaries, and QueryAPI JSON schemas, refer to the [EviGraph Data Contract v1.1](file:///c:/coding/college/CN%20Project/Evigraph/docs/DATA_CONTRACT.md).
> For performance benchmarks on 100k flows and 2.8M-row scaling analysis, see [Pipeline Performance Benchmarks](file:///c:/coding/college/CN%20Project/Evigraph/docs/benchmarks.md).

---

## 1. Quick Start Cheat Sheet

```python
# 1. Member 2: Load ready-to-train datasets
from pathlib import Path
from src.data_loader import FlowDataLoader

loader = FlowDataLoader()
df = loader.load_dataset(Path("data/processed/benchmark_train_flows.parquet"))
X_train, y_train, meta_train, X_val, y_val, meta_val, X_test, y_test, meta_test = (
    loader.prepare_temporal_split(df)
)

# 2. Member 3 & 4: Query indexed telemetry via API
from data.query import QueryAPI

api = QueryAPI()
flow = api.get_flow_by_id("flw_abc1234567890def")
host_history = api.get_flows_for_host("192.168.10.5", limit=500)
features_matrix = api.get_features(limit=1000, unprefixed=True)
sql_df = api.execute_sql("SELECT label, count(*) FROM flows GROUP BY label")

# 3. Cryptographic Chain-of-Custody Verification
from data.evidence import verify_chain
verify_chain()  # Raises IntegrityError if any file or log was tampered with
```

---

## 2. Complete Field & Feature Catalog

### 2.1 The 9 Mandatory Metadata Columns (Every Flow)
These fields are present in every canonical flow table and Member-2 export. **Never use these as tabular ML training features** (to prevent IP/port/timestamp identity leakage):

| Column Name | Type | Description | Example / Allowed Values |
|:---|:---|:---|:---|
| `flow_id` | `str` | Deterministic 16-hex hash identifier | `"flw_a1b2c3d4e5f60718"` |
| `evidence_id` | `str` | Parent capture evidence identifier | `"ev_7f8a9b0c1d2e"` |
| `timestamp` | `datetime64[ns]` | Flow start timestamp (tz-naive UTC) | `2026-10-18 10:00:00` |
| `src_ip` | `str` | Source IPv4 / IPv6 address | `"192.168.10.5"` |
| `dst_ip` | `str` | Destination IPv4 / IPv6 address | `"10.0.0.1"` |
| `src_port` | `int32` | Source transport port `[0, 65535]` | `54321` |
| `dst_port` | `int32` | Destination transport port `[0, 65535]` | `80`, `443`, `22` |
| `protocol` | `int16` | IANA protocol number (never string) | `6` (TCP), `17` (UDP), `1` (ICMP) |
| `label` | `str` | Normalized intrusion detection label | `"BENIGN"`, `"PortScan"`, `"DoS-Hulk"` |

---

### 2.2 The 35 Canonical Flow Features (Model Training Inputs)
All 35 features match CICFlowMeter / CICIDS2017 conventions and `config.py` `CANONICAL_FEATURES`.  
- **Storage name in canonical lake**: prefixed with `feat_` (e.g., `feat_flow_duration`).  
- **Storage name in Member-2 exports**: unprefixed (e.g., `flow_duration`).  
- **Dtype**: `float32`. Guaranteed **zero `NaN`**, **zero `+inf`**, **zero `-inf`**.

| # | Feature Name | Unit | Direction | Description |
|:---|:---|:---|:---|:---|
| 1 | `flow_duration` | $\mu s$ | Bidirectional | Total duration of the network flow in microseconds ($ts_{end} - ts_{start}$) |
| 2 | `tot_fwd_pkts` | count | Forward | Total number of packets transmitted in forward direction (source $\to$ dest) |
| 3 | `tot_bwd_pkts` | count | Backward | Total number of packets transmitted in backward direction (dest $\to$ source) |
| 4 | `tot_len_fwd_pkts` | bytes | Forward | Sum of payload lengths across all forward packets |
| 5 | `tot_len_bwd_pkts` | bytes | Backward | Sum of payload lengths across all backward packets |
| 6 | `fwd_pkt_len_max` | bytes | Forward | Maximum packet length observed in forward direction |
| 7 | `fwd_pkt_len_min` | bytes | Forward | Minimum packet length observed in forward direction |
| 8 | `fwd_pkt_len_mean` | bytes | Forward | Mean packet length observed in forward direction |
| 9 | `fwd_pkt_len_std` | bytes | Forward | Standard deviation of forward packet lengths |
| 10 | `bwd_pkt_len_max` | bytes | Backward | Maximum packet length observed in backward direction |
| 11 | `bwd_pkt_len_min` | bytes | Backward | Minimum packet length observed in backward direction |
| 12 | `bwd_pkt_len_mean` | bytes | Backward | Mean packet length observed in backward direction |
| 13 | `bwd_pkt_len_std` | bytes | Backward | Standard deviation of backward packet lengths |
| 14 | `flow_bytes_s` | bytes/sec | Bidirectional | Flow transmission rate: $\frac{\text{fwd\_bytes} + \text{bwd\_bytes}}{\text{duration\_seconds}}$ |
| 15 | `flow_pkts_s` | pkts/sec | Bidirectional | Flow packet rate: $\frac{\text{fwd\_pkts} + \text{bwd\_pkts}}{\text{duration\_seconds}}$ |
| 16 | `flow_iat_mean` | $\mu s$ | Bidirectional | Mean inter-arrival time between consecutive packets in the flow |
| 17 | `flow_iat_std` | $\mu s$ | Bidirectional | Standard deviation of packet inter-arrival times |
| 18 | `flow_iat_max` | $\mu s$ | Bidirectional | Maximum packet inter-arrival time in the flow |
| 19 | `flow_iat_min` | $\mu s$ | Bidirectional | Minimum packet inter-arrival time in the flow |
| 20 | `fwd_iat_tot` | $\mu s$ | Forward | Sum of all forward packet inter-arrival times |
| 21 | `bwd_iat_tot` | $\mu s$ | Backward | Sum of all backward packet inter-arrival times |
| 22 | `fwd_psh_flags` | count | Forward | Number of forward packets with TCP PSH flag set |
| 23 | `bwd_psh_flags` | count | Backward | Number of backward packets with TCP PSH flag set |
| 24 | `fwd_urg_flags` | count | Forward | Number of forward packets with TCP URG flag set |
| 25 | `bwd_urg_flags` | count | Backward | Number of backward packets with TCP URG flag set |
| 26 | `fin_flag_cnt` | count | Bidirectional | Total packets in flow with TCP FIN flag set |
| 27 | `syn_flag_cnt` | count | Bidirectional | Total packets in flow with TCP SYN flag set |
| 28 | `rst_flag_cnt` | count | Bidirectional | Total packets in flow with TCP RST flag set |
| 29 | `psh_flag_cnt` | count | Bidirectional | Total packets in flow with TCP PSH flag set |
| 30 | `ack_flag_cnt` | count | Bidirectional | Total packets in flow with TCP ACK flag set |
| 31 | `urg_flag_cnt` | count | Bidirectional | Total packets in flow with TCP URG flag set |
| 32 | `down_up_ratio` | ratio | Bidirectional | Ratio of backward packets to forward packets: $\frac{\text{tot\_bwd\_pkts}}{\text{tot\_fwd\_pkts}}$ |
| 33 | `pkt_size_avg` | bytes | Bidirectional | Average packet size across all packets in the flow |
| 34 | `init_fwd_win_byts` | bytes | Forward | Initial TCP window advertisement byte count in forward direction |
| 35 | `init_bwd_win_byts` | bytes | Backward | Initial TCP window advertisement byte count in backward direction |

---

### 2.3 Host Behavioral Graph Features (`host_features.parquet` ONLY)
> **CRITICAL RULE (Prompt 7):** Host features live in `data/processed/host_features.parquet` ONLY. They are strictly excluded from flow tables and Member-2 training sets to prevent topological target leakage.

| Feature Name | Type | Description | Use Case in Architecture |
|:---|:---|:---|:---|
| `host_ip` | `str` | Unique IP address of the host (primary key) | Host node identifier in graph |
| `out_degree` | `int64` | Total outbound flow connections initiated | Identifies scanning/brute-force sources |
| `in_degree` | `int64` | Total inbound flow connections received | Identifies targeted servers / victims |
| `fan_out` | `int64` | Count of unique destination IPs contacted | Measures lateral movement / propagation |
| `fan_in` | `int64` | Count of unique source IPs communicating with host | Measures distributed attacks (DDoS) |
| `unique_dst_ports` | `int64` | Count of distinct destination ports targeted | Detects horizontal port scans |
| `unique_services_hosted`| `int64` | Count of distinct listening ports receiving traffic | Host attack surface enumeration |
| `bytes_sent` | `int64` | Total bytes transmitted across all outbound flows | Exfiltration volume detection |
| `bytes_recv` | `int64` | Total bytes received across all inbound flows | Ingestion / payload reception volume |
| `flows_initiated` | `int64` | Total flow objects originating from this host | Connection creation rate |
| `flows_received` | `int64` | Total flow objects terminating at this host | Inbound connection load |
| `in_out_degree_ratio` | `float64`| $\frac{\text{in\_degree}}{\text{out\_degree}}$ | Differentiates clients from servers |
| `total_bytes` | `int64` | $\text{bytes\_sent} + \text{bytes\_recv}$ | Aggregate communication volume |
| `log_total_bytes` | `float64`| $\ln(1 + \text{total\_bytes})$ | Normalized logarithmic volume feature |
| `total_degree` | `int64` | $\text{out\_degree} + \text{in\_degree}$ | Total node degree in communication graph |

---

### 2.4 Correlated Auxiliary Event Tables (Metadata Join)
Generated when parsing Zeek or PCAP metadata captures:

#### A. DNS Events (`data/processed/dns_events.parquet`)
- `flow_id`: joined to parent flow.
- `ts`: event timestamp.
- `host`: requesting client IP.
- `query`: queried domain (e.g. `api.malicious-c2.com`, sanitized).
- `qtype_name`: DNS record type (`A`, `AAAA`, `PTR`, `TXT`).
- `rcode_name`: DNS response code (`NOERROR`, `NXDOMAIN`, `SERVFAIL`).

#### B. HTTP Events (`data/processed/http_events.parquet`)
- `flow_id`: joined to parent flow.
- `ts`: event timestamp.
- `host`: Host header.
- `method`: HTTP method (`GET`, `POST`, `PUT`, `CONNECT`).
- `uri`: request URI path (sanitized, $\le 256$ chars).
- `user_agent`: User-Agent header string.
- `status_code`: response status code (`200`, `404`, `500`).

#### C. TLS/SSL Events (`data/processed/tls_events.parquet`)
- `flow_id`: joined to parent flow.
- `ts`: event timestamp.
- `server_name` / `sni`: Server Name Indication hostname.
- `ja3`: JA3 client fingerprint hash (32-hex MD5).
- `ja3s`: JA3S server fingerprint hash.

---

## 3. How to Use & Integrate (By Team Role)

### For Member 2 (Detection & Graph Engine)

#### Step 1: Export or Load Data
Member 1 provides datasets formatted precisely for your models via `export_member2()`:
```python
from data.adapters import export_member2

# Export benchmark splits into data/processed/
export_member2("data/processed/benchmark_flows.parquet")
```

#### Step 2: Load with your `FlowDataLoader`
```python
from pathlib import Path
from src.data_loader import FlowDataLoader

loader = FlowDataLoader()
df = loader.load_dataset(Path("data/processed/benchmark_flows.parquet"))

# Clean temporal train (60%), val (20%), test (20%) split
(
    X_train, y_train, meta_train,
    X_val, y_val, meta_val,
    X_test, y_test, meta_test
) = loader.prepare_temporal_split(df)
```
- **Guarantees for Member 2**:
  1. `X_train.columns` will contain **exactly the 35 features** in `CANONICAL_FEATURES` (0 missing, 0 extra).
  2. `meta_train` contains `flow_id`, `timestamp`, `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`, and `evidence_id` for building host communication graph edges.
  3. `protocol` is integer (never string).
  4. `timestamp` is tz-naive datetime.
  5. `flow_id` is guaranteed unique.

#### Step 3: Access Host Graph Features
When building Graph Neural Network (GNN) node attributes or host communication graphs:
```python
import pandas as pd

# Load host behavioral metrics
host_features_df = pd.read_parquet("data/processed/host_features.parquet")
# Index is host_ip, columns include out_degree, in_degree, fan_out, etc.
```

---

### For Member 3 (LLM Forensic Reasoning Agent & RAG)

You need to investigate incidents, look up attacker flows, and inspect evidence. Use `QueryAPI`:

```python
from data.query import QueryAPI

api = QueryAPI()

# 1. Look up exact flow telemetry from an alert
flow_data = api.get_flow_by_id("flw_abc1234567890def")
# Returns dict: {'flow_id': ..., 'src_ip': '192.168.10.5', 'dst_port': 80, 'duration': 1.25, ...}

# 2. Reconstruct host activity (Blast Radius)
host_traffic = api.get_flows_for_host("192.168.10.5", limit=100)

# 3. Inspect communication between attacker and victim
pivot_traffic = api.get_flows_between("192.168.10.5", "10.0.0.1")

# 4. Temporal timeline query around an alert timestamp
window_traffic = api.get_flows_in_window("2026-10-18 10:00:00", "2026-10-18 10:05:00")

# 5. Extract uncorrupted float32 feature vectors for model explainability (SHAP / RAG context)
features_df = api.get_features(limit=500, unprefixed=True)

# 6. Execute direct zero-copy SQL analytics in DuckDB
attack_summary = api.execute_sql("""
    SELECT label, COUNT(*) AS total_flows, AVG(duration) AS avg_duration_sec
    FROM flows
    GROUP BY label
    ORDER BY total_flows DESC
""")
```

---

### For Member 4 (Mitigation, Countermeasures & UI)

You need to verify cryptographic integrity, isolate compromised hosts, and display incident timelines:

#### 1. Cryptographic Audit & Evidence Chain Verification
Prove to investigators that zero logs or raw PCAP files were altered:
```python
from data.evidence import verify_chain

try:
    verify_chain()
    print("Evidence verified: 100% cryptographically untampered.")
except Exception as e:
    print(f"Tamper alert! Violation detected: {e}")
```

#### 2. Querying Targets for Firewall Countermeasures
```python
from data.query import QueryAPI

api = QueryAPI()
# Get all distinct external ports contacted by compromised host to generate surgical firewall rules
quarantine_targets = api.execute_sql("""
    SELECT DISTINCT dst_ip, dst_port, proto_name
    FROM flows
    WHERE src_ip = '192.168.10.5' AND label != 'BENIGN'
""")
```

---

## 4. CLI Commands Cheat Sheet

The pipeline comes with a built-in CLI:

```bash
# 1. Ingest any capture file (.pcap, .csv, .log) into the evidence vault and Parquet lake
python -m data.cli ingest path/to/capture.pcap
python -m data.cli ingest path/to/cicids_flows.csv --format cicids
python -m data.cli ingest path/to/conn.log --format zeek

# 2. Cryptographic audit chain and file integrity verification
python -m data.cli verify

# 3. View indexed dataset summary and class distribution
python -m data.cli summary

# 4. Run instant SQL queries against the DuckDB catalog
python -m data.cli query "SELECT label, COUNT(*) FROM flows GROUP BY label"

# 5. Export stratified Train (60%) / Val (20%) / Test (20%) splits for Member 2
python -m data.cli export-splits --prefix benchmark
```

---

## 5. Common Gotchas & Golden Rules

1. **Protocol is ALWAYS Integer**:
   - `protocol` is `6` (TCP), `17` (UDP), `1` (ICMP). It is never `"TCP"` or `"UDP"` in the flow tables (use `proto_name` if you need the string name).
2. **Durations vs Microseconds**:
   - In the flow table, the canonical column `duration` is in **seconds** (`float64`).
   - The ML model feature `flow_duration` and all `*_iat_*` columns are in **microseconds** ($\mu s$, `float32`).
3. **Host Features vs Flow Features**:
   - Never merge host features (`in_degree`, `fan_out`, etc.) into `flows.parquet`. The schema validator will reject it. Always read `host_features.parquet` separately.
4. **Timestamps**:
   - Always formatted as tz-naive UTC `datetime64[ns]`.
5. **Sidecar Manifests**:
   - Every exported parquet file has a companion `<filename>.manifest.json` containing its exact row count, column list, and file SHA-256 for audit tracking.
