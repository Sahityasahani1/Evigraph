# EviGraph Network Flow Telemetry & Dataset Catalog

*Generated on: 2026-10-16 18:04:01 UTC*

This document indexes all training, validation, testing, and benchmark telemetry files preserved in `data/`.

## 1. Processed Model Training & Evaluation Splits (`data/processed/`)

| Filename | Type | Total Flows | Size (MB) | Description |
| :--- | :--- | :--- | :--- | :--- |
| `benchmark_full_340k.parquet` | PARQUET | 340,000 | 40.6 MB | Exact FULL partition used in model training |
| `benchmark_test_flows.parquet` | PARQUET | 68,000 | 8.114 MB | Exact TEST partition used in model training |
| `benchmark_test_sample_1000.csv` | CSV | 1,000 | 0.328 MB | Exact TEST partition used in model training |
| `benchmark_train_flows.parquet` | PARQUET | 204,000 | 24.489 MB | Exact TRAIN partition used in model training |
| `benchmark_train_sample_1000.csv` | CSV | 1,000 | 0.331 MB | Exact TRAIN partition used in model training |
| `benchmark_val_flows.parquet` | PARQUET | 68,000 | 8.155 MB | Exact VAL partition used in model training |

## 2. External Benchmark Datasets (`data/new_benchmark/`)

| Filename | Classes Contained | Total Flows | Size (MB) | SHA-256 (Prefix) |
| :--- | :--- | :--- | :--- | :--- |
| `APT-C2-Exfiltration.parquet` | `BENIGN, C2-Heartbeat, Lateral-SMB-Relay, HTTPS-Exfiltration` | 100,000 | 12.9 MB | `f7972b5f6188d2f4...` |
| `CIC-DDoS2019-Reflection.parquet` | `BENIGN, DNS-Amplification, NTP-Reflection, SYN-Flood` | 120,000 | 14.104 MB | `624b59caa31251e2...` |
| `UNSW-NB15-Enterprise.parquet` | `BENIGN, Reconnaissance, Fuzzers, Backdoor` | 120,000 | 15.231 MB | `eb1468d1fa70d018...` |

## 3. Raw Enterprise Captures (`data/raw/`)

| Filename | Total Flows | Size (MB) | SHA-256 (Prefix) |
| :--- | :--- | :--- | :--- |
| `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv.parquet` | 225,745 | 21.98 MB | `7c5876d52189fc01...` |
| `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv.parquet` | 286,467 | 17.769 MB | `4d78cee297c27f1a...` |
| `Monday-WorkingHours.pcap_ISCX.csv.parquet` | 529,918 | 62.433 MB | `dfdcef4b8670e52a...` |
| `NIDS2025-RemoteCE-Infiltration.csv` | 2,125 | 0.963 MB | `fa494b6f310c4c6c...` |
| `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv.parquet` | 458,968 | 18.763 MB | `d8110c04a7af9112...` |
| `Tuesday-WorkingHours.pcap_ISCX.csv.parquet` | 445,909 | 50.26 MB | `27e83d518cb093fa...` |
| `Wednesday-workingHours.pcap_ISCX.csv.parquet` | 692,703 | 72.968 MB | `d23a259820b16e1a...` |

## 4. How to Load These Files in Python

```python
import pandas as pd

# Load exact training split
train_df = pd.read_parquet('data/processed/benchmark_train_flows.parquet')
print(f'Train flows: {len(train_df):,}')

# Load exact held-out test split
test_df = pd.read_parquet('data/processed/benchmark_test_flows.parquet')
print(f'Test flows: {len(test_df):,}')
```
