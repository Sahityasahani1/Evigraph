"""
Contract Verification Tests: Member 1 -> Member 2 Integration Contract
Adheres strictly to Prompt 8:
- Tests export_member2() schema compliance and sidecar manifest generation.
- Loads the export with Member 2's own DataLoader.load_dataset() read-only from Evigraph workspace.
- Asserts:
  (a) required metadata exists
  (b) detected feature list equals CANONICAL_FEATURES exactly
  (c) no ValueError on protocol (must be numeric integer, never str)
  (d) flow_ids unique
  (e) query.get_features() reads FEATURE_COLUMNS only
"""

import hashlib
import json

import numpy as np
import pandas as pd
import pyarrow.parquet as pq

# Member 1 Pipeline Imports
from data.adapters import export_member2
from data.config import CANONICAL_FEATURES, FEATURE_COLUMNS
from data.query import QueryAPI

# Member 2 Read-Only Imports from src/
try:
    from src.data_loader import DataLoader
except ImportError:
    from src.data_loader import FlowDataLoader as DataLoader

from src.config import CANONICAL_FEATURES as M2_CANONICAL_FEATURES
from src.config import METADATA_COLS as M2_METADATA_COLS


def create_sample_canonical_dataframe(n_rows: int = 25) -> pd.DataFrame:
    """Creates a sample DataFrame matching Canonical Schema v1.1."""
    rows = []
    base_ts = pd.to_datetime("2026-10-18T10:00:00Z", utc=True)

    labels = ["BENIGN", "DoS-Hulk", "benign", "PortScan", "SSH-Patator"]
    protocols = [6, 17, 6, 6, 1]

    for i in range(n_rows):
        ts_start = base_ts + pd.to_timedelta(i * 10, unit="s")
        dur_sec = 1.5 + (i * 0.1)
        ts_end = ts_start + pd.to_timedelta(dur_sec, unit="s")

        row = {
            "flow_id": f"flw_contract_test_{i:04d}",
            "evidence_id": f"ev_contract_{(i % 3):04d}",
            "ts_start": ts_start,
            "ts_end": ts_end,
            "src_ip": f"192.168.1.{10 + (i % 5)}",
            "dst_ip": f"10.0.0.{1 + (i % 3)}",
            "src_port": 50000 + i,
            "dst_port": 80 if (i % 2 == 0) else 443,
            "protocol": protocols[i % len(protocols)],
            "proto_name": "TCP" if protocols[i % len(protocols)] == 6 else "UDP",
            "duration": dur_sec,
            "fwd_bytes": 1000 + i * 50,
            "bwd_bytes": 2000 + i * 100,
            "fwd_pkts": 10 + i,
            "bwd_pkts": 20 + i,
            "conn_state": "SF",
            "label_raw": labels[i % len(labels)],
            "label_family": "BENIGN" if "benign" in labels[i % len(labels)].lower() else "Attack",
            "source_type": "cicids",
            "zeek_uid": None,
        }

        # Populate all 35 canonical features with realistic values
        for f in CANONICAL_FEATURES:
            if f == "flow_duration":
                row[f"feat_{f}"] = np.float32(dur_sec * 1e6)
            elif "iat" in f:
                row[f"feat_{f}"] = np.float32(5000.0 + i * 100.0)
            elif "pkt_len" in f or "len" in f or "bytes" in f:
                row[f"feat_{f}"] = np.float32(100.0 + i * 10.0)
            elif "flags" in f or "cnt" in f or "pkts" in f:
                row[f"feat_{f}"] = np.float32(1.0 if i % 2 == 0 else 0.0)
            elif f == "down_up_ratio":
                row[f"feat_{f}"] = np.float32(2.0)
            elif f == "pkt_size_avg":
                row[f"feat_{f}"] = np.float32(120.0)
            elif "win" in f:
                row[f"feat_{f}"] = np.float32(65535.0)
            else:
                row[f"feat_{f}"] = np.float32(10.0)

        rows.append(row)

    return pd.DataFrame(rows)


def test_member2_export_contract(tmp_path):
    """
    Validates that export_member2 produces output directly ingestible by Member 2's DataLoader.
    Asserts:
    (a) required metadata exists
    (b) detected feature list equals CANONICAL_FEATURES exactly
    (c) no ValueError on protocol
    (d) flow_ids unique
    """
    sample_df = create_sample_canonical_dataframe(30)
    out_parquet = tmp_path / "member2_benchmark_flows.parquet"

    # Export using Member 1 adapter
    exported_path = export_member2(out_parquet, df=sample_df, split="test")

    assert exported_path == out_parquet
    assert out_parquet.exists()

    # 1. Verify sidecar manifest exists and hash matches
    manifest_path = out_parquet.parent / f"{out_parquet.name}.manifest.json"
    assert manifest_path.exists()
    manifest_data = json.loads(manifest_path.read_text(encoding="utf-8"))

    assert manifest_data["filename"] == out_parquet.name
    assert manifest_data["row_count"] == len(sample_df)
    assert len(manifest_data["column_list"]) == 44  # 9 metadata + 35 canonical features

    actual_sha256 = hashlib.sha256(out_parquet.read_bytes()).hexdigest()
    assert manifest_data["sha256"] == actual_sha256

    # 2. Ingest export using Member 2's own DataLoader (Read-Only)
    m2_loader = DataLoader()
    m2_df = m2_loader.load_dataset(out_parquet)

    assert not m2_df.empty
    assert len(m2_df) == len(sample_df)

    # (a) Assert required metadata exists
    required_metadata = [
        "flow_id",
        "evidence_id",
        "timestamp",
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "protocol",
        "label",
    ]
    for meta_col in required_metadata:
        assert meta_col in m2_df.columns, f"Missing required metadata column: '{meta_col}'"
        assert not m2_df[meta_col].isna().any(), f"Null values found in metadata column '{meta_col}'"

    # Verify timestamp is tz-naive UTC datetime64[ns]
    assert pd.api.types.is_datetime64_any_dtype(m2_df["timestamp"])
    assert getattr(m2_df["timestamp"].dt, "tz", None) is None, "timestamp must be tz-naive UTC"

    # Verify label normalization: case-insensitive 'benign' -> 'BENIGN'
    assert "benign" not in m2_df["label"].values
    assert (m2_df["label"] == "BENIGN").sum() > 0

    # (b) Assert detected feature list equals CANONICAL_FEATURES exactly
    # Member 2 detects features as all numeric columns excluding metadata
    detected_features = [
        c for c in m2_df.columns
        if c not in m2_loader.metadata_cols and pd.api.types.is_numeric_dtype(m2_df[c])
    ]

    assert len(detected_features) == 35
    assert detected_features == list(M2_CANONICAL_FEATURES)
    assert detected_features == list(CANONICAL_FEATURES)

    # Test Member 2's temporal split with the dataset
    (
        X_train, y_train, meta_train,
        X_val, y_val, meta_val,
        X_test, y_test, meta_test
    ) = m2_loader.prepare_temporal_split(m2_df, train_ratio=0.6, val_ratio=0.2)

    assert list(m2_loader.feature_columns) == list(M2_CANONICAL_FEATURES)
    assert list(X_train.columns) == list(M2_CANONICAL_FEATURES)
    assert list(X_val.columns) == list(M2_CANONICAL_FEATURES)
    assert list(X_test.columns) == list(M2_CANONICAL_FEATURES)

    # (c) Assert no ValueError on protocol and valid integer type
    assert pd.api.types.is_integer_dtype(m2_df["protocol"]), (
        f"protocol must be integer, never str! Got {m2_df['protocol'].dtype}"
    )
    assert not m2_df["protocol"].isna().any()
    valid_proto_vals = set(m2_df["protocol"].unique())
    assert valid_proto_vals.issubset({1, 6, 17})

    # (d) Assert flow_ids are unique
    assert m2_df["flow_id"].is_unique, "flow_id column must contain unique values"

    # (e) Assert no numeric column exists outside {ports, protocol, 35 features}
    allowed_numerics = {"src_port", "dst_port", "protocol"} | set(M2_CANONICAL_FEATURES)
    raw_table = pq.read_table(out_parquet)
    raw_df = raw_table.to_pandas()
    numeric_columns = set(raw_df.select_dtypes(include=[np.number]).columns)
    assert numeric_columns == allowed_numerics, (
        f"Unexpected numeric columns found: {numeric_columns - allowed_numerics}"
    )


def test_query_get_features_reads_feature_columns_only():
    """Verifies that QueryAPI.get_features() reads FEATURE_COLUMNS only."""
    sample_df = create_sample_canonical_dataframe(15)
    api = QueryAPI()

    features_df = api.get_features(df=sample_df, unprefixed=True)

    # Must contain only the 35 FEATURE_COLUMNS
    assert list(features_df.columns) == list(FEATURE_COLUMNS)
    assert len(features_df.columns) == 35

    # Zero metadata or host feature leakage
    for meta_col in M2_METADATA_COLS:
        assert meta_col not in features_df.columns

    # Pure float32 and no NaNs or Infs
    assert all(features_df[c].dtype == np.float32 for c in features_df.columns)
    assert not features_df.isna().any().any()
    assert not np.isneginf(features_df.to_numpy()).any()
    assert not np.isposinf(features_df.to_numpy()).any()
