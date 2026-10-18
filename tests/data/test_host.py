"""
Tests for Prompt 7: Host Features Isolation & Single Source of Truth
Verifies:
- Host features go in host_features.parquet ONLY.
- Host features must NEVER appear in the Member-2 view or the flow Parquet.
- In the flow Parquet, feat_* contains ONLY the 35 Member-2 features (plus any extras in FEATURE_COLUMNS in config.py).
- Canonical schema validation rejects host features in flow tables.
"""


import pandas as pd
import pyarrow.parquet as pq
import pytest

from data.config import CANONICAL_FEATURES, FEATURE_COLUMNS
from data.features.flow import FlowFeatureExtractor
from data.features.host import HostFeatureExtractor
from data.schema import (
    FEAT_COLUMNS,
    HOST_FEATURE_COLUMNS,
    canonicalize,
    validate,
)
from data.storage import ParquetStorageEngine


def test_feature_columns_single_source_of_truth():
    """FEATURE_COLUMNS in config.py is the single source of truth for flow features."""
    assert isinstance(FEATURE_COLUMNS, list)
    assert len(FEATURE_COLUMNS) == 35
    assert FEATURE_COLUMNS == CANONICAL_FEATURES
    # feat_* columns match FEATURE_COLUMNS exactly
    assert len(FEAT_COLUMNS) == len(FEATURE_COLUMNS)
    assert all(f"feat_{col}" in FEAT_COLUMNS for col in FEATURE_COLUMNS)


def test_host_features_saved_to_host_features_parquet_only(tmp_path):
    """Host features are extracted and saved to host_features.parquet ONLY."""
    df_flows = pd.DataFrame([
        {
            "flow_id": "flw_001",
            "src_ip": "192.168.1.10",
            "dst_ip": "10.0.0.1",
            "src_port": 54321,
            "dst_port": 80,
            "protocol": 6,
            "tot_len_fwd_pkts": 1500.0,
            "tot_len_bwd_pkts": 3000.0,
            "timestamp": "2026-10-18T10:00:00Z"
        },
        {
            "flow_id": "flw_002",
            "src_ip": "192.168.1.10",
            "dst_ip": "10.0.0.2",
            "src_port": 54322,
            "dst_port": 443,
            "protocol": 6,
            "tot_len_fwd_pkts": 2000.0,
            "tot_len_bwd_pkts": 4000.0,
            "timestamp": "2026-10-18T10:01:00Z"
        },
        {
            "flow_id": "flw_003",
            "src_ip": "10.0.0.1",
            "dst_ip": "192.168.1.10",
            "src_port": 80,
            "dst_port": 54321,
            "protocol": 6,
            "tot_len_fwd_pkts": 500.0,
            "tot_len_bwd_pkts": 1000.0,
            "timestamp": "2026-10-18T10:02:00Z"
        }
    ])

    extractor = HostFeatureExtractor(time_window_secs=300)
    out_file = tmp_path / "host_features.parquet"
    host_df, saved_path = extractor.extract_and_save(df_flows, out_path=out_file)

    assert saved_path == out_file
    assert out_file.exists()

    # Read back saved host features
    table = pq.read_table(out_file)
    saved_cols = set(table.column_names)

    # Must contain host-level behavioral metrics
    assert "host_ip" in saved_cols
    assert "out_degree" in saved_cols
    assert "in_degree" in saved_cols
    assert "fan_out" in saved_cols
    assert "total_bytes" in saved_cols

    # Verify 192.168.1.10 stats
    df_read = table.to_pandas().set_index("host_ip")
    assert "192.168.1.10" in df_read.index
    assert df_read.loc["192.168.1.10", "out_degree"] == 2
    assert df_read.loc["192.168.1.10", "in_degree"] == 1
    assert df_read.loc["192.168.1.10", "fan_out"] == 2


def test_host_features_never_in_flow_parquet_or_member2_view(tmp_path):
    """
    Host features must NEVER appear in the Member-2 view or the flow Parquet.
    In the flow Parquet, feat_* contains only the 35 Member-2 features.
    """
    # Create sample flow with attempts to inject host metrics
    raw_flow = {
        "flow_id": "flw_flow_test_01",
        "evidence_id": "ev_0123456789ab",
        "ts_start": "2026-10-18T10:00:00Z",
        "ts_end": "2026-10-18T10:00:05Z",
        "src_ip": "192.168.1.10",
        "dst_ip": "10.0.0.1",
        "src_port": 50000,
        "dst_port": 80,
        "protocol": 6,
        "duration": 5.0,
        "flow_duration": 5000000,
        "tot_fwd_pkts": 10,
        "tot_bwd_pkts": 20,
        "fwd_bytes": 1000,
        "bwd_bytes": 2000,
        "source_type": "cicids",
        # Attempted injection of host features:
        "out_degree": 5,
        "in_degree": 2,
        "fan_out": 4,
        "total_bytes": 99999,
        "feat_out_degree": 5.0,
        "feat_in_degree": 2.0,
    }
    df = pd.DataFrame([raw_flow])

    # 1. Validation must loudly reject host features in flow tables
    with pytest.raises(ValueError, match="Host features.*detected in flow table"):
        validate(df)

    # 2. Canonicalization must strip host features and unauthorized feat_*
    clean_df = canonicalize(df)
    for host_col in HOST_FEATURE_COLUMNS:
        assert host_col not in clean_df.columns

    assert "feat_out_degree" not in clean_df.columns
    assert "feat_in_degree" not in clean_df.columns

    # 3. Flow Parquet written to disk must contain ONLY the 35 feat_* features
    storage = ParquetStorageEngine(output_dir=tmp_path)
    flow_parquet_path = storage.write_parquet(clean_df, "flows.parquet")

    table = pq.read_table(flow_parquet_path)
    flow_cols = table.column_names

    # Check that NO host features exist in flow parquet
    for host_col in HOST_FEATURE_COLUMNS:
        assert host_col not in flow_cols

    # Check feat_* in flow parquet contains ONLY the 35 Member-2 features
    feat_cols_in_parquet = [c for c in flow_cols if c.startswith("feat_")]
    assert len(feat_cols_in_parquet) == 35
    assert set(feat_cols_in_parquet) == set(FEAT_COLUMNS)

    # 4. Member-2 view via FlowFeatureExtractor
    extractor = FlowFeatureExtractor()
    X_df, meta_df = extractor.extract_features(clean_df)

    # Member-2 X features must have exactly 35 columns matching FEATURE_COLUMNS
    assert list(X_df.columns) == FEATURE_COLUMNS
    for host_col in HOST_FEATURE_COLUMNS:
        assert host_col not in X_df.columns
        assert host_col not in meta_df.columns
