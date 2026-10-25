"""
Hypothesis & Property-Based Tests for Deterministic Flow ID Generation (Canonical v1.1)
Covers:
- same input -> same IDs
- row shuffle -> same ID per flow
- unique IDs
- different evidence hash -> different IDs
- collision check
"""

import pandas as pd
import pytest
from hypothesis import HealthCheck, given
from hypothesis import settings as hyp_settings
from hypothesis import strategies as st

from data.flow_id import (
    make_flow_ids,
)


def test_make_flow_ids_same_input_same_ids():
    """Same input DataFrame and evidence SHA-256 produces identical flow IDs."""
    df = pd.DataFrame([
        {
            "src_ip": "192.168.10.5",
            "src_port": 52340,
            "dst_ip": "10.0.0.1",
            "dst_port": 443,
            "protocol": 6,
            "ts_start": "2026-10-18T10:00:00Z",
            "feat_duration": 100.0
        },
        {
            "src_ip": "192.168.10.5",
            "src_port": 52342,
            "dst_ip": "10.0.0.1",
            "dst_port": 80,
            "protocol": 6,
            "ts_start": "2026-10-18T10:00:05Z",
            "feat_duration": 250.0
        }
    ])
    ev_sha = "a" * 64
    ids1 = make_flow_ids(df, ev_sha)
    ids2 = make_flow_ids(df, ev_sha)

    assert (ids1 == ids2).all()
    assert all(fid.startswith("flw_") for fid in ids1)
    assert all(len(fid) == 20 for fid in ids1)  # "flw_" (4) + 16 hex chars = 20


def test_make_flow_ids_row_shuffle_order_invariance():
    """Row shuffle does not change the generated ID for any flow."""
    records = [
        {
            "src_ip": f"192.168.1.{i}",
            "src_port": 10000 + i,
            "dst_ip": "10.0.0.5",
            "dst_port": 443,
            "protocol": 6,
            "ts_start": f"2026-10-18T10:00:{i:02d}Z",
            "feat_bytes": float(i * 100)
        }
        for i in range(10)
    ]
    df = pd.DataFrame(records)
    ev_sha = "b" * 64

    original_ids = make_flow_ids(df, ev_sha)

    # Shuffle DataFrame randomly
    shuffled_df = df.sample(frac=1.0, random_state=42)
    shuffled_ids = make_flow_ids(shuffled_df, ev_sha)

    # For each row by index, the ID must be strictly identical
    for idx in df.index:
        assert original_ids.loc[idx] == shuffled_ids.loc[idx]


def test_make_flow_ids_different_evidence_hash_different_ids():
    """Different evidence hashes produce completely distinct IDs for identical flow records."""
    df = pd.DataFrame([
        {
            "src_ip": "192.168.1.10",
            "src_port": 50000,
            "dst_ip": "8.8.8.8",
            "dst_port": 53,
            "protocol": 17,
            "ts_start": "2026-10-18T12:00:00Z"
        }
    ])
    ev_sha1 = "1" * 64
    ev_sha2 = "2" * 64

    id1 = make_flow_ids(df, ev_sha1).iloc[0]
    id2 = make_flow_ids(df, ev_sha2).iloc[0]

    assert id1 != id2


def test_make_flow_ids_unique_and_collision_check():
    """Generated flow IDs must be unique across all rows in a capture."""
    records = [
        {
            "src_ip": "192.168.1.10",
            "src_port": 50000 + i,
            "dst_ip": "8.8.8.8",
            "dst_port": 53,
            "protocol": 17,
            "ts_start": "2026-10-18T12:00:00Z"
        }
        for i in range(25)
    ]
    df = pd.DataFrame(records)
    ids = make_flow_ids(df, "c" * 64)

    assert len(ids) == len(set(ids))
    assert len(ids) == 25


@pytest.mark.parametrize(
    ("removed_column", "message"),
    [
        ("src_ip", "Missing required network metadata column 'src_ip'"),
        ("timestamp", "requires 'ts_start' or 'timestamp'"),
    ],
)
def test_make_flow_ids_rejects_missing_required_metadata(removed_column, message):
    df = pd.DataFrame(
        [
            {
                "src_ip": "192.0.2.1",
                "dst_ip": "198.51.100.2",
                "src_port": 50000,
                "dst_port": 443,
                "protocol": 6,
                "timestamp": "2026-10-18T10:00:00Z",
            }
        ]
    ).drop(columns=[removed_column])

    with pytest.raises(ValueError, match=message):
        make_flow_ids(df, "e" * 64)


@given(
    src_ip=st.ip_addresses().map(str),
    dst_ip=st.ip_addresses().map(str),
    src_port=st.integers(min_value=0, max_value=65535),
    dst_port=st.integers(min_value=0, max_value=65535),
    protocol=st.sampled_from([1, 6, 17]),
    ts_offset=st.integers(min_value=0, max_value=1000)
)
@hyp_settings(max_examples=30, suppress_health_check=[HealthCheck.too_slow])
def test_hypothesis_make_flow_ids_properties(src_ip, dst_ip, src_port, dst_port, protocol, ts_offset):
    """Hypothesis property test asserting stability, prefix, length, and determinism."""
    df = pd.DataFrame([
        {
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "protocol": protocol,
            "ts_start": f"2026-10-18T10:00:{ts_offset % 60:02d}Z"
        }
    ])
    ev_sha = "d" * 64
    ids = make_flow_ids(df, ev_sha)

    fid = ids.iloc[0]
    assert fid.startswith("flw_")
    assert len(fid) == 20
    # Re-running produces exact same ID
    ids_again = make_flow_ids(df, ev_sha)
    assert ids_again.iloc[0] == fid
