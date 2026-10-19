"""
Tests for Canonical Schema v1.1 & Validation
Covers:
- PyArrow Schema fields, order, and datatypes
- validate(df): dtypes, non-null keys, ports 0-65535, non-negative counts, ts_end >= ts_start
- protocol is integer (never str!) in {1, 6, 17} or documented other
- 35 feat_* features float32
- Hypothesis property testing on validation constraints
"""

import numpy as np
import pandas as pd
import pytest
from hypothesis import given
from hypothesis import settings as hyp_settings
from hypothesis import strategies as st

from data.schema import (
    CANONICAL_COLUMN_NAMES,
    CANONICAL_SCHEMA,
    FEAT_COLUMNS,
    canonicalize,
    validate,
)


def make_valid_canonical_row(**overrides) -> dict:
    """Helper creating a single valid row conforming to Canonical Schema v1.1."""
    row = {
        "flow_id": "flw_0123456789abcdef",
        "evidence_id": "ev_0123456789ab",
        "ts_start": pd.to_datetime("2026-10-18T10:00:00Z", utc=True),
        "ts_end": pd.to_datetime("2026-10-18T10:00:05Z", utc=True),
        "src_ip": "192.168.1.10",
        "dst_ip": "10.0.0.1",
        "src_port": 52340,
        "dst_port": 443,
        "protocol": 6,
        "proto_name": "TCP",
        "duration": 5.0,
        "fwd_bytes": 1500,
        "bwd_bytes": 4500,
        "fwd_pkts": 10,
        "bwd_pkts": 15,
        "conn_state": "SF",
        "label_raw": "BENIGN",
        "label_family": "BENIGN",
        "source_type": "zeek",
        "zeek_uid": "C12345"
    }
    for f in FEAT_COLUMNS:
        row[f] = np.float32(0.0)
    row.update(overrides)
    return row


def test_canonical_schema_pyarrow_structure():
    """Verify exact column ordering and datatypes in CANONICAL_SCHEMA."""
    assert len(CANONICAL_SCHEMA) == 20 + 35  # 20 metadata/base + 35 feat_*
    assert CANONICAL_COLUMN_NAMES[0] == "flow_id"
    assert CANONICAL_COLUMN_NAMES[1] == "evidence_id"
    assert CANONICAL_COLUMN_NAMES[2] == "ts_start"
    assert CANONICAL_COLUMN_NAMES[3] == "ts_end"
    assert CANONICAL_COLUMN_NAMES[4] == "src_ip"
    assert CANONICAL_COLUMN_NAMES[5] == "dst_ip"
    assert CANONICAL_COLUMN_NAMES[6] == "src_port"
    assert CANONICAL_COLUMN_NAMES[7] == "dst_port"
    assert CANONICAL_COLUMN_NAMES[8] == "protocol"
    assert CANONICAL_COLUMN_NAMES[9] == "proto_name"
    assert CANONICAL_COLUMN_NAMES[10] == "duration"
    assert CANONICAL_COLUMN_NAMES[11] == "fwd_bytes"
    assert CANONICAL_COLUMN_NAMES[12] == "bwd_bytes"
    assert CANONICAL_COLUMN_NAMES[13] == "fwd_pkts"
    assert CANONICAL_COLUMN_NAMES[14] == "bwd_pkts"
    assert CANONICAL_COLUMN_NAMES[18] == "source_type"

    # All 35 feat_* columns exist
    for f in FEAT_COLUMNS:
        assert f in CANONICAL_COLUMN_NAMES
        assert CANONICAL_SCHEMA.field(f).type == "float"


def test_validate_valid_dataframe():
    """Valid DataFrame passes validation."""
    df = pd.DataFrame([make_valid_canonical_row()])
    assert validate(df) is True


def test_validate_protocol_never_str():
    """String protocol must strictly fail with TypeError."""
    row = make_valid_canonical_row()
    row["protocol"] = "TCP"  # string protocol
    df = pd.DataFrame([row])

    with pytest.raises(TypeError) as exc_info:
        validate(df)
    assert "protocol must be integer, never str" in str(exc_info.value)


def test_validate_ports_range():
    """Ports outside [0, 65535] must fail validation."""
    row = make_valid_canonical_row(src_port=70000)
    df = pd.DataFrame([row])
    with pytest.raises(ValueError) as exc_info:
        validate(df)
    assert "out of range [0, 65535]" in str(exc_info.value)


def test_validate_non_negative_counts():
    """Negative packet or byte counts must fail validation."""
    row = make_valid_canonical_row(fwd_bytes=-5)
    df = pd.DataFrame([row])
    with pytest.raises(ValueError) as exc_info:
        validate(df)
    assert "cannot be negative" in str(exc_info.value)


def test_validate_temporal_order():
    """ts_end < ts_start must fail validation."""
    t1 = pd.to_datetime("2026-10-18T10:05:00Z", utc=True)
    t0 = pd.to_datetime("2026-10-18T10:00:00Z", utc=True)
    row = make_valid_canonical_row(ts_start=t1, ts_end=t0)
    df = pd.DataFrame([row])

    with pytest.raises(ValueError) as exc_info:
        validate(df)
    assert "ts_end must be >= ts_start" in str(exc_info.value)


def test_validate_mandatory_null_keys():
    """Null values in mandatory key columns must fail validation."""
    row = make_valid_canonical_row(src_ip=None)
    df = pd.DataFrame([row])
    with pytest.raises(ValueError) as exc_info:
        validate(df)
    assert "src_ip" in str(exc_info.value) and "null/NaN" in str(exc_info.value)


def test_canonicalize_populates_feat_columns():
    """canonicalize transforms raw input and populates all 35 feat_* columns."""
    df = pd.DataFrame([{
        "src_ip": "1.1.1.1",
        "dst_ip": "2.2.2.2",
        "src_port": 100,
        "dst_port": 80,
        "protocol": 6,
        "flow_duration": 150000.0,
        "tot_len_fwd_pkts": 500.0,
        "tot_len_bwd_pkts": 1200.0
    }])
    clean = canonicalize(df)
    assert clean["protocol"].iloc[0] == 6
    assert clean["proto_name"].iloc[0] == "TCP"
    assert clean["duration"].iloc[0] == 0.15  # 150000 us -> 0.15 s
    assert clean["feat_flow_duration"].iloc[0] == 150000.0
    assert clean["feat_tot_len_fwd_pkts"].iloc[0] == 500.0
    assert len([c for c in clean.columns if c.startswith("feat_")]) == 35


@given(
    protocol=st.sampled_from([1, 6, 17, 0, 50, 89]),
    src_port=st.integers(min_value=0, max_value=65535),
    dst_port=st.integers(min_value=0, max_value=65535),
    duration=st.floats(min_value=0.0, max_value=1e6)
)
@hyp_settings(max_examples=30)
def test_hypothesis_validate_valid_inputs(protocol, src_port, dst_port, duration):
    """Hypothesis assertions ensuring validate passes on valid bounded ranges."""
    t_start = pd.to_datetime("2026-10-18T10:00:00Z", utc=True)
    t_end = t_start + pd.to_timedelta(duration, unit="s")
    row = make_valid_canonical_row(
        protocol=protocol,
        src_port=src_port,
        dst_port=dst_port,
        duration=duration,
        ts_start=t_start,
        ts_end=t_end
    )
    df = pd.DataFrame([row])
    assert validate(df) is True
