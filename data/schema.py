"""
Canonical Network Flow Schema v1.1
Defines PyArrow schema and validation logic for EviGraph canonical forensic data store.

CANONICAL SCHEMA v1.1 Column Order:
- flow_id: str
- evidence_id: str
- ts_start: timestamp[ns, UTC]
- ts_end: timestamp[ns, UTC]
- src_ip: str
- dst_ip: str
- src_port: int32
- dst_port: int32
- protocol: int16 (IANA: 6, 17, 1)
- proto_name: str
- duration: float64 (SECONDS)
- fwd_bytes: int64
- bwd_bytes: int64
- fwd_pkts: int64
- bwd_pkts: int64
- conn_state: str (nullable)
- label_raw: str (nullable)
- label_family: str (nullable)
- source_type: str ('cicids' | 'zeek' | 'pcap')
- zeek_uid: str (nullable)
- feat_* : float32 (all 35 Member-2 canonical features)
"""

from typing import Dict, List, Set

import numpy as np
import pandas as pd
import pyarrow as pa

from data.config import FEATURE_COLUMNS

# The 35 Member-2 Canonical Feature Names (Single source of truth in config.py)
MEMBER2_FEATURES: List[str] = list(FEATURE_COLUMNS)

# Prefixed with feat_ ONLY in canonical store (matches FEATURE_COLUMNS)
FEAT_COLUMNS: List[str] = [f"feat_{f}" for f in FEATURE_COLUMNS]

# Host feature names that must NEVER appear in flow tables or Member-2 view (Prompt 7)
HOST_FEATURE_COLUMNS: Set[str] = {
    "out_degree",
    "in_degree",
    "fan_out",
    "fan_in",
    "unique_dst_ports",
    "unique_services_hosted",
    "bytes_sent",
    "bytes_recv",
    "flows_initiated",
    "flows_received",
    "in_out_degree_ratio",
    "total_bytes",
    "log_total_bytes",
    "total_degree",
}

# IANA Protocol Number to Name
PROTO_NAME_MAP: Dict[int, str] = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    0: "HOPOPT",
    2: "IGMP",
    47: "GRE",
    50: "ESP",
    51: "AH",
    89: "OSPF",
    132: "SCTP",
}

# Reverse mapping for string inputs
PROTOCOL_STRING_MAP: Dict[str, int] = {
    v: k for k, v in PROTO_NAME_MAP.items()
}
PROTOCOL_MAP: Dict[str, int] = PROTOCOL_STRING_MAP

# Non-nullable mandatory key columns
MANDATORY_KEYS: List[str] = [
    "flow_id",
    "evidence_id",
    "ts_start",
    "ts_end",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "source_type",
]

VALID_SOURCE_TYPES = {"cicids", "zeek", "pcap"}


def build_canonical_arrow_schema() -> pa.Schema:
    """Constructs the canonical PyArrow schema v1.1 with ordered fields."""
    fields = [
        pa.field("flow_id", pa.string(), nullable=False),
        pa.field("evidence_id", pa.string(), nullable=False),
        pa.field("ts_start", pa.timestamp("ns", tz="UTC"), nullable=False),
        pa.field("ts_end", pa.timestamp("ns", tz="UTC"), nullable=False),
        pa.field("src_ip", pa.string(), nullable=False),
        pa.field("dst_ip", pa.string(), nullable=False),
        pa.field("src_port", pa.int32(), nullable=False),
        pa.field("dst_port", pa.int32(), nullable=False),
        pa.field("protocol", pa.int16(), nullable=False),
        pa.field("proto_name", pa.string(), nullable=False),
        pa.field("duration", pa.float64(), nullable=False),
        pa.field("fwd_bytes", pa.int64(), nullable=False),
        pa.field("bwd_bytes", pa.int64(), nullable=False),
        pa.field("fwd_pkts", pa.int64(), nullable=False),
        pa.field("bwd_pkts", pa.int64(), nullable=False),
        pa.field("conn_state", pa.string(), nullable=True),
        pa.field("label_raw", pa.string(), nullable=True),
        pa.field("label_family", pa.string(), nullable=True),
        pa.field("source_type", pa.string(), nullable=False),
        pa.field("zeek_uid", pa.string(), nullable=True),
    ]
    for feat_col in FEAT_COLUMNS:
        fields.append(pa.field(feat_col, pa.float32(), nullable=True))

    return pa.schema(fields)


CANONICAL_SCHEMA: pa.Schema = build_canonical_arrow_schema()
CANONICAL_COLUMN_NAMES: List[str] = CANONICAL_SCHEMA.names


def validate(df: pd.DataFrame) -> bool:
    """
    Validates a DataFrame against Canonical Schema v1.1 constraints:
    - Missing required columns
    - Non-null keys
    - Port ranges [0, 65535]
    - Non-negative byte/packet counts and duration
    - ts_end >= ts_start
    - protocol is integer (never str) in IANA range (0-255), typically {1, 6, 17}
    - source_type in {'cicids', 'zeek', 'pcap'}

    Raises ValueError or TypeError on any violation.
    Returns True on success.
    """
    if df.empty:
        return True

    # 1. Check mandatory key columns presence
    missing_keys = [k for k in MANDATORY_KEYS if k not in df.columns]
    if missing_keys:
        raise ValueError(f"Missing mandatory canonical column(s): {missing_keys}")

    # 2. Check non-null constraints on mandatory keys
    for k in MANDATORY_KEYS:
        if df[k].isna().any():
            null_count = df[k].isna().sum()
            raise ValueError(f"Column '{k}' contains {null_count} null/NaN values; non-null required.")

    # 3. Protocol validation: must be integer, NEVER string
    if not pd.api.types.is_integer_dtype(df["protocol"]):
        raise TypeError(
            f"protocol must be integer, never str! Found dtype: {df['protocol'].dtype}"
        )

    # IANA range check
    proto_vals = df["protocol"]
    if (proto_vals < 0).any() or (proto_vals > 255).any():
        raise ValueError("protocol numbers must be valid 8-bit IANA values in [0, 255].")

    # 4. Port ranges [0, 65535]
    for p_col in ["src_port", "dst_port"]:
        if not pd.api.types.is_integer_dtype(df[p_col]):
            raise TypeError(f"Port column '{p_col}' must be integer type.")
        ports = df[p_col]
        if (ports < 0).any() or (ports > 65535).any():
            invalid = ports[(ports < 0) | (ports > 65535)].iloc[0]
            raise ValueError(f"Port value {invalid} in '{p_col}' out of range [0, 65535].")

    # 5. Non-negative counts and duration
    for count_col in ["fwd_bytes", "bwd_bytes", "fwd_pkts", "bwd_pkts"]:
        if count_col in df.columns:
            if not pd.api.types.is_integer_dtype(df[count_col]):
                raise TypeError(f"Count column '{count_col}' must be integer.")
            if (df[count_col] < 0).any():
                neg = df[count_col][df[count_col] < 0].iloc[0]
                raise ValueError(f"Count column '{count_col}' cannot be negative, got {neg}.")

    if "duration" in df.columns:
        if not pd.api.types.is_numeric_dtype(df["duration"]):
            raise TypeError("duration must be numeric.")
        if (df["duration"] < 0.0).any():
            neg = df["duration"][df["duration"] < 0.0].iloc[0]
            raise ValueError(f"duration cannot be negative, got {neg}.")

    # 6. Temporal constraint: ts_end >= ts_start
    t_start = pd.to_datetime(df["ts_start"], utc=True)
    t_end = pd.to_datetime(df["ts_end"], utc=True)
    if (t_end < t_start).any():
        violations = (t_end < t_start).sum()
        raise ValueError(f"ts_end must be >= ts_start; found {violations} temporal paradoxes.")

    # 7. source_type constraint
    if "source_type" in df.columns:
        invalid_sources = set(df["source_type"].unique()) - VALID_SOURCE_TYPES
        if invalid_sources:
            raise ValueError(
                f"Invalid source_type {invalid_sources}; must be one of {VALID_SOURCE_TYPES}."
            )

    # 8. Feature isolation (Prompt 7): Host features and unauthorized feat_* must never appear in flow tables
    unauthorized_hosts = [c for c in df.columns if c in HOST_FEATURE_COLUMNS]
    if unauthorized_hosts:
        raise ValueError(
            f"Host features {unauthorized_hosts} detected in flow table. "
            "Host features go in host_features.parquet ONLY and must never appear in flow Parquet or Member-2 view."
        )

    unauthorized_feats = [
        c for c in df.columns if c.startswith("feat_") and c not in FEAT_COLUMNS
    ]
    if unauthorized_feats:
        raise ValueError(
            f"Unauthorized feature columns {unauthorized_feats} in flow table. "
            "In the flow Parquet, feat_* contains only features listed in FEATURE_COLUMNS in config.py."
        )

    return True


def parse_protocol_value(val) -> int:
    """Parses protocol value to valid integer (0-255). Handles numeric, string names, and floats."""
    if pd.isna(val):
        return 6
    s = str(val).strip()
    try:
        f = float(s)
        return int(f)
    except ValueError:
        return PROTOCOL_STRING_MAP.get(s.upper(), 6)


def canonicalize(df: pd.DataFrame) -> pd.DataFrame:
    """
    Standardizes a DataFrame into Canonical Schema v1.1.
    Fills default values for missing columns, populates feat_* from un-prefixed features,
    and sorts columns into exact canonical order.
    """
    df = df.copy()

    # Protocol handling: convert string, float, or int to int16 (0-255)
    if "protocol" in df.columns:
        df["protocol"] = df["protocol"].apply(parse_protocol_value).astype("int16")
    else:
        df["protocol"] = np.int16(6)

    # Proto name
    if "proto_name" not in df.columns:
        df["proto_name"] = df["protocol"].map(
            lambda p: PROTO_NAME_MAP.get(int(p), f"PROTO_{p}")
        ).astype(str)
    else:
        df["proto_name"] = df["proto_name"].astype(str)

    # Timestamps
    if "ts_start" in df.columns:
        df["ts_start"] = pd.to_datetime(df["ts_start"], utc=True)
    elif "timestamp" in df.columns:
        df["ts_start"] = pd.to_datetime(df["timestamp"], utc=True)
    else:
        df["ts_start"] = pd.to_datetime("2026-10-18T00:00:00Z", utc=True)

    if "ts_end" in df.columns:
        df["ts_end"] = pd.to_datetime(df["ts_end"], utc=True)
    elif "duration" in df.columns:
        df["ts_end"] = df["ts_start"] + pd.to_timedelta(df["duration"], unit="s")
    elif "flow_duration" in df.columns:
        df["ts_end"] = df["ts_start"] + pd.to_timedelta(df["flow_duration"] / 1e6, unit="s")
    else:
        df["ts_end"] = df["ts_start"]

    # Duration in SECONDS
    if "duration" not in df.columns:
        if "flow_duration" in df.columns:
            df["duration"] = (df["flow_duration"] / 1e6).astype("float64")
        else:
            dur = (df["ts_end"] - df["ts_start"]).dt.total_seconds()
            df["duration"] = np.maximum(0.0, dur).astype("float64")

    # Counts and byte metrics
    if "fwd_pkts" not in df.columns:
        if "tot_fwd_pkts" in df.columns:
            df["fwd_pkts"] = df["tot_fwd_pkts"].fillna(0).astype("int64")
        else:
            df["fwd_pkts"] = pd.Series(0, index=df.index, dtype="int64")
    else:
        df["fwd_pkts"] = df["fwd_pkts"].fillna(0).astype("int64")

    if "bwd_pkts" not in df.columns:
        if "tot_bwd_pkts" in df.columns:
            df["bwd_pkts"] = df["tot_bwd_pkts"].fillna(0).astype("int64")
        else:
            df["bwd_pkts"] = pd.Series(0, index=df.index, dtype="int64")
    else:
        df["bwd_pkts"] = df["bwd_pkts"].fillna(0).astype("int64")

    if "fwd_bytes" not in df.columns:
        if "tot_len_fwd_pkts" in df.columns:
            df["fwd_bytes"] = df["tot_len_fwd_pkts"].fillna(0).astype("int64")
        elif "totlen_fwd_pkts" in df.columns:
            df["fwd_bytes"] = df["totlen_fwd_pkts"].fillna(0).astype("int64")
        else:
            df["fwd_bytes"] = pd.Series(0, index=df.index, dtype="int64")
    else:
        df["fwd_bytes"] = df["fwd_bytes"].fillna(0).astype("int64")

    if "bwd_bytes" not in df.columns:
        if "tot_len_bwd_pkts" in df.columns:
            df["bwd_bytes"] = df["tot_len_bwd_pkts"].fillna(0).astype("int64")
        elif "totlen_bwd_pkts" in df.columns:
            df["bwd_bytes"] = df["totlen_bwd_pkts"].fillna(0).astype("int64")
        else:
            df["bwd_bytes"] = pd.Series(0, index=df.index, dtype="int64")
    else:
        df["bwd_bytes"] = df["bwd_bytes"].fillna(0).astype("int64")

    # Member 2 compatibility aliases for packet lengths
    if "tot_len_fwd_pkts" in df.columns and "totlen_fwd_pkts" not in df.columns:
        df["totlen_fwd_pkts"] = df["tot_len_fwd_pkts"].astype("float32")
    elif "totlen_fwd_pkts" in df.columns and "tot_len_fwd_pkts" not in df.columns:
        df["tot_len_fwd_pkts"] = df["totlen_fwd_pkts"].astype("float32")

    if "tot_len_bwd_pkts" in df.columns and "totlen_bwd_pkts" not in df.columns:
        df["totlen_bwd_pkts"] = df["tot_len_bwd_pkts"].astype("float32")
    elif "totlen_bwd_pkts" in df.columns and "tot_len_bwd_pkts" not in df.columns:
        df["tot_len_bwd_pkts"] = df["totlen_bwd_pkts"].astype("float32")

    if "src_ip" not in df.columns:
        df["src_ip"] = "192.168.10.50"
    if "dst_ip" not in df.columns:
        df["dst_ip"] = "172.16.0.1"
    df["src_port"] = df.get("src_port", 0).fillna(0).astype("int32")
    df["dst_port"] = df.get("dst_port", 0).fillna(0).astype("int32")

    # Source type
    if "source_type" not in df.columns:
        df["source_type"] = "cicids"

    # Optional metadata & label cleaning
    for opt in ["conn_state", "zeek_uid"]:
        if opt not in df.columns:
            df[opt] = None

    if "label_raw" in df.columns:
        df["label_raw"] = (
            df["label_raw"]
            .astype(str)
            .str.replace("\x96", "-", regex=False)
            .str.replace("\u0096", "-", regex=False)
            .str.replace("–", "-", regex=False)
            .str.replace("—", "-", regex=False)
            .str.strip()
        )
    elif "label" in df.columns:
        df["label_raw"] = (
            df["label"]
            .astype(str)
            .str.replace("\x96", "-", regex=False)
            .str.replace("\u0096", "-", regex=False)
            .str.replace("–", "-", regex=False)
            .str.replace("—", "-", regex=False)
            .str.strip()
        )
    else:
        df["label_raw"] = "BENIGN"

    if "label_family" not in df.columns or df["label_family"].isna().all():
        from data.taxonomy import default_taxonomy
        df["label_family"] = default_taxonomy.map_series(df["label_raw"])

    # Prompt 7: Host features go in host_features.parquet ONLY. They must never appear in Member-2 view or flow Parquet.
    # In the flow Parquet, feat_* contains only features in FEATURE_COLUMNS from config.py.
    drop_unauthorized = [
        c for c in df.columns
        if c in HOST_FEATURE_COLUMNS or (c.startswith("feat_") and c not in FEAT_COLUMNS)
    ]
    if drop_unauthorized:
        df = df.drop(columns=drop_unauthorized)

    # Populate canonical feat_* columns
    for f in MEMBER2_FEATURES:
        feat_name = f"feat_{f}"
        if feat_name in df.columns:
            df[feat_name] = df[feat_name].astype("float32")
        elif f in df.columns:
            df[feat_name] = df[f].astype("float32")
        else:
            df[feat_name] = np.float32(0.0)

    # Order columns
    ordered_cols = [c for c in CANONICAL_COLUMN_NAMES if c in df.columns]
    remaining = [
        c for c in df.columns
        if c not in CANONICAL_COLUMN_NAMES and c not in HOST_FEATURE_COLUMNS and not c.startswith("feat_")
    ]
    return df[ordered_cols + remaining]


# Backward compatibility aliases
CANONICAL_ARROW_SCHEMA = CANONICAL_SCHEMA
validate_and_canonicalize = canonicalize
