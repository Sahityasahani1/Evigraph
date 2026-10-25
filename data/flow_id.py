"""
Deterministic Flow Identifier Generator (Canonical v1.1)
Implements:
make_flow_ids(df, evidence_sha256) -> 'flw_' + sha256(
    evidence_sha256|src_ip|src_port|dst_ip|dst_port|protocol|ts_start_ns|occurrence_idx
).hexdigest()[:16]

Features:
- Deterministic total order across all keys and features: row shuffle never alters IDs.
- Collision check: loudly raises ValueError if any flow_id repeats.
- Supports both Series generation and DataFrame assignment.
"""

import hashlib
from typing import List

import pandas as pd

from data.schema import validate_ip_addresses


def compute_flow_5tuple_str(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    protocol: int
) -> str:
    """Returns canonical string representation of a network flow 5-tuple."""
    return f"{str(src_ip).strip()}:{int(src_port)}->{str(dst_ip).strip()}:{int(dst_port)}/proto={int(protocol)}"


def generate_single_flow_id(
    evidence_sha256: str,
    src_ip: str,
    src_port: int,
    dst_ip: str,
    dst_port: int,
    protocol: int,
    ts_start_ns: int,
    occurrence_idx: int = 0
) -> str:
    """
    Computes a canonical flow identifier string:
    'flw_' + sha256(evidence_sha256|src_ip|src_port|dst_ip|dst_port|protocol|ts_start_ns|occurrence_idx)[:16]
    """
    raw_str = (
        f"{evidence_sha256}|{str(src_ip).strip()}|{int(src_port)}|"
        f"{str(dst_ip).strip()}|{int(dst_port)}|{int(protocol)}|"
        f"{int(ts_start_ns)}|{int(occurrence_idx)}"
    )
    digest = hashlib.sha256(raw_str.encode("utf-8")).hexdigest()[:16]
    return f"flw_{digest}"


def make_flow_ids(
    df: pd.DataFrame,
    evidence_sha256: str
) -> pd.Series:
    """
    Computes deterministic, order-invariant flow identifiers for all rows in a DataFrame.

    Algorithm:
    1. Extracts nanosecond epoch integer ts_start_ns.
    2. Sorts DataFrame by deterministic total order (key columns + feature columns).
    3. Calculates occurrence_idx = cumcount within identical 5-tuple + ts_start_ns keys.
    4. Computes SHA-256 hash truncated to 16 hex chars prefixed with 'flw_'.
    5. Performs strict collision check; raises ValueError if any flow_id repeats.
    6. Restores original row order.
    """
    if df.empty:
        return pd.Series([], dtype="object", index=df.index)

    df_work = df.copy()

    # 1. Extract ts_start_ns (nanoseconds since epoch)
    if "ts_start_ns" in df_work.columns:
        ts_ns = df_work["ts_start_ns"].astype("int64")
    else:
        if "ts_start" in df_work.columns:
            timestamp_source = df_work["ts_start"]
        elif "timestamp" in df_work.columns:
            timestamp_source = df_work["timestamp"]
        else:
            raise ValueError("Flow ID generation requires 'ts_start' or 'timestamp'.")
        timestamps = pd.to_datetime(timestamp_source, utc=True, errors="coerce")
        if timestamps.isna().any():
            rows = ", ".join(map(str, df_work.index[timestamps.isna()][:5]))
            raise ValueError(
                "Flow ID generation found missing or invalid timestamps "
                f"at row index(es): {rows}."
            )
        ts_ns = timestamps.astype("int64")

    validate_ip_addresses(df_work)
    df_work["_ts_start_ns"] = ts_ns

    # Default optional transport metadata if absent
    if "src_port" not in df_work.columns:
        df_work["src_port"] = 0
    if "dst_port" not in df_work.columns:
        df_work["dst_port"] = 0
    if "protocol" not in df_work.columns:
        df_work["protocol"] = 6

    # 2. Total deterministic order: key columns + all feature/other columns
    key_sort_cols = ["src_ip", "src_port", "dst_ip", "dst_port", "protocol", "_ts_start_ns"]
    other_cols = sorted([
        c for c in df_work.columns
        if c not in key_sort_cols and c != "flow_id"
    ])
    total_sort_order = key_sort_cols + other_cols

    # Deterministic sort
    df_sorted = df_work.sort_values(by=total_sort_order, kind="mergesort")

    # 3. Compute occurrence_idx via cumcount on identical 5-tuple + timestamp keys
    df_sorted["_occurrence_idx"] = df_sorted.groupby(key_sort_cols).cumcount()

    # 4. Generate flow_ids
    fids: List[str] = []
    for s_ip, sp, d_ip, dp, proto, t_ns, occ in zip(
        df_sorted["src_ip"],
        df_sorted["src_port"],
        df_sorted["dst_ip"],
        df_sorted["dst_port"],
        df_sorted["protocol"],
        df_sorted["_ts_start_ns"],
        df_sorted["_occurrence_idx"], strict=False
    ):
        raw_key = f"{evidence_sha256}|{s_ip}|{sp}|{d_ip}|{dp}|{proto}|{t_ns}|{occ}"
        h = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()[:16]
        fids.append(f"flw_{h}")

    df_sorted["flow_id"] = fids

    # 5. Collision check across the dataset
    if len(fids) != len(set(fids)):
        duplicates_count = len(fids) - len(set(fids))
        raise ValueError(f"Collision detected in flow_id generation: {duplicates_count} duplicate ID(s) found.")

    # 6. Restore original row order
    return df_sorted["flow_id"].loc[df.index]


def assign_flow_ids(
    df: pd.DataFrame,
    evidence_sha256: str = "0000000000000000000000000000000000000000000000000000000000000000",
    prefix: str = "flw",
    overwrite: bool = False
) -> pd.DataFrame:
    """
    Vectorized assignment of flow_id to a DataFrame.
    If 'flow_id' already exists and overwrite is False, retains existing IDs.
    Otherwise uses make_flow_ids to assign canonical v1.1 identifiers.
    """
    df = df.copy()
    if "flow_id" in df.columns and not overwrite and df["flow_id"].notna().all():
        return df

    df["flow_id"] = make_flow_ids(df, evidence_sha256=evidence_sha256)
    return df


# Backward compatibility alias
generate_flow_id = generate_single_flow_id
