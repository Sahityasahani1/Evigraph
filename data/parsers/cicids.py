"""
CICIDS2017 & CICFlowMeter Telemetry Parser
Parses verbose, title-cased CICFlowMeter CSV and Parquet files into Canonical Schema v1.1.
Implements:
1. Microsecond unit isolation: Converts duration to SECONDS for canonical store (divide by 1e6)
   while preserving feat_flow_duration and feat_*_iat_* in MICROSECONDS for model features.
2. Protocol standardization: Maps numeric CICIDS Protocol to int16 (0-255) and populates proto_name.
3. Label sanitization: Strips whitespace, fixes known 'Web Attack \\x96 ...' non-standard dash encoding,
   and maps label_family from versioned YAML taxonomy.
4. Mini-experiment reporting: Tracks initial, removed, and kept flows, along with counts per label_raw
   and per calendar day, exporting to cleaning_report.json.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

import numpy as np
import pandas as pd

from data.config import settings
from data.flow_id import assign_flow_ids
from data.schema import (
    MEMBER2_FEATURES,
    PROTO_NAME_MAP,
    canonicalize,
    parse_protocol_value,
    validate,
)
from data.taxonomy import TaxonomyMapper, default_taxonomy

# Column renaming map for CICFlowMeter verbose headers
CICIDS_COLUMN_MAP: Dict[str, str] = {
    "Flow ID": "flow_id",
    "Source IP": "src_ip",
    "Source Port": "src_port",
    "Destination IP": "dst_ip",
    "Destination Port": "dst_port",
    "Protocol": "protocol",
    "Timestamp": "timestamp",
    "Label": "label_raw",
    "Flow Duration": "flow_duration",
    "Total Fwd Packets": "tot_fwd_pkts",
    "Total Backward Packets": "tot_bwd_pkts",
    "Total Length of Fwd Packets": "tot_len_fwd_pkts",
    "Total Length of Bwd Packets": "tot_len_bwd_pkts",
    "Fwd Packet Length Max": "fwd_pkt_len_max",
    "Fwd Packet Length Min": "fwd_pkt_len_min",
    "Fwd Packet Length Mean": "fwd_pkt_len_mean",
    "Fwd Packet Length Std": "fwd_pkt_len_std",
    "Bwd Packet Length Max": "bwd_pkt_len_max",
    "Bwd Packet Length Min": "bwd_pkt_len_min",
    "Bwd Packet Length Mean": "bwd_pkt_len_mean",
    "Bwd Packet Length Std": "bwd_pkt_len_std",
    "Flow Bytes/s": "flow_bytes_s",
    "Flow Packets/s": "flow_pkts_s",
    "Flow IAT Mean": "flow_iat_mean",
    "Flow IAT Std": "flow_iat_std",
    "Flow IAT Max": "flow_iat_max",
    "Flow IAT Min": "flow_iat_min",
    "Fwd IAT Total": "fwd_iat_tot",
    "Bwd IAT Total": "bwd_iat_tot",
    "Fwd PSH Flags": "fwd_psh_flags",
    "Bwd PSH Flags": "bwd_psh_flags",
    "Fwd URG Flags": "fwd_urg_flags",
    "Bwd URG Flags": "bwd_urg_flags",
    "FIN Flag Count": "fin_flag_cnt",
    "SYN Flag Count": "syn_flag_cnt",
    "RST Flag Count": "rst_flag_cnt",
    "PSH Flag Count": "psh_flag_cnt",
    "ACK Flag Count": "ack_flag_cnt",
    "URG Flag Count": "urg_flag_cnt",
    "Down/Up Ratio": "down_up_ratio",
    "Average Packet Size": "pkt_size_avg",
    "Init_Win_bytes_forward": "init_fwd_win_byts",
    "Init_Win_bytes_backward": "init_bwd_win_byts",
}

_last_cleaning_report: Optional[Dict[str, Any]] = None


def get_last_cleaning_report() -> Optional[Dict[str, Any]]:
    """Returns the most recently generated cleaning report dictionary."""
    global _last_cleaning_report
    return _last_cleaning_report


def clean_label_raw(series: pd.Series) -> pd.Series:
    """
    Cleans raw intrusion label strings:
    - Replaces non-standard byte \\x96 (en-dash in CP1252 / Latin-1) and unicode dashes with standard '-'
    - Strips leading and trailing whitespace
    """
    return (
        series.astype(str)
        .str.replace("\x96", "-", regex=False)
        .str.replace("\u0096", "-", regex=False)
        .str.replace("–", "-", regex=False)
        .str.replace("—", "-", regex=False)
        .str.strip()
    )


def load_raw_cicids(file_path: Path, max_rows: Optional[int] = None) -> pd.DataFrame:
    """
    Loads raw CSV or Parquet file with automatic encoding fallback (utf-8 -> latin-1).
    """
    file_path = Path(file_path)
    if not file_path.exists():
        raise FileNotFoundError(f"CICIDS file not found: {file_path}")

    if file_path.suffix == ".parquet":
        return pd.read_parquet(file_path)

    # Detect separator
    sep = ","
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f_peek:
            first_line = f_peek.readline()
            sep = ";" if ";" in first_line else ","
    except Exception:
        sep = ","

    # Attempt utf-8 first; fallback to latin-1 to handle \x96 byte encoding
    try:
        df = pd.read_csv(file_path, sep=sep, nrows=max_rows, encoding="utf-8")
    except (UnicodeDecodeError, UnicodeError):
        df = pd.read_csv(file_path, sep=sep, nrows=max_rows, encoding="latin-1")

    return df


def parse_cicids(
    file_path: Path | str,
    evidence_id: Optional[str] = None,
    evidence_sha256: Optional[str] = None,
    max_rows: Optional[int] = None,
    taxonomy_yaml: Optional[Path | str] = None,
    report_path: Optional[Path | str] = None,
) -> pd.DataFrame:
    """
    Parses a CICIDS CSV or Parquet file into the EviGraph canonical schema v1.1.

    Key guarantees:
    - Canonical `duration` is in SECONDS (float64).
    - Model features `feat_flow_duration` and `feat_*_iat_*` remain in MICROSECONDS (float32).
    - `protocol` is converted to int16; `proto_name` is filled with standard IANA names.
    - `label_raw` is cleaned (whitespace stripped, \\x96 fixed).
    - `label_family` is mapped from versioned YAML taxonomy.
    - Generates and writes `cleaning_report.json` with counts per label_raw, per day, and removed vs kept.
    """
    global _last_cleaning_report
    file_path = Path(file_path)
    ev_id = evidence_id or file_path.stem
    ev_sha = evidence_sha256 or "0000000000000000000000000000000000000000000000000000000000000000"

    df = load_raw_cicids(file_path, max_rows=max_rows)
    initial_rows = len(df)

    # Clean whitespace in column names
    df.columns = [str(c).strip() for c in df.columns]

    # Rename known CICIDS columns (case-insensitive fallback)
    col_map_lower = {k.lower(): v for k, v in CICIDS_COLUMN_MAP.items()}
    rename_targets = {}
    for c in df.columns:
        if c in CICIDS_COLUMN_MAP:
            rename_targets[c] = CICIDS_COLUMN_MAP[c]
        elif c.lower() in col_map_lower:
            rename_targets[c] = col_map_lower[c.lower()]
    df = df.rename(columns=rename_targets)
    df = df.loc[:, ~df.columns.duplicated()]

    # Evidence ID
    df["evidence_id"] = ev_id

    # 1. Label Extraction & Sanitization
    raw_label_source = None
    for l_cand in ["label_raw", "label", "Label"]:
        if l_cand in df.columns:
            raw_label_source = l_cand
            break

    if raw_label_source:
        df["label_raw"] = clean_label_raw(df[raw_label_source])
    else:
        df["label_raw"] = "BENIGN"

    # Map label_family from versioned YAML
    mapper = TaxonomyMapper(yaml_path=taxonomy_yaml) if taxonomy_yaml else default_taxonomy
    df["label_family"] = mapper.map_series(df["label_raw"])
    df["label"] = df["label_raw"]  # Member 2 compatibility

    # 2. Protocol Standardization to int16 & Proto Name
    if "protocol" in df.columns:
        df["protocol"] = df["protocol"].apply(parse_protocol_value).astype("int16")
    else:
        df["protocol"] = np.int16(6)

    df["proto_name"] = df["protocol"].map(
        lambda p: PROTO_NAME_MAP.get(int(p), f"PROTO_{p}")
    ).astype(str)

    # 3. Durations, Timestamps, and Feature Unit Isolation
    # Raw CICIDS Flow Duration is in MICROSECONDS.
    if "flow_duration" in df.columns:
        df["flow_duration"] = pd.to_numeric(df["flow_duration"], errors="coerce")
    else:
        df["flow_duration"] = 0.0

    # Model feature retains microseconds
    df["feat_flow_duration"] = df["flow_duration"].astype("float32")

    # Canonical column duration is converted to SECONDS (divide by 1e6)
    df["duration"] = (df["flow_duration"] / 1e6).astype("float64")

    # Keep IAT features in microseconds
    for iat_col in [
        "flow_iat_mean",
        "flow_iat_std",
        "flow_iat_max",
        "flow_iat_min",
        "fwd_iat_tot",
        "bwd_iat_tot",
    ]:
        feat_name = f"feat_{iat_col}"
        if iat_col in df.columns:
            df[feat_name] = pd.to_numeric(df[iat_col], errors="coerce").astype("float32")

    # Timestamps
    ts_col = "timestamp" if "timestamp" in df.columns else ("Timestamp" if "Timestamp" in df.columns else None)
    if ts_col:
        df["ts_start"] = pd.to_datetime(df[ts_col], format="mixed", errors="coerce", utc=True)
    else:
        df["ts_start"] = pd.to_datetime("2026-10-18T00:00:00Z", utc=True)

    df["ts_end"] = df["ts_start"] + pd.to_timedelta(df["duration"], unit="s")

    # 4. Data Cleaning & Hierarchical Drop Reason Tracking (Mini-Experiment)
    drop_reasons: Dict[str, int] = {
        "repeated_headers": 0,
        "invalid_timestamps": 0,
        "negative_duration": 0,
        "invalid_ports": 0,
        "inf_or_nan_features": 0,
    }

    # Repeated header rows (e.g. from concatenated CSV files)
    is_header = (
        df["protocol"].astype(str).str.lower().str.contains("protocol")
        | df["src_ip"].astype(str).str.lower().str.contains("source")
        | df["label_raw"].astype(str).str.lower().eq("label")
    )
    drop_reasons["repeated_headers"] = int(is_header.sum())

    # Invalid unparseable timestamps (evaluated on non-headers)
    remaining_mask = ~is_header
    invalid_ts = remaining_mask & df["ts_start"].isna()
    drop_reasons["invalid_timestamps"] = int(invalid_ts.sum())

    # Negative duration (known CICFlowMeter clock skew bug)
    remaining_mask = remaining_mask & (~invalid_ts)
    negative_dur = remaining_mask & ((df["duration"] < 0) | (df["flow_duration"] < 0))
    drop_reasons["negative_duration"] = int(negative_dur.sum())

    # Port validation
    remaining_mask = remaining_mask & (~negative_dur)
    src_port_num = pd.to_numeric(df.get("src_port", 0), errors="coerce")
    dst_port_num = pd.to_numeric(df.get("dst_port", 0), errors="coerce")
    bad_ports = remaining_mask & (
        src_port_num.isna()
        | dst_port_num.isna()
        | (src_port_num < 0)
        | (src_port_num > 65535)
        | (dst_port_num < 0)
        | (dst_port_num > 65535)
    )
    drop_reasons["invalid_ports"] = int(bad_ports.sum())

    # Infinite or NaN in core numeric features
    remaining_mask = remaining_mask & (~bad_ports)
    feat_cols_present = [f for f in MEMBER2_FEATURES if f in df.columns]
    for c in feat_cols_present:
        df[c] = pd.to_numeric(df[c], errors="coerce").replace([np.inf, -np.inf], np.nan)
    nan_features = remaining_mask & (
        df[feat_cols_present].isna().any(axis=1) if feat_cols_present else pd.Series(False, index=df.index)
    )
    drop_reasons["inf_or_nan_features"] = int(nan_features.sum())

    # Filter valid rows
    valid_mask = remaining_mask & (~nan_features)
    df_clean = df[valid_mask].copy()

    # Port casting
    df_clean["src_port"] = src_port_num[valid_mask].astype("int32")
    df_clean["dst_port"] = dst_port_num[valid_mask].astype("int32")

    # Source type
    df_clean["source_type"] = "cicids"

    # Assign deterministic flow_id
    df_clean = assign_flow_ids(df_clean, evidence_sha256=ev_sha)

    # Canonicalize and validate schema constraints
    df_clean = canonicalize(df_clean)
    validate(df_clean)

    # 5. Mini-Experiment Cleaning Report
    kept_count = len(df_clean)
    removed_count = initial_rows - kept_count
    removal_rate_pct = round((removed_count / initial_rows * 100.0), 3) if initial_rows > 0 else 0.0

    counts_per_label_raw = df_clean["label_raw"].value_counts().to_dict()
    counts_per_day = df_clean["ts_start"].dt.date.astype(str).value_counts().to_dict()
    counts_per_label_family = df_clean["label_family"].value_counts().to_dict()

    cleaning_report = {
        "report_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_file": str(file_path),
        "taxonomy_version": mapper.version,
        "removed_vs_kept": {
            "raw_total": initial_rows,
            "kept": kept_count,
            "removed": removed_count,
            "removal_rate_pct": removal_rate_pct,
        },
        "drop_reasons": drop_reasons,
        "counts_per_label_raw": counts_per_label_raw,
        "counts_per_day": counts_per_day,
        "counts_per_label_family": counts_per_label_family,
    }
    _last_cleaning_report = cleaning_report

    # Save to cleaning_report.json
    out_report_path = Path(report_path) if report_path else settings.resolve_path(settings.cleaning_report_path)
    out_report_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_report_path, "w", encoding="utf-8") as f_out:
        json.dump(cleaning_report, f_out, indent=2)

    return df_clean
