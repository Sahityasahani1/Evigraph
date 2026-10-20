"""
Member 2 Telemetry & Feature Export Adapter
Generates strict Member-2 compliant Parquet datasets and sidecar cryptographic manifests.
Adheres to Member 2 schema contracts:
- Exact 44-column order: 9 metadata columns + 35 canonical flow features
- Unprefixed feature names matching Member 2's config.py CANONICAL_FEATURES
- Tz-naive UTC datetime64[ns] timestamp
- Standardized BENIGN label
- flow_duration in microseconds (duration * 1e6)
- Pure float32 features with zero NaN/Inf guarantees
- Cryptographic sidecar <name>.manifest.json with SHA-256
- Strict numeric column boundary: only {src_port, dst_port, protocol, 35 features}
"""

import hashlib
import json
from pathlib import Path
from typing import List, Optional, Union

import numpy as np
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

from data.config import CANONICAL_FEATURES
from data.evidence import AuditLogger
from data.storage import DuckDBCatalog

# 9 Metadata columns required by Member 2
MEMBER2_METADATA_COLS: List[str] = [
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

# Exact 44-column canonical schema expected by Member 2
MEMBER2_EXPORT_COLUMNS: List[str] = MEMBER2_METADATA_COLS + list(CANONICAL_FEATURES)

# Numeric columns allowed in the Member-2 dataset
ALLOWED_NUMERIC_COLS = {"src_port", "dst_port", "protocol"} | set(CANONICAL_FEATURES)


def export_member2(
    out_path: Union[str, Path],
    df: Optional[pd.DataFrame] = None,
    split: Optional[str] = None
) -> Path:
    """
    Exports flow telemetry in Member 2's exact schema contract.

    Args:
        out_path: Destination path for the generated snappy Parquet file.
        df: Optional source DataFrame. If None, queries from DuckDBCatalog.
        split: Optional split filter ('train', 'val', 'test').

    Returns:
        Path to the written Parquet file.
    """
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    # 1. Ingest input DataFrame or query from DuckDB catalog
    if df is None:
        catalog = DuckDBCatalog()
        sql = "SELECT * FROM flows"
        if split:
            sql += f" WHERE split = '{split}'"
        df = catalog.query(sql)

    if df.empty:
        # Build empty dataframe with exact schema
        out_df = pd.DataFrame(columns=MEMBER2_EXPORT_COLUMNS)
    else:
        out_df = pd.DataFrame(index=df.index)

        # 2. Metadata Columns
        # flow_id
        if "flow_id" in df.columns:
            out_df["flow_id"] = df["flow_id"].astype(str)
        else:
            out_df["flow_id"] = [f"flw_{i:07d}" for i in range(len(df))]

        # evidence_id
        if "evidence_id" in df.columns:
            out_df["evidence_id"] = df["evidence_id"].astype(str)
        else:
            out_df["evidence_id"] = out_path.stem

        # timestamp: ts_start converted to tz-naive UTC datetime64[ns]
        raw_ts = df.get("ts_start", df.get("timestamp", "2026-10-18T00:00:00Z"))
        dt_ts = pd.to_datetime(raw_ts, utc=True)
        if hasattr(dt_ts.dt, "tz") and dt_ts.dt.tz is not None:
            dt_ts = dt_ts.dt.tz_convert(None)
        out_df["timestamp"] = dt_ts.astype("datetime64[ns]")

        # IPs and Ports
        out_df["src_ip"] = df.get("src_ip", "0.0.0.0").astype(str)
        out_df["dst_ip"] = df.get("dst_ip", "0.0.0.0").astype(str)
        out_df["src_port"] = df.get("src_port", 0).fillna(0).astype("int32")
        out_df["dst_port"] = df.get("dst_port", 0).fillna(0).astype("int32")

        # protocol
        if "protocol" in df.columns:
            out_df["protocol"] = df["protocol"].fillna(6).astype("int16")
        else:
            out_df["protocol"] = np.int16(6)

        # label: label_raw with BENIGN normalized (case-insensitive 'benign' -> 'BENIGN')
        raw_label = df.get("label_raw", df.get("label", "BENIGN")).astype(str).str.strip()
        cleaned_label = (
            raw_label
            .replace(to_replace=r"(?i)^benign$", value="BENIGN", regex=True)
            .str.replace("\x96", "-", regex=False)
            .str.replace("Normal", "BENIGN", regex=False)
        )
        out_df["label"] = cleaned_label

        # 3. 35 Canonical Features (Unprefixed, Float32, Zero NaN/Inf)
        for f in CANONICAL_FEATURES:
            if f == "flow_duration":
                # flow_duration = duration*1e6 (µs); IATs already µs
                if "duration" in df.columns:
                    val = (df["duration"].astype("float64") * 1e6).astype("float32")
                elif "feat_flow_duration" in df.columns:
                    val = df["feat_flow_duration"].astype("float32")
                elif "flow_duration" in df.columns:
                    val = df["flow_duration"].astype("float32")
                else:
                    val = pd.Series(0.0, index=df.index, dtype="float32")
            else:
                feat_col = f"feat_{f}"
                if feat_col in df.columns:
                    val = df[feat_col].astype("float32")
                elif f in df.columns:
                    val = df[f].astype("float32")
                else:
                    val = pd.Series(0.0, index=df.index, dtype="float32")

            # Clean NaN and Inf values
            val = val.replace([np.inf, -np.inf], np.nan).fillna(0.0).astype("float32")

            # Assertions: NaN/inf impossible
            assert not val.isna().any(), f"NaN detected in exported feature '{f}'"
            assert not np.isneginf(val).any(), f"-inf detected in exported feature '{f}'"
            assert not np.isposinf(val).any(), f"+inf detected in exported feature '{f}'"

            out_df[f] = val

    # 4. Enforce exact column order
    out_df = out_df[MEMBER2_EXPORT_COLUMNS]
    assert list(out_df.columns) == MEMBER2_EXPORT_COLUMNS, (
        f"Column order mismatch. Got {list(out_df.columns)}, expected {MEMBER2_EXPORT_COLUMNS}"
    )

    # 5. Assert no numeric column exists outside {ports, protocol, 35 features}
    numeric_cols = set(out_df.select_dtypes(include=[np.number]).columns)
    assert numeric_cols == ALLOWED_NUMERIC_COLS, (
        f"Forbidden numeric columns in Member-2 export: {numeric_cols - ALLOWED_NUMERIC_COLS}"
    )

    # 6. Write snappy Parquet
    table = pa.Table.from_pandas(out_df, preserve_index=False)
    pq.write_table(table, out_path, compression="snappy")

    # 7. Write sidecar <name>.manifest.json (row count, column list, sha256)
    sha256 = hashlib.sha256(out_path.read_bytes()).hexdigest()
    manifest_data = {
        "filename": out_path.name,
        "row_count": len(out_df),
        "column_list": list(out_df.columns),
        "sha256": sha256,
    }

    # Write both <name>.manifest.json and <stem>.manifest.json for broad compatibility
    sidecar_path = out_path.parent / f"{out_path.name}.manifest.json"
    sidecar_path.write_text(json.dumps(manifest_data, indent=2), encoding="utf-8")

    if out_path.suffix == ".parquet":
        alt_manifest = out_path.with_suffix(".manifest.json")
        alt_manifest.write_text(json.dumps(manifest_data, indent=2), encoding="utf-8")

    # 8. Record audit log entry
    AuditLogger().log_action(
        action="EXPORT_MEMBER2",
        params={
            "output_file": str(out_path),
            "rows": len(out_df),
            "columns": len(out_df.columns),
            "split": split,
            "sha256": sha256,
        },
        output_files=[str(out_path), str(sidecar_path)]
    )

    return out_path
