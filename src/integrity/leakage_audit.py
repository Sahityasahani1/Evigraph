"""Leakage and overlap auditing helpers for EviGraph splits.

These checks are deliberately conservative: they report overlaps and suspicious
feature choices instead of silently assuming a split is clean.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, List

import numpy as np
import pandas as pd

from src.config import OUTPUTS_DIR


def _composite_key(df: pd.DataFrame) -> pd.Series:
    columns = [
        c for c in (
            "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
            "flow_duration", "tot_fwd_pkts", "tot_bwd_pkts",
        )
        if c in df.columns
    ]
    if not columns:
        return pd.Series([""] * len(df), index=df.index)
    return df[columns].astype(str).agg("|".join, axis=1)


def audit_split_leakage(
    train_df: pd.DataFrame,
    val_df: pd.DataFrame,
    test_df: pd.DataFrame,
) -> Dict[str, Any]:
    train_keys = set(_composite_key(train_df))
    val_keys = set(_composite_key(val_df))
    test_keys = set(_composite_key(test_df))

    train_test_overlap = len(train_keys & test_keys)
    train_val_overlap = len(train_keys & val_keys)
    val_test_overlap = len(val_keys & test_keys)

    exact_duplicate_rows = {
        "train": int(train_df.duplicated().sum()),
        "val": int(val_df.duplicated().sum()),
        "test": int(test_df.duplicated().sum()),
    }

    total_test = max(len(test_keys), 1)
    return {
        "rows": {
            "train": len(train_df),
            "val": len(val_df),
            "test": len(test_df),
        },
        "unique_composite_keys": {
            "train": len(train_keys),
            "val": len(val_keys),
            "test": len(test_keys),
        },
        "overlap_counts": {
            "train_test": train_test_overlap,
            "train_val": train_val_overlap,
            "val_test": val_test_overlap,
        },
        "overlap_rates": {
            "train_test": train_test_overlap / total_test,
            "train_val": train_val_overlap / max(len(val_keys), 1),
            "val_test": val_test_overlap / total_test,
        },
        "exact_duplicate_rows": exact_duplicate_rows,
        "leakage_detected": bool(train_test_overlap or train_val_overlap or val_test_overlap),
    }


def audit_feature_leakage(feature_columns: Iterable[str]) -> Dict[str, Any]:
    forbidden = {
        "flow_id", "timestamp", "src_ip", "dst_ip", "src_port", "dst_port",
        "protocol", "src_mac", "dst_mac", "evidence_id", "label",
    }
    leaked = [c for c in feature_columns if c in forbidden]
    return {
        "feature_count": len(list(feature_columns)),
        "forbidden_features_present": leaked,
        "passed": not leaked,
    }


def write_leakage_audit(
    train_df: pd.DataFrame,
    val_df: pd.DataFrame,
    test_df: pd.DataFrame,
    feature_columns: Iterable[str],
    output_path: Optional[Path] = None,
) -> Path:
    report = {
        "split_leakage": audit_split_leakage(train_df, val_df, test_df),
        "feature_leakage": audit_feature_leakage(feature_columns),
    }
    out = Path(output_path or (OUTPUTS_DIR / "leakage_audit.json"))
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)
    print(f"[LeakageAudit] Report written to: {out}")
    if report["split_leakage"]["leakage_detected"]:
        print("[LeakageAudit] WARNING: train/test or train/val key overlap detected.")
    if not report["feature_leakage"]["passed"]:
        print("[LeakageAudit] WARNING: forbidden metadata columns are used as features.")
    return out