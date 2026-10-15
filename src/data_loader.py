"""
EviGraph Data Loader & Preprocessing Pipeline
Adheres to TRD Section 3.2 and FR-2.5:
- Clean CICIDS2017/Flow data: drop NaN/Inf, drop exact duplicates
- Strict leakage controls: exclude IPs, ports-as-identity, timestamps from model features
- Temporal split (train on earliest window, test on latest window)
"""

import pandas as pd
import numpy as np
from pathlib import Path
from typing import Tuple, List, Optional
from src.config import METADATA_COLS, SAMPLES_DATA_DIR, LABEL_MAPPING

class FlowDataLoader:
    def __init__(self, metadata_cols: Optional[List[str]] = None):
        self.metadata_cols = metadata_cols or METADATA_COLS
        self.feature_columns: List[str] = []

    def clean_dataset(self, df: pd.DataFrame) -> pd.DataFrame:
        """Removes infinite/NaN values and duplicates (TRD FR-2.5)."""
        initial_len = len(df)
        
        # Strip column names of whitespace
        df.columns = [c.strip() for c in df.columns]
        
        # Replace Inf with NaN, then fill or drop
        df = df.replace([np.inf, -np.inf], np.nan)
        df = df.dropna(subset=[c for c in df.columns if c not in self.metadata_cols])
        
        # Deduplicate
        df = df.drop_duplicates()
        
        print(f"[DataLoader] Cleaned dataset: {initial_len} -> {len(df)} rows ({initial_len - len(df)} dropped)")
        return df

    def prepare_temporal_split(
        self, 
        df: pd.DataFrame, 
        train_ratio: float = 0.50,
        val_ratio: float = 0.20
    ):
        """
        Sorts chronologically and splits into Train/Val/Test temporally (TRD Sec 3.3.5).
        Returns: (X_train, y_train, meta_train, X_val, y_val, meta_val, X_test, y_test, meta_test)
        """
        if "timestamp" in df.columns:
            df["timestamp"] = pd.to_datetime(df["timestamp"], format="mixed")
            df = df.sort_values(by="timestamp").reset_index(drop=True)
            
        n = len(df)
        train_end = int(n * train_ratio)
        val_end = int(n * (train_ratio + val_ratio))
        
        train_df = df.iloc[:train_end].copy()
        val_df = df.iloc[train_end:val_end].copy()
        test_df = df.iloc[val_end:].copy()

        # Identify numerical features (excluding metadata)
        self.feature_columns = [
            c for c in df.columns 
            if c not in self.metadata_cols and np.issubdtype(df[c].dtype, np.number)
        ]

        X_train = train_df[self.feature_columns]
        y_train = train_df["label"]
        meta_train = train_df[[c for c in self.metadata_cols if c in train_df.columns]]

        X_val = val_df[self.feature_columns]
        y_val = val_df["label"]
        meta_val = val_df[[c for c in self.metadata_cols if c in val_df.columns]]

        X_test = test_df[self.feature_columns]
        y_test = test_df["label"]
        meta_test = test_df[[c for c in self.metadata_cols if c in test_df.columns]]

        print(f"[DataLoader] Temporal Split: Train={len(X_train)} flows, Val={len(X_val)} flows, Test={len(X_test)} flows")
        print(f"[DataLoader] Features extracted: {len(self.feature_columns)} flow features (IPs/ports excluded from training)")
        
        return X_train, y_train, meta_train, X_val, y_val, meta_val, X_test, y_test, meta_test

    def load_dataset(self, file_path: Path, max_rows: Optional[int] = None) -> pd.DataFrame:
        print(f"[DataLoader] Reading flows from {file_path}")
        if str(file_path).endswith(".parquet"):
            df = pd.read_parquet(file_path)
        else:
            df = pd.read_csv(file_path)
            
        # Standardize known CICIDS2017 column names to canonical schema
        rename_map = {
            "Flow ID": "flow_id",
            "Source IP": "src_ip",
            "Source Port": "src_port",
            "Destination IP": "dst_ip",
            "Destination Port": "dst_port",
            "Protocol": "protocol",
            "Timestamp": "timestamp",
            "Label": "label"
        }
        df = df.rename(columns={k: v for k, v in rename_map.items() if k in df.columns})
        
        if max_rows and len(df) > max_rows:
            # Take earliest chronological slice if timestamp exists
            if "timestamp" in df.columns:
                df["timestamp"] = pd.to_datetime(df["timestamp"], format="mixed")
                df = df.sort_values(by="timestamp")
            df = df.iloc[:max_rows].copy()
        
        # Ensure flow_id exists and is clean string
        if "flow_id" not in df.columns:
            df["flow_id"] = [f"flw_{i:07d}" for i in range(len(df))]
        else:
            df["flow_id"] = df["flow_id"].astype(str)
            
        if "evidence_id" not in df.columns:
            df["evidence_id"] = file_path.stem
            
        return self.clean_dataset(df)

    def load_from_csv(self, file_path: Path) -> pd.DataFrame:
        return self.load_dataset(file_path)
