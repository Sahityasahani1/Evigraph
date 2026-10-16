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

# Canonical column mapping: maps CICFlowMeter verbose / title-cased names to lowercase snake_case
COLUMN_CANONICAL_MAP = {
    "Flow ID": "flow_id",
    "Source IP": "src_ip",
    "Source Port": "src_port",
    "Destination IP": "dst_ip",
    "Destination Port": "dst_port",
    "Protocol": "protocol",
    "Timestamp": "timestamp",
    "Label": "label",
    "Flow Duration": "flow_duration",
    "Total Fwd Packets": "tot_fwd_pkts",
    "Total Backward Packets": "tot_bwd_pkts",
    "Total Length of Fwd Packets": "totlen_fwd_pkts",
    "Total Length of Bwd Packets": "totlen_bwd_pkts",
    "Fwd Packet Length Max": "fwd_pkt_len_max",
    "Fwd Packet Length Min": "fwd_pkt_len_min",
    "Fwd Packet Length Mean": "fwd_pkt_len_mean",
    "Fwd Packet Length Std": "fwd_pkt_len_std",
    "Bwd Packet Length Max": "bwd_pkt_len_max",
    "Bwd Packet Length Min": "bwd_pkt_len_min",
    "Bwd Packet Length Mean": "bwd_pkt_len_mean",
    "Bwd Packet Length Std": "bwd_pkt_len_std",
    "Flow Bytes/s": "flow_byts_s",
    "Flow Packets/s": "flow_pkts_s",
    "Flow IAT Mean": "flow_iat_mean",
    "Flow IAT Std": "flow_iat_std",
    "Flow IAT Max": "flow_iat_max",
    "Flow IAT Min": "flow_iat_min",
    "Fwd IAT Total": "fwd_iat_tot",
    "Fwd IAT Mean": "fwd_iat_mean",
    "Fwd IAT Std": "fwd_iat_std",
    "Fwd IAT Max": "fwd_iat_max",
    "Fwd IAT Min": "fwd_iat_min",
    "Bwd IAT Total": "bwd_iat_tot",
    "Bwd IAT Mean": "bwd_iat_mean",
    "Bwd IAT Std": "bwd_iat_std",
    "Bwd IAT Max": "bwd_iat_max",
    "Bwd IAT Min": "bwd_iat_min",
    "Fwd PSH Flags": "fwd_psh_flags",
    "Bwd PSH Flags": "bwd_psh_flags",
    "Fwd URG Flags": "fwd_urg_flags",
    "Bwd URG Flags": "bwd_urg_flags",
    "Fwd Header Length": "fwd_header_len",
    "Fwd Header Length.1": "fwd_header_len_dup",
    "Bwd Header Length": "bwd_header_len",
    "Fwd Packets/s": "fwd_pkts_s",
    "Bwd Packets/s": "bwd_pkts_s",
    "Min Packet Length": "pkt_len_min",
    "Max Packet Length": "pkt_len_max",
    "Packet Length Mean": "pkt_len_mean",
    "Packet Length Std": "pkt_len_std",
    "Packet Length Variance": "pkt_len_var",
    "FIN Flag Count": "fin_flag_cnt",
    "SYN Flag Count": "syn_flag_cnt",
    "RST Flag Count": "rst_flag_cnt",
    "PSH Flag Count": "psh_flag_cnt",
    "ACK Flag Count": "ack_flag_cnt",
    "URG Flag Count": "urg_flag_cnt",
    "CWE Flag Count": "cwr_flag_count",
    "ECE Flag Count": "ece_flag_cnt",
    "Down/Up Ratio": "down_up_ratio",
    "Average Packet Size": "pkt_size_avg",
    "Avg Fwd Segment Size": "fwd_seg_size_avg",
    "Avg Bwd Segment Size": "bwd_seg_size_avg",
    "Fwd Avg Bytes/Bulk": "fwd_byts_b_avg",
    "Fwd Avg Packets/Bulk": "fwd_pkts_b_avg",
    "Fwd Avg Bulk Rate": "fwd_blk_rate_avg",
    "Bwd Avg Bytes/Bulk": "bwd_byts_b_avg",
    "Bwd Avg Packets/Bulk": "bwd_pkts_b_avg",
    "Bwd Avg Bulk Rate": "bwd_blk_rate_avg",
    "Subflow Fwd Packets": "subflow_fwd_pkts",
    "Subflow Fwd Bytes": "subflow_fwd_byts",
    "Subflow Bwd Packets": "subflow_bwd_pkts",
    "Subflow Bwd Bytes": "subflow_bwd_byts",
    "Init_Win_bytes_forward": "init_fwd_win_byts",
    "Init_Win_bytes_backward": "init_bwd_win_byts",
    "act_data_pkt_fwd": "fwd_act_data_pkts",
    "min_seg_size_forward": "fwd_seg_size_min",
    "Active Mean": "active_mean",
    "Active Std": "active_std",
    "Active Max": "active_max",
    "Active Min": "active_min",
    "Idle Mean": "idle_mean",
    "Idle Std": "idle_std",
    "Idle Max": "idle_max",
    "Idle Min": "idle_min"
}

class FlowDataLoader:
    def __init__(self, metadata_cols: Optional[List[str]] = None):
        self.metadata_cols = metadata_cols or METADATA_COLS
        self.feature_columns: List[str] = []

    def clean_dataset(self, df: pd.DataFrame) -> pd.DataFrame:
        """Removes infinite/NaN values and duplicates (TRD FR-2.5)."""
        initial_len = len(df)
        
        # Strip column names of whitespace
        df.columns = [c.strip() for c in df.columns]
        
        # Standardize column names to canonical snake_case
        df = df.rename(columns={k: v for k, v in COLUMN_CANONICAL_MAP.items() if k in df.columns})
        df = df.loc[:, ~df.columns.duplicated()]

        # Clean label strings (strip spaces, replace non-standard dashes, standardize BENIGN)
        if "label" in df.columns:
            df["label"] = df["label"].astype(str).str.replace('\x96', '-').str.strip()
            df["label"] = df["label"].replace({"Normal": "BENIGN"})

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
        val_ratio: float = 0.20,
        per_class: bool = True
    ):
        """
        Sorts chronologically and splits into Train/Val/Test temporally (TRD Sec 3.3.5).
        When per_class=True, splits chronologically within each attack class,
        guaranteeing zero future-to-past leakage while preserving multi-class representation.
        Returns: (X_train, y_train, meta_train, X_val, y_val, meta_val, X_test, y_test, meta_test)
        """
        if "timestamp" in df.columns:
            df["timestamp"] = pd.to_datetime(df["timestamp"], format="mixed", errors="coerce")
            
        if per_class and "label" in df.columns:
            train_dfs, val_dfs, test_dfs = [], [], []
            for label_name, group in df.groupby("label"):
                if "timestamp" in group.columns:
                    group = group.sort_values(by="timestamp").reset_index(drop=True)
                n = len(group)
                train_end = int(n * train_ratio)
                val_end = int(n * (train_ratio + val_ratio))
                train_dfs.append(group.iloc[:train_end])
                val_dfs.append(group.iloc[train_end:val_end])
                test_dfs.append(group.iloc[val_end:])
            
            train_df = pd.concat(train_dfs, ignore_index=True)
            val_df = pd.concat(val_dfs, ignore_index=True)
            test_df = pd.concat(test_dfs, ignore_index=True)
        else:
            if "timestamp" in df.columns:
                df = df.sort_values(by="timestamp").reset_index(drop=True)
            n = len(df)
            train_end = int(n * train_ratio)
            val_end = int(n * (train_ratio + val_ratio))
            train_df = df.iloc[:train_end].copy()
            val_df = df.iloc[train_end:val_end].copy()
            test_df = df.iloc[val_end:].copy()

        # Identify numerical features (excluding metadata) using robust pandas type check
        self.feature_columns = [
            c for c in df.columns 
            if c not in self.metadata_cols and pd.api.types.is_numeric_dtype(df[c])
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
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f_peek:
                first_line = f_peek.readline()
                sep = ";" if ";" in first_line else ","
            df = pd.read_csv(file_path, sep=sep)
            
        # Standardize known column names
        df.columns = [c.strip() for c in df.columns]
        df = df.rename(columns={k: v for k, v in COLUMN_CANONICAL_MAP.items() if k in df.columns})
        df = df.loc[:, ~df.columns.duplicated()]
        
        # Clean label strings
        if "label" in df.columns:
            df["label"] = df["label"].astype(str).str.replace('\x96', '-').str.strip()
            df["label"] = df["label"].replace({"Normal": "BENIGN"})
        
        if max_rows and len(df) > max_rows:
            if "timestamp" in df.columns:
                df["timestamp"] = pd.to_datetime(df["timestamp"], format="mixed", errors="coerce")
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

    def load_combined_dataset(
        self, 
        file_paths: Optional[List[Path]] = None, 
        max_per_attack: int = 15000,
        benign_per_file: int = 20000
    ) -> pd.DataFrame:
        """
        Loads and combines all attack captures into a unified multi-class enterprise dataset.
        Includes CICIDS2017 parquet captures and USP datasets (e.g. NIDS2025 RCE CSV).
        Ensures all attack classes are fairly represented.
        """
        from src.config import RAW_DATA_DIR
        if file_paths is None:
            file_paths = sorted(list(RAW_DATA_DIR.glob("*.parquet")) + list(RAW_DATA_DIR.glob("*.csv")))

        dfs = []
        for f in file_paths:
            print(f"[DataLoader] Ingesting attack slice from: {f.name}")
            df_full = self.load_dataset(f)
            
            # Separate Benign and Attacks to ensure attack representation
            benign_df = df_full[df_full["label"] == "BENIGN"].head(benign_per_file)
            
            # Group attacks by class and cap each class individually to prevent single-class skew
            attack_slices = []
            for atk_cls in df_full[df_full["label"] != "BENIGN"]["label"].unique():
                cls_df = df_full[df_full["label"] == atk_cls]
                if len(cls_df) > max_per_attack:
                    cls_df = cls_df.head(max_per_attack)
                attack_slices.append(cls_df)
                
            if attack_slices:
                file_df = pd.concat([benign_df] + attack_slices, ignore_index=True)
            else:
                file_df = benign_df
                
            dfs.append(file_df)

        combined_df = pd.concat(dfs, ignore_index=True)
        # Fill missing columns across heterogeneous datasets with 0.0
        combined_df = combined_df.fillna(0.0)

        if "timestamp" in combined_df.columns:
            combined_df["timestamp"] = pd.to_datetime(combined_df["timestamp"], format="mixed", errors="coerce")
            combined_df = combined_df.sort_values(by="timestamp").reset_index(drop=True)

        print(f"\n[DataLoader] Unified Enterprise Dataset Built:")
        print(f"   * Total Flows  : {len(combined_df):,}")
        print(f"   * Unique Hosts : {combined_df['src_ip'].nunique() + combined_df['dst_ip'].nunique():,}")
        print("   * Class Breakdown:")
        for cls, count in combined_df["label"].value_counts().items():
            print(f"     - {cls:<25} : {count:>7,} flows")

        return combined_df
