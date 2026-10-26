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
from typing import Tuple, List, Optional, Dict, Set
import re
from src.config import METADATA_COLS, SAMPLES_DATA_DIR, LABEL_MAPPING, CANONICAL_FEATURES


def split_temporally(
    df: pd.DataFrame,
    train_ratio: float = 0.60,
    val_ratio: float = 0.20,
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Split rows by global timestamp order; if no timestamp exists, preserve input order."""
    if not 0.0 <= train_ratio <= 1.0 or not 0.0 <= val_ratio <= 1.0:
        raise ValueError("train_ratio and val_ratio must be between 0 and 1.")
    if train_ratio + val_ratio > 1.0:
        raise ValueError("train_ratio + val_ratio must not exceed 1.")

    ordered = df.copy()
    if "timestamp" in ordered.columns:
        ordered["timestamp"] = pd.to_datetime(
            ordered["timestamp"], format="mixed", errors="coerce"
        )
        if ordered["timestamp"].isna().any():
            raise ValueError("Global temporal splitting requires a valid timestamp for every row.")
        ordered = ordered.sort_values(by="timestamp", kind="stable").reset_index(drop=True)

        group_ends = (
            ordered["timestamp"].ne(ordered["timestamp"].shift(-1)).to_numpy().nonzero()[0] + 1
        )
        valid_ends = group_ends[(group_ends > 0) & (group_ends < len(ordered))]
        if len(valid_ends) < 2:
            raise ValueError(
                "Global temporal splitting requires at least three distinct timestamps "
                "to keep train, validation, and test time ranges disjoint."
            )
        train_candidates = valid_ends[:-1]
        train_target = int(len(ordered) * train_ratio)
        train_end = int(train_candidates[np.abs(train_candidates - train_target).argmin()])
        val_candidates = valid_ends[valid_ends > train_end]
        val_target = int(len(ordered) * (train_ratio + val_ratio))
        val_end = int(val_candidates[np.abs(val_candidates - val_target).argmin()])
    else:
        train_end = int(len(ordered) * train_ratio)
        val_end = int(len(ordered) * (train_ratio + val_ratio))

    return (
        ordered.iloc[:train_end].copy(),
        ordered.iloc[train_end:val_end].copy(),
        ordered.iloc[val_end:].copy(),
    )


# Canonical column mapping: maps CICFlowMeter verbose / title-cased names to lowercase snake_case
COLUMN_CANONICAL_MAP = {
    "Flow ID": "flow_id",
    "Src IP": "src_ip",
    "Source_IP": "src_ip",
    "Src_IP": "src_ip",
    "Source.IP": "src_ip",
    "Src.IP": "src_ip",
    "Source Address": "src_ip",
    "Src Address": "src_ip",
    "Src Addr": "src_ip",
    "src_addr": "src_ip",
    "src_ip": "src_ip",
    "Dst IP": "dst_ip",
    "Destination_IP": "dst_ip",
    "Dst_IP": "dst_ip",
    "Destination.IP": "dst_ip",
    "Dst.IP": "dst_ip",
    "Destination Address": "dst_ip",
    "Dst Address": "dst_ip",
    "Dst Addr": "dst_ip",
    "dst_addr": "dst_ip",
    "dst_ip": "dst_ip",
    "Src Port": "src_port",
    "Source_Port": "src_port",
    "Src_Port": "src_port",
    "Source.Port": "src_port",
    "Src.Port": "src_port",
    "sport": "src_port",
    "src_port": "src_port",
    "Destination Port": "dst_port",
    "Dst Port": "dst_port",
    "Destination_Port": "dst_port",
    "Dst_Port": "dst_port",
    "Destination.Port": "dst_port",
    "Dst.Port": "dst_port",
    "dport": "dst_port",
    "dst_port": "dst_port",
    "Proto": "protocol",
    "proto": "protocol",
    "Protocol Name": "protocol",
    "Time Stamp": "timestamp",
    "Time_Stamp": "timestamp",
    "Date / Time": "timestamp",
    "Date/Time": "timestamp",
    "Date_Time": "timestamp",
    "DateTime": "timestamp",
    "ts_start": "timestamp",
    "Label_Raw": "label",
    "label_raw": "label",
    "Class": "label",
    "class": "label",
    "Flow_ID": "flow_id",
    "Flow.ID": "flow_id",
    "totlen_fwd_pkts": "tot_len_fwd_pkts",
    "totlen_bwd_pkts": "tot_len_bwd_pkts",
    "flow_byts_s": "flow_bytes_s",
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

def _normalize_header(name: str) -> str:
    """Normalize a header name by stripping whitespace, removing non-alphanumeric chars, and lowercasing."""
    return re.sub(r"[^a-zA-Z0-9]+", "", str(name).strip()).lower()


# Normalized reverse lookup for case/delimiter-insensitive header resolution
NORMALIZED_CANONICAL_MAP: Dict[str, str] = {
    _normalize_header(k): v for k, v in COLUMN_CANONICAL_MAP.items()
}

# Additional normalized synonyms for common telemetry and CIC-IDS2017 variations
NORMALIZED_CANONICAL_MAP.update({
    "srcip": "src_ip",
    "sourceip": "src_ip",
    "srcaddr": "src_ip",
    "sourceaddr": "src_ip",
    "srcaddress": "src_ip",
    "sourceaddress": "src_ip",
    "sport": "src_port",
    "dstip": "dst_ip",
    "destip": "dst_ip",
    "destinationip": "dst_ip",
    "dstaddr": "dst_ip",
    "destaddr": "dst_ip",
    "destinationaddr": "dst_ip",
    "dstaddress": "dst_ip",
    "destinationaddress": "dst_ip",
    "dport": "dst_port",
    "srcport": "src_port",
    "sourceport": "src_port",
    "dstport": "dst_port",
    "destport": "dst_port",
    "destinationport": "dst_port",
    "protocol": "protocol",
    "proto": "protocol",
    "protocolname": "protocol",
    "timestamp": "timestamp",
    "datetime": "timestamp",
    "dateandtime": "timestamp",
    "tsstart": "timestamp",
    "ts": "timestamp",
    "flowid": "flow_id",
    "label": "label",
    "labelraw": "label",
    "class": "label",
    "target": "label",
    "totlenfwdpkts": "tot_len_fwd_pkts",
    "totallengthoffwdpackets": "tot_len_fwd_pkts",
    "totallengthoffwdpacket": "tot_len_fwd_pkts",
    "totlenbwdpkts": "tot_len_bwd_pkts",
    "totallengthofbwdpackets": "tot_len_bwd_pkts",
    "totallengthofbwdpacket": "tot_len_bwd_pkts",
    "flowbytss": "flow_bytes_s",
    "flowbyts": "flow_bytes_s",
    "flowpktss": "flow_pkts_s",
    "flowpacketss": "flow_pkts_s",
    "flowduration": "flow_duration",
    "duration": "flow_duration",
})


def standardize_flow_columns(df: pd.DataFrame) -> pd.DataFrame:
    """
    Standardizes raw DataFrame column headers to EviGraph's canonical schema.
    Handles:
    - Case-insensitivity (e.g. 'SOURCE IP', 'source ip')
    - Surrounding and internal whitespace
    - Punctuation differences: dots, hyphens, underscores, slashes (e.g. 'Source.IP', 'Date / Time')
    - Equivalent naming aliases for metadata (e.g. 'Src IP' -> 'src_ip', 'Dst Port' -> 'dst_port')
    - Feature columns needed by XGBoost and GNN detectors (e.g. 'tot_len_fwd_pkts')
    - Preserves existing canonical columns and avoids overwriting them with duplicates.
    """
    if df.empty and len(df.columns) == 0:
        return df

    raw_columns = [str(c).strip() for c in df.columns]
    existing_canonical = {c for c in raw_columns if c in CANONICAL_FEATURES or c in METADATA_COLS}

    rename_map: Dict[str, str] = {}
    for orig_col, stripped in zip(df.columns, raw_columns):
        if stripped in CANONICAL_FEATURES or stripped in METADATA_COLS:
            if orig_col != stripped:
                rename_map[orig_col] = stripped
            continue

        if stripped in COLUMN_CANONICAL_MAP:
            target = COLUMN_CANONICAL_MAP[stripped]
            if target not in existing_canonical or orig_col == target:
                rename_map[orig_col] = target
                existing_canonical.add(target)
                continue

        norm = _normalize_header(stripped)
        if norm in NORMALIZED_CANONICAL_MAP:
            target = NORMALIZED_CANONICAL_MAP[norm]
            if target not in existing_canonical or orig_col == target:
                rename_map[orig_col] = target
                existing_canonical.add(target)
                continue

        if orig_col != stripped:
            rename_map[orig_col] = stripped

    df = df.rename(columns=rename_map)
    df = df.loc[:, ~df.columns.duplicated()]

    # Dual-populate common feature alias pairs to guarantee compatibility across detectors
    if "tot_len_fwd_pkts" in df.columns and "totlen_fwd_pkts" not in df.columns:
        df["totlen_fwd_pkts"] = df["tot_len_fwd_pkts"]
    elif "totlen_fwd_pkts" in df.columns and "tot_len_fwd_pkts" not in df.columns:
        df["tot_len_fwd_pkts"] = df["totlen_fwd_pkts"]

    if "tot_len_bwd_pkts" in df.columns and "totlen_bwd_pkts" not in df.columns:
        df["totlen_bwd_pkts"] = df["tot_len_bwd_pkts"]
    elif "totlen_bwd_pkts" in df.columns and "tot_len_bwd_pkts" not in df.columns:
        df["tot_len_bwd_pkts"] = df["totlen_bwd_pkts"]

    if "flow_bytes_s" in df.columns and "flow_byts_s" not in df.columns:
        df["flow_byts_s"] = df["flow_bytes_s"]
    elif "flow_byts_s" in df.columns and "flow_bytes_s" not in df.columns:
        df["flow_bytes_s"] = df["flow_byts_s"]

    return df

class FlowDataLoader:
    def __init__(self, metadata_cols: Optional[List[str]] = None):
        self.metadata_cols = metadata_cols or METADATA_COLS
        self.feature_columns: List[str] = []

    def clean_dataset(self, df: pd.DataFrame, drop_missing: bool = True) -> pd.DataFrame:
        """Removes infinite/NaN values and duplicates (TRD FR-2.5)."""
        initial_len = len(df)
        
        # Standardize column names to canonical schema
        df = standardize_flow_columns(df)

        # Clean label strings (strip spaces, replace non-standard dashes, standardize BENIGN)
        if "label" in df.columns:
            df["label"] = df["label"].astype(str).str.replace('\x96', '-').str.strip()
            df["label"] = df["label"].replace({"Normal": "BENIGN"})

        # Replace Inf with NaN, then fill or drop
        df = df.replace([np.inf, -np.inf], np.nan)
        if drop_missing:
            df = df.dropna(subset=[c for c in df.columns if c not in self.metadata_cols])
        
        # Deduplicate
        df = df.drop_duplicates()

        # Memory optimization: downcast float64 to float32
        float_cols = df.select_dtypes(include=["float64"]).columns
        if len(float_cols) > 0:
            df[float_cols] = df[float_cols].astype("float32")
        
        print(f"[DataLoader] Cleaned dataset: {initial_len} -> {len(df)} rows ({initial_len - len(df)} dropped)")
        return df

    def prepare_temporal_split(
        self, 
        df: pd.DataFrame, 
        train_ratio: float = 0.60,
        val_ratio: float = 0.20,
        per_class: bool = False
    ):
        """
        Sorts chronologically and splits into Train/Val/Test temporally (TRD Sec 3.3.5).
        The default split uses global chronological boundaries. Per-class splitting is an
        explicit opt-in for callers that accept overlapping time ranges between partitions.
        Returns: (X_train, y_train, meta_train, X_val, y_val, meta_val, X_test, y_test, meta_test)
        """
        if per_class and "label" in df.columns:
            df = df.copy()
            if "timestamp" in df.columns:
                df["timestamp"] = pd.to_datetime(
                    df["timestamp"], format="mixed", errors="coerce"
                )
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
            train_df, val_df, test_df = split_temporally(df, train_ratio, val_ratio)

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

    def load_dataset(
        self,
        file_path: Path,
        max_rows: Optional[int] = None,
        *,
        drop_missing: bool = True,
    ) -> pd.DataFrame:
        print(f"[DataLoader] Reading flows from {file_path}")
        if Path(file_path).suffix.lower() == ".parquet":
            df = pd.read_parquet(file_path)
        else:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f_peek:
                first_line = f_peek.readline()
                sep = ";" if ";" in first_line else ","
            df = pd.read_csv(file_path, sep=sep)
            
        # Standardize known column names
        df = standardize_flow_columns(df)
        
        # Clean label strings
        if "label" in df.columns:
            df["label"] = df["label"].astype(str).str.replace('\x96', '-').str.strip()
            df["label"] = df["label"].replace({"Normal": "BENIGN"})
        
        if max_rows and len(df) > max_rows:
            if "timestamp" in df.columns:
                df["timestamp"] = pd.to_datetime(df["timestamp"], format="mixed", errors="coerce")
                df = df.sort_values(by="timestamp")
            df = df.iloc[:max_rows].copy()
        
        # Remove exact duplicate source rows before synthetic row IDs distinguish them.
        # Existing distinct flow IDs remain distinct, even for otherwise identical rows.
        if "flow_id" not in df.columns:
            df = df.drop_duplicates()

        # Ensure flow_id exists and preserve missing IDs for callers that can replace them
        # with source-bound identifiers.
        if "flow_id" not in df.columns:
            df["flow_id"] = [f"flw_{i:07d}" for i in range(len(df))]
        else:
            df["flow_id"] = df["flow_id"].astype("string")
            
        if "evidence_id" not in df.columns:
            df["evidence_id"] = file_path.stem
            
        return self.clean_dataset(df, drop_missing=drop_missing)

    def load_from_csv(self, file_path: Path) -> pd.DataFrame:
        return self.load_dataset(file_path)

    def load_processed_splits(
        self,
        split_prefix: str = "benchmark"
    ):
        """
        Loads pre-saved processed splits directly from `data/processed/`.
        Returns: (X_train, y_train, meta_train, X_val, y_val, meta_val, X_test, y_test, meta_test)
        """
        from src.config import PROCESSED_DATA_DIR
        train_path = PROCESSED_DATA_DIR / f"{split_prefix}_train_flows.parquet"
        val_path = PROCESSED_DATA_DIR / f"{split_prefix}_val_flows.parquet"
        test_path = PROCESSED_DATA_DIR / f"{split_prefix}_test_flows.parquet"

        if not (train_path.exists() and val_path.exists() and test_path.exists()):
            raise FileNotFoundError(f"Processed splits not found in {PROCESSED_DATA_DIR}. Run 'python -m src.export_training_data' first.")

        train_df = pd.read_parquet(train_path)
        val_df = pd.read_parquet(val_path)
        test_df = pd.read_parquet(test_path)

        self.feature_columns = [
            c for c in train_df.columns 
            if c not in self.metadata_cols and pd.api.types.is_numeric_dtype(train_df[c])
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

        print(f"[DataLoader] Loaded Pre-saved Splits: Train={len(X_train):,}, Val={len(X_val):,}, Test={len(X_test):,}")
        return X_train, y_train, meta_train, X_val, y_val, meta_val, X_test, y_test, meta_test

    def load_combined_dataset(
        self, 
        file_paths: Optional[List[Path]] = None, 
        max_per_attack: Optional[int] = None,
        benign_per_file: Optional[int] = None
    ) -> pd.DataFrame:
        """
        Loads and combines all attack captures into a unified multi-class enterprise dataset.
        Includes CICIDS2017 parquet captures and USP datasets (e.g. NIDS2025 RCE CSV).
        When max_per_attack and benign_per_file are None, loads the full 2.64M+ dataset.
        """
        from src.config import RAW_DATA_DIR
        if file_paths is None:
            file_paths = sorted(list(RAW_DATA_DIR.glob("*.parquet")) + list(RAW_DATA_DIR.glob("*.csv")))

        dfs = []
        for f in file_paths:
            print(f"[DataLoader] Ingesting attack slice from: {f.name}")
            df_full = self.load_dataset(f)
            
            # Separate Benign and Attacks
            if benign_per_file is not None:
                benign_df = df_full[df_full["label"] == "BENIGN"].head(benign_per_file)
            else:
                benign_df = df_full[df_full["label"] == "BENIGN"]
            
            # Group attacks by class and cap each class individually if specified
            attack_slices = []
            for atk_cls in df_full[df_full["label"] != "BENIGN"]["label"].unique():
                cls_df = df_full[df_full["label"] == atk_cls]
                if max_per_attack is not None and len(cls_df) > max_per_attack:
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

        # Downcast float64 to float32 to reduce memory footprint by 50%
        float_cols = combined_df.select_dtypes(include=["float64"]).columns
        if len(float_cols) > 0:
            combined_df[float_cols] = combined_df[float_cols].astype("float32")

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
