"""
Flow Feature Extraction Engine
Extracts 35 canonical statistical flow features under strict anti-leakage isolation rules (TRD Sec 3.2).
Guarantees IPs, ports, and absolute timestamps are never exposed as ML training features.
"""

from typing import List, Tuple

import numpy as np
import pandas as pd

from evigraph.data.schema import validate_and_canonicalize

# Metadata columns to isolate from ML training
METADATA_COLUMNS = [
    "flow_id", "timestamp", "src_ip", "dst_ip", "src_port", "dst_port",
    "protocol", "evidence_id", "label", "src_mac", "dst_mac"
]

CANONICAL_FEATURE_NAMES = [
    "flow_duration", "tot_fwd_pkts", "tot_bwd_pkts", "tot_len_fwd_pkts",
    "tot_len_bwd_pkts", "fwd_pkt_len_max", "fwd_pkt_len_min", "fwd_pkt_len_mean",
    "fwd_pkt_len_std", "bwd_pkt_len_max", "bwd_pkt_len_min", "bwd_pkt_len_mean",
    "bwd_pkt_len_std", "flow_bytes_s", "flow_pkts_s", "flow_iat_mean",
    "flow_iat_std", "flow_iat_max", "flow_iat_min", "fwd_iat_tot", "bwd_iat_tot",
    "fwd_psh_flags", "bwd_psh_flags", "fwd_urg_flags", "bwd_urg_flags",
    "fin_flag_cnt", "syn_flag_cnt", "rst_flag_cnt", "psh_flag_cnt", "ack_flag_cnt",
    "urg_flag_cnt", "down_up_ratio", "pkt_size_avg", "init_fwd_win_byts",
    "init_bwd_win_byts"
]


class FlowFeatureExtractor:
    """Extracts, standardizes, and isolates numerical flow features for model consumption."""

    def __init__(self, feature_columns: List[str] | None = None):
        self.feature_columns = feature_columns or CANONICAL_FEATURE_NAMES

    def extract_features(
        self,
        df: pd.DataFrame
    ) -> Tuple[pd.DataFrame, pd.DataFrame]:
        """
        Splits canonical flow DataFrame into:
        - X (numerical features only, zero IP/timestamp leakage)
        - meta (identity, timestamps, and graph routing information)
        """
        df_clean = validate_and_canonicalize(df)

        meta_cols_present = [c for c in METADATA_COLUMNS if c in df_clean.columns]
        meta_df = df_clean[meta_cols_present].copy()

        # Populate any missing canonical features with 0.0
        X_df = pd.DataFrame(index=df_clean.index)
        for col in self.feature_columns:
            if col in df_clean.columns:
                X_df[col] = df_clean[col].astype(np.float32)
            else:
                X_df[col] = np.float32(0.0)

        # Replace infs and NaNs
        X_df = X_df.replace([np.inf, -np.inf], np.nan).fillna(0.0)

        return X_df, meta_df

    def compute_rate_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Computes or re-computes flow_bytes_s and flow_pkts_s from duration and packet counts."""
        df = df.copy()
        if "flow_duration" in df.columns:
            dur_sec = (df["flow_duration"] / 1e6).replace(0.0, np.nan)
            tot_bytes = df.get("tot_len_fwd_pkts", 0) + df.get("tot_len_bwd_pkts", 0)
            tot_pkts = df.get("tot_fwd_pkts", 0) + df.get("tot_bwd_pkts", 0)
            df["flow_bytes_s"] = (tot_bytes / dur_sec).fillna(0.0).astype(np.float32)
            df["flow_pkts_s"] = (tot_pkts / dur_sec).fillna(0.0).astype(np.float32)
        return df
