"""
Host Behavioral & Communication Graph Feature Extractor
Extracts time-windowed host behavioral metrics (degrees, fan-out, port diversity, volumes).
"""

import numpy as np
import pandas as pd


class HostFeatureExtractor:
    """Computes vectorized host-level behavioral features over time-windowed network traffic."""

    def __init__(self, time_window_secs: int = 300):
        self.time_window_secs = time_window_secs

    def compute_host_metrics(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Computes host-level communication features across all source and destination IPs.
        Returns a DataFrame indexed by host IP.
        """
        if df.empty or "src_ip" not in df.columns or "dst_ip" not in df.columns:
            return pd.DataFrame()

        fwd_bytes_col = "tot_len_fwd_pkts" if "tot_len_fwd_pkts" in df.columns else ("totlen_fwd_pkts" if "totlen_fwd_pkts" in df.columns else None)
        bwd_bytes_col = "tot_len_bwd_pkts" if "tot_len_bwd_pkts" in df.columns else ("totlen_bwd_pkts" if "totlen_bwd_pkts" in df.columns else None)

        # Aggregate Outbound Activity (host as source)
        out_agg = df.groupby("src_ip").agg(
            out_degree=("dst_ip", "count"),
            fan_out=("dst_ip", "nunique"),
            unique_dst_ports=("dst_port", "nunique") if "dst_port" in df.columns else ("dst_ip", "nunique"),
            bytes_sent=(fwd_bytes_col, "sum") if fwd_bytes_col else ("dst_ip", "count"),
            flows_initiated=("flow_id", "count") if "flow_id" in df.columns else ("dst_ip", "count")
        )

        # Aggregate Inbound Activity (host as destination)
        in_agg = df.groupby("dst_ip").agg(
            in_degree=("src_ip", "count"),
            fan_in=("src_ip", "nunique"),
            unique_services_hosted=("dst_port", "nunique") if "dst_port" in df.columns else ("src_ip", "nunique"),
            bytes_recv=(bwd_bytes_col, "sum") if bwd_bytes_col else ("src_ip", "count"),
            flows_received=("flow_id", "count") if "flow_id" in df.columns else ("src_ip", "count")
        )

        all_hosts = sorted(list(set(df["src_ip"]).union(set(df["dst_ip"]))))
        host_df = pd.DataFrame(index=all_hosts)
        host_df.index.name = "host_ip"

        host_df = host_df.join(out_agg).join(in_agg).fillna(0)

        # Calculated host ratios
        tot_deg = host_df["out_degree"] + host_df["in_degree"]
        host_df["in_out_degree_ratio"] = (host_df["in_degree"] / host_df["out_degree"].replace(0, np.nan)).fillna(0.0)
        host_df["total_bytes"] = host_df["bytes_sent"] + host_df["bytes_recv"]
        host_df["log_total_bytes"] = np.log1p(np.maximum(0.0, host_df["total_bytes"]))
        host_df["total_degree"] = tot_deg

        return host_df
