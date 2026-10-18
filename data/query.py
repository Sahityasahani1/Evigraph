"""
Public Telemetry Query API
Provides programmatic access to indexed network telemetry for detection, graph, and forensic agent layers.
"""

from pathlib import Path
from typing import Any, Dict, Optional

import pandas as pd

from data.storage import DuckDBCatalog, ParquetStorageEngine


class QueryAPI:
    """Public query interface for downstream members (Detection, Reasoning, UI)."""

    def __init__(self, catalog: Optional[DuckDBCatalog] = None):
        self.catalog = catalog or DuckDBCatalog()

    def get_flow_by_id(self, flow_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves exact telemetry for a single flow by its unique identifier."""
        clean_fid = str(flow_id).replace("'", "''")
        df = self.catalog.query(f"SELECT * FROM flows WHERE flow_id = '{clean_fid}' LIMIT 1")
        if df.empty:
            return None
        return df.iloc[0].to_dict()

    def get_flows_for_host(self, host_ip: str, limit: int = 1000) -> pd.DataFrame:
        """Retrieves all flows where the host participated as source or destination."""
        clean_ip = str(host_ip).replace("'", "''")
        return self.catalog.query(f"""
            SELECT * FROM flows
            WHERE src_ip = '{clean_ip}' OR dst_ip = '{clean_ip}'
            ORDER BY timestamp
            LIMIT {int(limit)}
        """)

    def get_flows_between(self, src_ip: str, dst_ip: str, limit: int = 1000) -> pd.DataFrame:
        """Retrieves flows communicating directly between two hosts."""
        s = str(src_ip).replace("'", "''")
        d = str(dst_ip).replace("'", "''")
        return self.catalog.query(f"""
            SELECT * FROM flows
            WHERE (src_ip = '{s}' AND dst_ip = '{d}')
               OR (src_ip = '{d}' AND dst_ip = '{s}')
            ORDER BY timestamp
            LIMIT {int(limit)}
        """)

    def get_flows_in_window(self, start_time: str, end_time: str, limit: int = 50000) -> pd.DataFrame:
        """Retrieves flows within a specific temporal window."""
        t1 = str(start_time).replace("'", "''")
        t2 = str(end_time).replace("'", "''")
        return self.catalog.query(f"""
            SELECT * FROM flows
            WHERE timestamp >= '{t1}' AND timestamp <= '{t2}'
            ORDER BY timestamp
            LIMIT {int(limit)}
        """)

    def execute_sql(self, sql_query: str) -> pd.DataFrame:
        """Executes an arbitrary SQL query against the DuckDB catalog."""
        return self.catalog.query(sql_query)

    def export_splits_for_member2(
        self,
        train_ratio: float = 0.60,
        val_ratio: float = 0.20,
        split_prefix: str = "benchmark"
    ) -> Dict[str, Path]:
        """
        Creates stratified temporal train (60%), validation (20%), and test (20%) splits
        saved directly into `data/processed/` matching Member 2's `load_processed_splits()`.
        """
        flows_df = self.catalog.query("SELECT * FROM flows ORDER BY timestamp")
        if flows_df.empty:
            raise ValueError("No flows available in catalog to split.")

        train_dfs, val_dfs, test_dfs = [], [], []
        for _, group in flows_df.groupby("label"):
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

        storage = ParquetStorageEngine()
        p_train = storage.write_parquet(train_df, f"{split_prefix}_train_flows.parquet")
        p_val = storage.write_parquet(val_df, f"{split_prefix}_val_flows.parquet")
        p_test = storage.write_parquet(test_df, f"{split_prefix}_test_flows.parquet")

        return {
            "train": p_train,
            "val": p_val,
            "test": p_test
        }
