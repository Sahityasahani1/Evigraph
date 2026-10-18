"""
Public Telemetry Query API
Provides programmatic access to indexed network telemetry for detection, graph, and forensic agent layers.
"""

from pathlib import Path
from typing import Any, Dict, Optional

import pandas as pd

from data.storage import DuckDBCatalog


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

    def get_features(
        self,
        flow_ids: Optional[list[str]] = None,
        df: Optional[pd.DataFrame] = None,
        limit: Optional[int] = None,
        unprefixed: bool = True
    ) -> pd.DataFrame:
        """
        Retrieves flow feature matrix reading FEATURE_COLUMNS only.
        Guarantees zero metadata or host feature leakage.
        """
        import numpy as np

        from data.config import FEATURE_COLUMNS

        if df is not None:
            out = pd.DataFrame(index=df.index)
            for col in FEATURE_COLUMNS:
                feat_col = f"feat_{col}"
                target_col = col if unprefixed else feat_col
                if feat_col in df.columns:
                    out[target_col] = df[feat_col].astype("float32")
                elif col in df.columns:
                    out[target_col] = df[col].astype("float32")
                else:
                    out[target_col] = np.float32(0.0)

            out = out.replace([np.inf, -np.inf], np.nan).fillna(0.0)
            return out

        feat_cols = [f"feat_{c}" for c in FEATURE_COLUMNS]
        cols_sql = ", ".join(feat_cols)
        sql = f"SELECT {cols_sql} FROM flows"

        if flow_ids:
            quote = "'"
            double_quote = "''"
            clean_ids = [f"'{fid.replace(quote, double_quote)}'" for fid in flow_ids]
            sql += f" WHERE flow_id IN ({', '.join(clean_ids)})"

        if limit:
            sql += f" LIMIT {int(limit)}"

        res = self.catalog.query(sql)
        if res.empty:
            cols = list(FEATURE_COLUMNS) if unprefixed else feat_cols
            return pd.DataFrame(columns=cols, dtype="float32")

        if unprefixed:
            rename_map = {f"feat_{c}": c for c in FEATURE_COLUMNS}
            res = res.rename(columns=rename_map)

        res = res.astype("float32").replace([np.inf, -np.inf], np.nan).fillna(0.0)
        return res

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

        from data.adapters import export_member2
        from data.config import settings

        proc_dir = settings.resolve_path(settings.processed_dir)
        p_train = export_member2(proc_dir / f"{split_prefix}_train_flows.parquet", train_df, split="train")
        p_val = export_member2(proc_dir / f"{split_prefix}_val_flows.parquet", val_df, split="val")
        p_test = export_member2(proc_dir / f"{split_prefix}_test_flows.parquet", test_df, split="test")

        return {
            "train": p_train,
            "val": p_val,
            "test": p_test
        }
