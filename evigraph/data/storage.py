"""
Storage & DuckDB Telemetry Catalog Engine
Handles high-throughput snappy Parquet serialization and zero-copy DuckDB analytical cataloging.
"""

from pathlib import Path
from typing import Any, Dict, Optional

import duckdb
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

from evigraph.data.config import settings
from evigraph.data.evidence import AuditLogger
from evigraph.data.schema import validate_and_canonicalize


class ParquetStorageEngine:
    """Writes standardized, snappy-compressed Parquet files matching Member 2's specifications."""

    def __init__(self, output_dir: Optional[Path] = None):
        self.output_dir = settings.resolve_path(output_dir or settings.processed_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.logger = AuditLogger()

    def write_parquet(
        self,
        df: pd.DataFrame,
        filename: str,
        compression: str = "snappy"
    ) -> Path:
        """
        Validates, canonicalizes, and writes a DataFrame to snappy/zstd compressed Parquet.
        Records an audit action upon completion.
        """
        df_clean = validate_and_canonicalize(df)
        out_path = self.output_dir / filename

        # Convert to PyArrow table
        table = pa.Table.from_pandas(df_clean, preserve_index=False)
        pq.write_table(table, out_path, compression=compression)

        self.logger.log_action(
            action="WRITE_PARQUET",
            params={"rows": len(df_clean), "columns": len(df_clean.columns), "compression": compression},
            output_files=[str(out_path)]
        )

        return out_path


class DuckDBCatalog:
    """
    Embedded DuckDB SQL catalog providing instant analytical queries across Parquet captures
    without loading full datasets into RAM.
    """

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = settings.resolve_path(db_path or settings.duckdb_catalog_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = duckdb.connect(str(self.db_path))
        self._init_views()

    def _init_views(self):
        """Creates unified views over processed Parquet files if they exist."""
        proc_dir = settings.resolve_path(settings.processed_dir)
        parquet_files = list(proc_dir.glob("*.parquet"))
        if parquet_files:
            file_pattern = str(proc_dir / "*.parquet").replace("\\", "/")
            try:
                self.conn.execute(f"""
                    CREATE OR REPLACE VIEW flows AS
                    SELECT * FROM read_parquet('{file_pattern}')
                """)
            except Exception:
                pass

    def refresh(self):
        """Refreshes DuckDB views against disk."""
        self._init_views()

    def query(self, sql: str) -> pd.DataFrame:
        """Executes a SQL query against the catalog and returns a pandas DataFrame."""
        self.refresh()
        return self.conn.execute(sql).df()

    def count_flows(self) -> int:
        """Returns the total number of indexed flows in the catalog."""
        try:
            res = self.query("SELECT COUNT(*) AS total FROM flows")
            return int(res["total"].iloc[0])
        except Exception:
            return 0

    def get_catalog_summary(self) -> Dict[str, Any]:
        """Returns summary statistics of the indexed dataset."""
        try:
            total = self.count_flows()
            if total == 0:
                return {"total_flows": 0, "status": "empty"}

            classes = self.query("SELECT label, COUNT(*) AS count FROM flows GROUP BY label ORDER BY count DESC")
            hosts = self.query("SELECT COUNT(DISTINCT src_ip) + COUNT(DISTINCT dst_ip) AS total_hosts FROM flows")
            timerange = self.query("SELECT MIN(timestamp) AS start_time, MAX(timestamp) AS end_time FROM flows")

            return {
                "total_flows": total,
                "total_hosts": int(hosts["total_hosts"].iloc[0]) if not hosts.empty else 0,
                "time_range": {
                    "start": str(timerange["start_time"].iloc[0]),
                    "end": str(timerange["end_time"].iloc[0])
                },
                "class_distribution": classes.set_index("label")["count"].to_dict()
            }
        except Exception as e:
            return {"error": str(e), "total_flows": 0}

    def close(self):
        """Closes DuckDB connection cleanly."""
        self.conn.close()
