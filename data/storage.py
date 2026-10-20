import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Optional

import duckdb
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

from data.config import settings
from data.evidence import AuditLogger
from data.schema import validate_and_canonicalize


class ParquetStorageEngine:
    """Writes standardized, snappy-compressed Parquet files matching Member 2's specifications."""

    def __init__(self, output_dir: Optional[Path] = None):
        self.output_dir = settings.resolve_path(output_dir or settings.processed_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.logger = AuditLogger()

    def write_manifest(self, file_path: Path, df: pd.DataFrame) -> Path:
        """Writes sidecar <name>.manifest.json with row count, column list, and sha256."""
        sha256 = hashlib.sha256(file_path.read_bytes()).hexdigest()
        manifest_data = {
            "filename": file_path.name,
            "row_count": len(df),
            "column_list": list(df.columns),
            "sha256": sha256,
        }
        manifest_path = file_path.parent / f"{file_path.name}.manifest.json"
        manifest_path.write_text(json.dumps(manifest_data, indent=2), encoding="utf-8")
        return manifest_path

    def write_parquet(
        self,
        df: pd.DataFrame,
        filename: str,
        compression: str = "snappy",
        sidecar_manifest: bool = False
    ) -> Path:
        """
        Validates, canonicalizes, and writes a DataFrame to snappy/zstd compressed Parquet.
        Optionally writes a sidecar manifest and records an audit action upon completion.
        """
        df_clean = validate_and_canonicalize(df)
        out_path = self.output_dir / filename

        # Convert to PyArrow table
        table = pa.Table.from_pandas(df_clean, preserve_index=False)
        pq.write_table(table, out_path, compression=compression)

        output_files = [str(out_path)]
        if sidecar_manifest:
            m_path = self.write_manifest(out_path, df_clean)
            output_files.append(str(m_path))

        self.logger.log_action(
            action="WRITE_PARQUET",
            params={"rows": len(df_clean), "columns": len(df_clean.columns), "compression": compression},
            output_files=output_files
        )

        return out_path


class DuckDBCatalog:
    """
    Embedded DuckDB SQL catalog providing instant analytical queries across Parquet captures
    without loading full datasets into RAM.
    """

    NON_FLOW_FILES = {
        "host_features.parquet",
        "dns_events.parquet",
        "http_events.parquet",
        "tls_events.parquet",
        "ssl_events.parquet",
        "evidence_files.parquet",
    }

    def __init__(self, db_path: Optional[Path] = None, processed_dir: Optional[Path] = None):
        self.db_path = settings.resolve_path(db_path or settings.duckdb_catalog_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.processed_dir = (
            Path(processed_dir)
            if processed_dir
            else (self.db_path.parent if db_path else settings.resolve_path(settings.processed_dir))
        )
        self.conn = duckdb.connect(str(self.db_path))
        self._init_views()

    def _init_views(self):
        """Creates unified views over processed Parquet files if they exist."""
        proc_dir = self.processed_dir
        if not proc_dir.exists():
            return
        parquet_files = list(proc_dir.glob("*.parquet"))
        if not parquet_files:
            return

        # 1. Flow view: only include flow parquet files (isolate host_features, metadata, etc.)
        flow_files = [
            str(p).replace("\\", "/") for p in parquet_files if p.name not in self.NON_FLOW_FILES
        ]
        if flow_files:
            try:
                files_str = ", ".join(f"'{f}'" for f in flow_files)
                self.conn.execute(f"""
                    CREATE OR REPLACE VIEW flows AS
                    SELECT * FROM read_parquet([{files_str}])
                """)
            except Exception:
                pass

        # 2. Host features view
        host_feat_path = proc_dir / "host_features.parquet"
        if host_feat_path.exists():
            try:
                h_path_str = str(host_feat_path).replace("\\", "/")
                self.conn.execute(f"""
                    CREATE OR REPLACE VIEW host_features AS
                    SELECT * FROM read_parquet('{h_path_str}')
                """)
            except Exception:
                pass

        # 3. Metadata event views (DNS, HTTP, SSL/TLS)
        for view_name, fname in [
            ("dns_events", "dns_events.parquet"),
            ("http_events", "http_events.parquet"),
            ("tls_events", "tls_events.parquet"),
            ("ssl_events", "ssl_events.parquet"),
        ]:
            meta_path = proc_dir / fname
            if meta_path.exists():
                try:
                    m_path_str = str(meta_path).replace("\\", "/")
                    self.conn.execute(f"""
                        CREATE OR REPLACE VIEW {view_name} AS
                        SELECT * FROM read_parquet('{m_path_str}')
                    """)
                except Exception:
                    pass

    def refresh(self):
        """Refreshes DuckDB views against disk."""
        self._init_views()

    def query(self, sql: str) -> pd.DataFrame:
        """Executes a SQL query against the catalog and returns a pandas DataFrame."""
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
