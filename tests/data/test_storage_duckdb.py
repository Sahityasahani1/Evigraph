"""
Tests for Parquet Storage & DuckDB Catalog
"""

import pandas as pd

from data.query import QueryAPI
from data.storage import DuckDBCatalog, ParquetStorageEngine


def test_parquet_storage_and_duckdb(tmp_path):
    storage = ParquetStorageEngine(output_dir=tmp_path)
    df = pd.DataFrame([
        {
            "flow_id": "flw_test_001",
            "src_ip": "192.168.10.5",
            "dst_ip": "8.8.8.8",
            "src_port": 50000,
            "dst_port": 53,
            "protocol": 17,
            "timestamp": "2026-10-18T10:00:00",
            "tot_len_fwd_pkts": 120.0,
            "tot_len_bwd_pkts": 250.0,
            "label": "BENIGN"
        },
        {
            "flow_id": "flw_test_002",
            "src_ip": "172.16.0.100",
            "dst_ip": "192.168.10.5",
            "src_port": 45000,
            "dst_port": 22,
            "protocol": 6,
            "timestamp": "2026-10-18T10:05:00",
            "tot_len_fwd_pkts": 84.0,
            "tot_len_bwd_pkts": 0.0,
            "label": "PortScan"
        }
    ])

    pq_path = storage.write_parquet(df, "test_flows.parquet")
    assert pq_path.exists()

    db_path = tmp_path / "test_catalog.duckdb"
    catalog = DuckDBCatalog(db_path=db_path)
    # Register view over tmp_path parquet
    clean_pq = str(pq_path).replace("\\", "/")
    catalog.conn.execute(f"CREATE OR REPLACE VIEW flows AS SELECT * FROM read_parquet('{clean_pq}')")

    count = catalog.count_flows()
    assert count == 2

    # Query API tests
    api = QueryAPI(catalog=catalog)
    flow = api.get_flow_by_id("flw_test_001")
    assert flow is not None
    assert flow["src_ip"] == "192.168.10.5"

    host_flows = api.get_flows_for_host("192.168.10.5")
    assert len(host_flows) == 2

    catalog.close()
