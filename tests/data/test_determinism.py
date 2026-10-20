"""
Determinism & Reproducibility Verification Test
Adheres to Task 4:
- Runs the pipeline twice on a fixed 10,000-row sample from Tuesday-WorkingHours.pcap_ISCX.csv
  into two separate isolated temporary directories.
- Asserts identical flow_id sets.
- Asserts identical export content hash (hash of rows sorted by flow_id, NOT parquet file bytes).
- Asserts that verify_chain() passes on both isolated directories.
"""

import hashlib
from pathlib import Path

import pandas as pd
import pytest

from data.adapters import export_member2
from data.config import DataPipelineSettings
from data.evidence import EvidenceStore, verify_chain
from data.features.host import HostFeatureExtractor
from data.parsers import parse_cicids
from data.schema import validate_and_canonicalize
from data.storage import ParquetStorageEngine


def run_pipeline_on_sample(input_csv: Path, target_dir: Path, n_rows: int = 10000) -> pd.DataFrame:
    """Runs the complete pipeline in an isolated target directory and returns the Member 2 export DataFrame."""
    # 1. Configure isolated directory settings
    proc_dir = target_dir / "data" / "processed"
    evid_dir = target_dir / "data" / "evidence"
    proc_dir.mkdir(parents=True, exist_ok=True)
    evid_dir.mkdir(parents=True, exist_ok=True)

    isolated_settings = DataPipelineSettings(
        base_dir=target_dir,
        processed_dir=proc_dir,
        evidence_dir=evid_dir,
        audit_log_path=proc_dir / "audit_log.jsonl",
        evidence_parquet_path=proc_dir / "evidence_files.parquet",
        duckdb_catalog_path=proc_dir / "catalog.duckdb",
        host_features_parquet_path=proc_dir / "host_features.parquet",
    )

    # 2. Stage 1: Ingest & Register raw evidence
    store = EvidenceStore(settings=isolated_settings)
    ev_record = store.register_evidence(input_csv, source_description="Determinism test capture")
    ev_id = ev_record["evidence_id"]

    # 3. Stage 2: Parse and Clean
    df_raw = parse_cicids(input_csv, evidence_id=ev_id, max_rows=n_rows)
    assert not df_raw.empty
    assert len(df_raw) > 0

    df_clean = validate_and_canonicalize(df_raw)

    # 4. Stage 3: Features (Host features extraction)
    host_extractor = HostFeatureExtractor(time_window_secs=300)
    host_df = host_extractor.compute_host_metrics(df_clean)
    host_extractor.save_host_features(host_df, out_path=isolated_settings.host_features_parquet_path)

    # 5. Stage 4: Storage
    storage = ParquetStorageEngine(output_dir=proc_dir)
    storage.write_parquet(df_clean, "flows.parquet", sidecar_manifest=True)

    # 6. Stage 5: Verify chain
    assert store.verify()

    # 7. Stage 6: Export Member 2
    out_m2_path = proc_dir / "member2_flows.parquet"
    export_member2(out_m2_path, df=df_clean)

    # Return exported DataFrame
    return pd.read_parquet(out_m2_path)


def test_pipeline_determinism(tmp_path):
    """Verifies 100% deterministic output across independent pipeline executions."""
    sample_csv = Path("data/samples/Tuesday-WorkingHours.pcap_ISCX.csv")
    if not sample_csv.exists():
        pytest.skip(f"Sample file {sample_csv} not found.")

    dir_a = tmp_path / "run_a"
    dir_b = tmp_path / "run_b"

    n_sample_rows = 10000

    # Run execution A
    df_a = run_pipeline_on_sample(sample_csv, dir_a, n_rows=n_sample_rows)

    # Run execution B
    df_b = run_pipeline_on_sample(sample_csv, dir_b, n_rows=n_sample_rows)

    # 1. Assert identical row counts
    assert len(df_a) == len(df_b)
    assert len(df_a) > 0

    # 2. Assert identical flow_id sets
    flow_ids_a = set(df_a["flow_id"])
    flow_ids_b = set(df_b["flow_id"])
    assert flow_ids_a == flow_ids_b
    assert len(flow_ids_a) == len(df_a)

    # 3. Assert identical export content hash
    # Sort both by flow_id and compute cryptographic hash of normalized content
    sorted_a = df_a.sort_values(by="flow_id").reset_index(drop=True)
    sorted_b = df_b.sort_values(by="flow_id").reset_index(drop=True)

    content_str_a = sorted_a.to_csv(index=False)
    content_str_b = sorted_b.to_csv(index=False)

    hash_a = hashlib.sha256(content_str_a.encode("utf-8")).hexdigest()
    hash_b = hashlib.sha256(content_str_b.encode("utf-8")).hexdigest()

    assert hash_a == hash_b, "Content hash mismatch between independent pipeline runs!"
