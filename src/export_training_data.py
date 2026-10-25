"""
EviGraph Training Data Exporter & Manifest Generator
Consolidates and persists all training, validation, and test datasets into `data/processed/`
and generates cryptographic SHA-256 evidence manifests.
"""

import hashlib
import json
import os
from datetime import datetime
from pathlib import Path
import pandas as pd
import numpy as np

from src.config import BASE_DIR, DATA_DIR, PROCESSED_DATA_DIR, RAW_DATA_DIR
from src.data_loader import FlowDataLoader, split_temporally

def compute_sha256(file_path: Path) -> str:
    """Computes SHA-256 checksum of a file for forensic evidence integrity."""
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()

def export_benchmark_splits():
    """
    Loads the 3 new benchmark files (340,000 flows), creates the exact 60/20/20
    temporal splits used to train the models, and persists them into `data/processed/`.
    """
    print("=" * 65)
    print("   EVIGRAPH: EXPORTING TRAINING DATA FILES FOR FUTURE USE")
    print("=" * 65)
    
    PROCESSED_DATA_DIR.mkdir(parents=True, exist_ok=True)
    new_bench_dir = DATA_DIR / "new_benchmark"
    benchmark_files = sorted(list(new_bench_dir.glob("*.parquet")) + list(new_bench_dir.glob("*.csv")))
    
    print(f"\n[1/3] Loading 3 External Benchmark Datasets from: {new_bench_dir}")
    for bf in benchmark_files:
        print(f"   -> {bf.name}")
        
    loader = FlowDataLoader()
    combined_df = loader.load_combined_dataset(file_paths=benchmark_files)
    
    # 1. Save Full Unified Benchmark Dataset
    full_path = PROCESSED_DATA_DIR / "benchmark_full_340k.parquet"
    combined_df.to_parquet(full_path, index=False)
    print(f"\n[OK] Saved Unified Benchmark Dataset: {full_path.name} ({len(combined_df):,} flows)")
    
    # 2. Keep each partition on a disjoint global time horizon.
    print("\n[2/3] Partitioning chronologically into 60% Train / 20% Val / 20% Test splits...")
    train_df, val_df, test_df = split_temporally(
        combined_df, train_ratio=0.60, val_ratio=0.20
    )
    
    # Save Parquet Splits
    train_path = PROCESSED_DATA_DIR / "benchmark_train_flows.parquet"
    val_path = PROCESSED_DATA_DIR / "benchmark_val_flows.parquet"
    test_path = PROCESSED_DATA_DIR / "benchmark_test_flows.parquet"
    
    train_df.to_parquet(train_path, index=False)
    val_df.to_parquet(val_path, index=False)
    test_df.to_parquet(test_path, index=False)
    
    print(f"   * Train Split Saved : {train_path.name} ({len(train_df):,} flows, {os.path.getsize(train_path)/1024/1024:.2f} MB)")
    print(f"   * Val Split Saved   : {val_path.name} ({len(val_df):,} flows, {os.path.getsize(val_path)/1024/1024:.2f} MB)")
    print(f"   * Test Split Saved  : {test_path.name} ({len(test_df):,} flows, {os.path.getsize(test_path)/1024/1024:.2f} MB)")
    
    # 3. Save Inspection Samples (CSV)
    train_sample_csv = PROCESSED_DATA_DIR / "benchmark_train_sample_1000.csv"
    test_sample_csv = PROCESSED_DATA_DIR / "benchmark_test_sample_1000.csv"
    train_df.head(1000).to_csv(train_sample_csv, index=False)
    test_df.head(1000).to_csv(test_sample_csv, index=False)
    print(f"   * CSV Sample Saved  : {train_sample_csv.name}")
    print(f"   * CSV Sample Saved  : {test_sample_csv.name}")

    # 4. Generate Comprehensive Manifest & Catalog
    print("\n[3/3] Generating Cryptographic SHA-256 Evidence Manifest...")
    all_data_files = []
    
    # Check new_benchmark, processed, raw, and samples
    target_dirs = [
        ("processed", PROCESSED_DATA_DIR),
        ("new_benchmark", new_bench_dir),
        ("raw", RAW_DATA_DIR),
        ("samples", DATA_DIR / "samples")
    ]
    
    manifest_records = []
    
    for category, directory in target_dirs:
        if not directory.exists():
            continue
        for f in sorted(directory.iterdir()):
            if f.is_file() and f.suffix in [".parquet", ".csv"]:
                size_bytes = f.stat().st_size
                sha256_hash = compute_sha256(f)
                
                # Count rows
                try:
                    if f.suffix == ".parquet":
                        df_peek = pd.read_parquet(f)
                        num_rows = len(df_peek)
                        num_cols = len(df_peek.columns)
                        classes = list(df_peek["label"].unique()) if "label" in df_peek.columns else []
                    else:
                        df_peek = pd.read_csv(f, nrows=100)
                        # quick line count
                        with open(f, "rb") as flc:
                            num_rows = sum(1 for _ in flc) - 1
                        num_cols = len(df_peek.columns)
                        classes = list(df_peek["label"].unique()) if "label" in df_peek.columns else []
                except Exception as e:
                    num_rows = -1
                    num_cols = -1
                    classes = []
                    
                record = {
                    "category": category,
                    "filename": f.name,
                    "rel_path": str(f.relative_to(DATA_DIR)),
                    "size_mb": round(size_bytes / (1024 * 1024), 3),
                    "total_flows": num_rows,
                    "feature_columns": num_cols,
                    "classes": classes,
                    "sha256": sha256_hash,
                    "last_modified": datetime.fromtimestamp(f.stat().st_mtime).isoformat()
                }
                manifest_records.append(record)
                
    manifest_path = DATA_DIR / "data_manifest.json"
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump({
            "version": "1.0",
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "total_files": len(manifest_records),
            "files": manifest_records
        }, f, indent=2)
    print(f"[OK] Saved Manifest: {manifest_path.name}")
    
    # 5. Generate Markdown Dataset Catalog
    catalog_path = DATA_DIR / "DATASET_CATALOG.md"
    with open(catalog_path, "w", encoding="utf-8") as f:
        f.write("# EviGraph Network Flow Telemetry & Dataset Catalog\n\n")
        f.write(f"*Generated on: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}*\n\n")
        f.write("This document indexes all training, validation, testing, and benchmark telemetry files preserved in `data/`.\n\n")
        
        f.write("## 1. Processed Model Training & Evaluation Splits (`data/processed/`)\n\n")
        f.write("| Filename | Type | Total Flows | Size (MB) | Description |\n")
        f.write("| :--- | :--- | :--- | :--- | :--- |\n")
        for rec in manifest_records:
            if rec["category"] == "processed":
                f.write(f"| `{rec['filename']}` | {rec['filename'].split('.')[-1].upper()} | {rec['total_flows']:,} | {rec['size_mb']} MB | Exact {rec['filename'].split('_')[1].upper()} partition used in model training |\n")
                
        f.write("\n## 2. External Benchmark Datasets (`data/new_benchmark/`)\n\n")
        f.write("| Filename | Classes Contained | Total Flows | Size (MB) | SHA-256 (Prefix) |\n")
        f.write("| :--- | :--- | :--- | :--- | :--- |\n")
        for rec in manifest_records:
            if rec["category"] == "new_benchmark":
                classes_str = ", ".join(rec["classes"][:4])
                f.write(f"| `{rec['filename']}` | `{classes_str}` | {rec['total_flows']:,} | {rec['size_mb']} MB | `{rec['sha256'][:16]}...` |\n")
                
        f.write("\n## 3. Raw Enterprise Captures (`data/raw/`)\n\n")
        f.write("| Filename | Total Flows | Size (MB) | SHA-256 (Prefix) |\n")
        f.write("| :--- | :--- | :--- | :--- |\n")
        for rec in manifest_records:
            if rec["category"] == "raw":
                f.write(f"| `{rec['filename']}` | {rec['total_flows']:,} | {rec['size_mb']} MB | `{rec['sha256'][:16]}...` |\n")
                
        f.write("\n## 4. How to Load These Files in Python\n\n")
        f.write("```python\nimport pandas as pd\n\n# Load exact training split\ntrain_df = pd.read_parquet('data/processed/benchmark_train_flows.parquet')\nprint(f'Train flows: {len(train_df):,}')\n\n# Load exact held-out test split\ntest_df = pd.read_parquet('data/processed/benchmark_test_flows.parquet')\nprint(f'Test flows: {len(test_df):,}')\n```\n")

    print(f"[OK] Saved Markdown Catalog: {catalog_path.name}")
    print("\n=================================================================")
    print(" [DONE] All model training datasets successfully archived in data/")
    print("=================================================================")

if __name__ == "__main__":
    export_benchmark_splits()
