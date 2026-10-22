"""
Dataset Size & Memory Inspector for EviGraph
Analyzes disk footprint, row counts, memory consumption, and attack distributions.
"""

import sys
import pandas as pd
from pathlib import Path
from src.config import RAW_DATA_DIR, SAMPLES_DATA_DIR

def inspect_file(file_path: Path):
    file_path = Path(file_path)
    if not file_path.exists():
        print(f"[Error] File not found: {file_path}")
        return

    disk_mb = file_path.stat().st_size / (1024 * 1024)
    print("\n" + "=" * 65)
    print(f" FILE: {file_path.name}")
    print("=" * 65)
    print(f" Disk Size      : {disk_mb:.2f} MB")
    
    # Read metadata & sample
    if file_path.suffix == ".parquet":
        df = pd.read_parquet(file_path)
    else:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f_peek:
            first_line = f_peek.readline()
            sep = ";" if ";" in first_line else ","
        df = pd.read_csv(file_path, sep=sep)
        
    ram_mb = df.memory_usage(deep=True).sum() / (1024 * 1024)
    print(f" Total Rows     : {len(df):,}")
    print(f" Total Columns  : {len(df.columns)}")
    print(f" In-Memory RAM  : {ram_mb:.2f} MB")
    
    # Check for label column
    label_col = next((c for c in ["Label", "label", "class"] if c in df.columns), None)
    if label_col:
        print("\n Class Breakdown:")
        counts = df[label_col].value_counts()
        for label, count in counts.items():
            pct = (count / len(df)) * 100
            clean_label = str(label).replace('\x96', '-').encode('ascii', errors='replace').decode('ascii')
            print(f"   * {clean_label:<25} : {count:>8,} flows ({pct:>5.1f}%)")
            
    # Check IP diversity
    src_col = next((c for c in ["Source IP", "src_ip"] if c in df.columns), None)
    dst_col = next((c for c in ["Destination IP", "dst_ip"] if c in df.columns), None)
    if src_col and dst_col:
        unique_src = df[src_col].nunique()
        unique_dst = df[dst_col].nunique()
        total_hosts = len(set(df[src_col]).union(set(df[dst_col])))
        print(f"\n Graph Topology Scale:")
        print(f"   * Unique Source IPs      : {unique_src:,}")
        print(f"   * Unique Destination IPs : {unique_dst:,}")
        print(f"   * Total Unique Hosts     : {total_hosts:,}")
    print("=" * 65)

def inspect_all():
    files = list(RAW_DATA_DIR.glob("*.parquet")) + list(RAW_DATA_DIR.glob("*.csv")) + list(SAMPLES_DATA_DIR.glob("*.csv"))
    if not files:
        print("[Inspector] No dataset files found.")
        return
        
    print(f"[Inspector] Found {len(files)} dataset files:")
    for f in files:
        inspect_file(f)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        inspect_file(Path(sys.argv[1]))
    else:
        inspect_all()
