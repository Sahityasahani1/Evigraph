"""
Automated Dataset Downloader for EviGraph
Downloads real large-scale CICIDS2017 data (Parquet format) via HuggingFace Hub.
Zero credentials required. Fast, authenticated-free, and compressed.
"""

import argparse
import shutil
from pathlib import Path
from huggingface_hub import hf_hub_download
from src.config import RAW_DATA_DIR

AVAILABLE_DAYS = {
    "portscan": "traffic_labels/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv.parquet",
    "tuesday": "traffic_labels/Tuesday-WorkingHours.pcap_ISCX.csv.parquet",      # SSH & FTP Patator
    "ddos": "traffic_labels/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv.parquet",
    "dos": "traffic_labels/Wednesday-workingHours.pcap_ISCX.csv.parquet",          # Slowloris, Hulk, etc.
    "web": "traffic_labels/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv.parquet",
    "benign": "traffic_labels/Monday-WorkingHours.pcap_ISCX.csv.parquet"          # Pure Benign
}

def download_cicids(day_key: str = "portscan", output_dir: Path = RAW_DATA_DIR) -> Path:
    if day_key not in AVAILABLE_DAYS:
        raise ValueError(f"Unknown day key '{day_key}'. Available: {list(AVAILABLE_DAYS.keys())}")
        
    remote_path = AVAILABLE_DAYS[day_key]
    output_dir.mkdir(parents=True, exist_ok=True)
    local_filename = Path(remote_path).name
    target_path = output_dir / local_filename
    
    if target_path.exists():
        print(f"[Downloader] Dataset already present at: {target_path}")
        return target_path

    print(f"[Downloader] Fetching '{day_key}' ({remote_path}) from bvsam/cic-ids-2017...")
    cached_file = hf_hub_download(
        repo_id="bvsam/cic-ids-2017",
        filename=remote_path,
        repo_type="dataset"
    )
    
    shutil.copy(cached_file, target_path)
    print(f"[Downloader] Successfully downloaded to {target_path} ({round(target_path.stat().st_size / (1024*1024), 2)} MB)")
    return target_path

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Download CICIDS2017 Parquet datasets")
    parser.add_argument(
        "--day", 
        type=str, 
        default="portscan", 
        choices=list(AVAILABLE_DAYS.keys()) + ["all"],
        help="Which day/attack slice to download"
    )
    args = parser.parse_args()
    
    if args.day == "all":
        for d in AVAILABLE_DAYS:
            download_cicids(d)
    else:
        download_cicids(args.day)
