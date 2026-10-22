"""
Synthetic CICIDS2017 Sample Generator for EviGraph Member 2.
Generates realistic multi-stage network flows conforming to canonical schema
for instant testing of the XGBoost detector and Graph Engine.
"""

import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import uuid
from src.config import SAMPLES_DATA_DIR, CANONICAL_FEATURES

def generate_flows(num_benign=1500, seed=42) -> pd.DataFrame:
    np.random.seed(seed)
    base_time = datetime(2026, 10, 15, 9, 0, 0)
    flows = []
    
    # 1. Benign background traffic (Office network)
    internal_ips = [f"192.168.10.{i}" for i in range(10, 30)]
    servers = ["192.168.10.5", "192.168.10.6", "8.8.8.8", "1.1.1.1"]
    
    for i in range(num_benign):
        src = np.random.choice(internal_ips)
        dst = np.random.choice(servers)
        port = np.random.choice([80, 443, 53, 445])
        ts = base_time + timedelta(seconds=int(np.random.uniform(0, 1800)))
        
        flow = {
            "flow_id": f"flw_benign_{i:05d}",
            "evidence_id": "evd_cicids_sample",
            "timestamp": ts.isoformat(),
            "src_ip": src,
            "dst_ip": dst,
            "src_port": int(np.random.randint(49152, 65535)),
            "dst_port": int(port),
            "protocol": 6 if port != 53 else 17,
            "label": "BENIGN",
            "flow_duration": float(np.random.exponential(150000)),
            "tot_fwd_pkts": int(np.random.randint(5, 30)),
            "tot_bwd_pkts": int(np.random.randint(4, 30)),
            "tot_len_fwd_pkts": float(np.random.normal(1200, 300)),
            "tot_len_bwd_pkts": float(np.random.normal(4500, 1000)),
            "fwd_pkt_len_max": float(np.random.uniform(200, 1400)),
            "fwd_pkt_len_min": 40.0,
            "fwd_pkt_len_mean": float(np.random.uniform(80, 250)),
            "fwd_pkt_len_std": float(np.random.uniform(10, 80)),
            "bwd_pkt_len_max": float(np.random.uniform(500, 1460)),
            "bwd_pkt_len_min": 40.0,
            "bwd_pkt_len_mean": float(np.random.uniform(200, 800)),
            "bwd_pkt_len_std": float(np.random.uniform(30, 200)),
            "flow_bytes_s": float(np.random.uniform(5000, 80000)),
            "flow_pkts_s": float(np.random.uniform(10, 200)),
            "flow_iat_mean": float(np.random.uniform(1000, 50000)),
            "flow_iat_std": float(np.random.uniform(500, 20000)),
            "flow_iat_max": float(np.random.uniform(20000, 100000)),
            "flow_iat_min": float(np.random.uniform(10, 500)),
            "fwd_iat_tot": float(np.random.uniform(10000, 200000)),
            "bwd_iat_tot": float(np.random.uniform(10000, 200000)),
            "fwd_psh_flags": int(np.random.choice([0, 1], p=[0.7, 0.3])),
            "bwd_psh_flags": int(np.random.choice([0, 1], p=[0.7, 0.3])),
            "fwd_urg_flags": 0,
            "bwd_urg_flags": 0,
            "fin_flag_cnt": 1,
            "syn_flag_cnt": 1,
            "rst_flag_cnt": 0,
            "psh_flag_cnt": 1,
            "ack_flag_cnt": 1,
            "urg_flag_cnt": 0,
            "down_up_ratio": float(np.random.uniform(0.8, 1.5)),
            "pkt_size_avg": float(np.random.uniform(100, 500)),
            "init_fwd_win_byts": 29200,
            "init_bwd_win_byts": 28960
        }
        flows.append(flow)
        
    # 2. Incident 1: External PortScan -> SSH-Patator Brute Force
    attacker_ip = "172.16.0.105"
    victim_ssh = "192.168.10.50"
    
    # 2a. Port Scan Phase (Time: 09:10:00 -> 09:12:00)
    scan_start = datetime(2026, 10, 15, 9, 10, 0)
    for p_idx, port in enumerate(range(20, 120)):
        ts = scan_start + timedelta(seconds=p_idx * 0.8)
        flow = {
            "flow_id": f"flw_scan_{p_idx:04d}",
            "evidence_id": "evd_cicids_sample",
            "timestamp": ts.isoformat(),
            "src_ip": attacker_ip,
            "dst_ip": victim_ssh,
            "src_port": int(np.random.randint(40000, 60000)),
            "dst_port": int(port),
            "protocol": 6,
            "label": "PortScan",
            "flow_duration": float(np.random.uniform(50, 400)),
            "tot_fwd_pkts": 2,
            "tot_bwd_pkts": 1,
            "tot_len_fwd_pkts": 84.0,
            "tot_len_bwd_pkts": 40.0,
            "fwd_pkt_len_max": 44.0,
            "fwd_pkt_len_min": 40.0,
            "fwd_pkt_len_mean": 42.0,
            "fwd_pkt_len_std": 2.0,
            "bwd_pkt_len_max": 40.0,
            "bwd_pkt_len_min": 40.0,
            "bwd_pkt_len_mean": 40.0,
            "bwd_pkt_len_std": 0.0,
            "flow_bytes_s": float(np.random.uniform(100000, 300000)),
            "flow_pkts_s": float(np.random.uniform(2000, 8000)),
            "flow_iat_mean": float(np.random.uniform(20, 100)),
            "flow_iat_std": float(np.random.uniform(5, 30)),
            "flow_iat_max": float(np.random.uniform(80, 200)),
            "flow_iat_min": 10.0,
            "fwd_iat_tot": float(np.random.uniform(30, 200)),
            "bwd_iat_tot": 0.0,
            "fwd_psh_flags": 0,
            "bwd_psh_flags": 0,
            "fwd_urg_flags": 0,
            "bwd_urg_flags": 0,
            "fin_flag_cnt": 0,
            "syn_flag_cnt": 1,
            "rst_flag_cnt": 1,  # Port rejected/closed
            "psh_flag_cnt": 0,
            "ack_flag_cnt": 0,
            "urg_flag_cnt": 0,
            "down_up_ratio": 0.5,
            "pkt_size_avg": 41.3,
            "init_fwd_win_byts": 1024,
            "init_bwd_win_byts": 0
        }
        flows.append(flow)
        
    # 2b. SSH Brute Force Phase (Time: 09:13:00 -> 09:17:00)
    ssh_start = datetime(2026, 10, 15, 9, 13, 0)
    for b_idx in range(60):
        ts = ssh_start + timedelta(seconds=b_idx * 3.5)
        flow = {
            "flow_id": f"flw_ssh_{b_idx:04d}",
            "evidence_id": "evd_cicids_sample",
            "timestamp": ts.isoformat(),
            "src_ip": attacker_ip,
            "dst_ip": victim_ssh,
            "src_port": int(np.random.randint(45000, 65000)),
            "dst_port": 22,
            "protocol": 6,
            "label": "SSH-Patator",
            "flow_duration": float(np.random.uniform(200000, 350000)),
            "tot_fwd_pkts": 22,
            "tot_bwd_pkts": 20,
            "tot_len_fwd_pkts": 1820.0,
            "tot_len_bwd_pkts": 2400.0,
            "fwd_pkt_len_max": 240.0,
            "fwd_pkt_len_min": 32.0,
            "fwd_pkt_len_mean": 82.7,
            "fwd_pkt_len_std": 45.0,
            "bwd_pkt_len_max": 480.0,
            "bwd_pkt_len_min": 32.0,
            "bwd_pkt_len_mean": 120.0,
            "bwd_pkt_len_std": 80.0,
            "flow_bytes_s": float(np.random.uniform(12000, 25000)),
            "flow_pkts_s": float(np.random.uniform(80, 150)),
            "flow_iat_mean": float(np.random.uniform(5000, 12000)),
            "flow_iat_std": float(np.random.uniform(2000, 5000)),
            "flow_iat_max": 25000.0,
            "flow_iat_min": 20.0,
            "fwd_iat_tot": 250000.0,
            "bwd_iat_tot": 245000.0,
            "fwd_psh_flags": 1,
            "bwd_psh_flags": 1,
            "fwd_urg_flags": 0,
            "bwd_urg_flags": 0,
            "fin_flag_cnt": 1,
            "syn_flag_cnt": 1,
            "rst_flag_cnt": 0,
            "psh_flag_cnt": 1,
            "ack_flag_cnt": 1,
            "urg_flag_cnt": 0,
            "down_up_ratio": 0.91,
            "pkt_size_avg": 100.5,
            "init_fwd_win_byts": 14600,
            "init_bwd_win_byts": 14600
        }
        flows.append(flow)

    # 3. Incident 2: DoS-Slowloris attack on Web Server
    dos_attacker = "172.16.0.120"
    victim_web = "192.168.10.80"
    dos_start = datetime(2026, 10, 15, 9, 20, 0)
    
    for d_idx in range(50):
        ts = dos_start + timedelta(seconds=d_idx * 2.0)
        flow = {
            "flow_id": f"flw_dos_{d_idx:04d}",
            "evidence_id": "evd_cicids_sample",
            "timestamp": ts.isoformat(),
            "src_ip": dos_attacker,
            "dst_ip": victim_web,
            "src_port": int(np.random.randint(50000, 65000)),
            "dst_port": 80,
            "protocol": 6,
            "label": "DoS-Slowloris",
            "flow_duration": float(np.random.uniform(800000, 1200000)),
            "tot_fwd_pkts": 6,
            "tot_bwd_pkts": 2,
            "tot_len_fwd_pkts": 180.0,
            "tot_len_bwd_pkts": 80.0,
            "fwd_pkt_len_max": 35.0,
            "fwd_pkt_len_min": 20.0,
            "fwd_pkt_len_mean": 30.0,
            "fwd_pkt_len_std": 5.0,
            "bwd_pkt_len_max": 40.0,
            "bwd_pkt_len_min": 40.0,
            "bwd_pkt_len_mean": 40.0,
            "bwd_pkt_len_std": 0.0,
            "flow_bytes_s": float(np.random.uniform(150, 400)),
            "flow_pkts_s": float(np.random.uniform(5, 12)),
            "flow_iat_mean": float(np.random.uniform(150000, 250000)),
            "flow_iat_std": float(np.random.uniform(20000, 50000)),
            "flow_iat_max": 300000.0,
            "flow_iat_min": 50000.0,
            "fwd_iat_tot": 900000.0,
            "bwd_iat_tot": 850000.0,
            "fwd_psh_flags": 0,
            "bwd_psh_flags": 0,
            "fwd_urg_flags": 0,
            "bwd_urg_flags": 0,
            "fin_flag_cnt": 0,
            "syn_flag_cnt": 1,
            "rst_flag_cnt": 0,
            "psh_flag_cnt": 1,
            "ack_flag_cnt": 1,
            "urg_flag_cnt": 0,
            "down_up_ratio": 0.33,
            "pkt_size_avg": 32.5,
            "init_fwd_win_byts": 8192,
            "init_bwd_win_byts": 4096
        }
        flows.append(flow)

    df = pd.DataFrame(flows)
    # Sort chronologically as expected in real capture
    df = df.sort_values(by="timestamp").reset_index(drop=True)
    return df

if __name__ == "__main__":
    df = generate_flows()
    output_path = SAMPLES_DATA_DIR / "sample_cicids2017_flows.csv"
    df.to_csv(output_path, index=False)
    print(f"Generated {len(df)} sample flows saved to {output_path}")
    print(df["label"].value_counts())
