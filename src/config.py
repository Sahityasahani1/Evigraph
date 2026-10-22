"""
EviGraph Configuration File: Member 2 (Detection & Graph Engine)
Adheres to EviGraph TRD/PRD specifications.
"""

from pathlib import Path

# Paths
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
RAW_DATA_DIR = DATA_DIR / "raw"
PROCESSED_DATA_DIR = DATA_DIR / "processed"
SAMPLES_DATA_DIR = DATA_DIR / "samples"
MODELS_DIR = BASE_DIR / "models"
OUTPUTS_DIR = BASE_DIR / "outputs"

# Metadata columns: NEVER use these as tabular model training features
# to prevent artificial identity leakage (TRD Section 3.2)
METADATA_COLS = [
    "flow_id",
    "timestamp",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "src_mac",
    "dst_mac",
    "evidence_id",
    "label"
]

# Standard Canonical Flow Features (subset aligned with CICIDS2017)
CANONICAL_FEATURES = [
    "flow_duration",
    "tot_fwd_pkts",
    "tot_bwd_pkts",
    "tot_len_fwd_pkts",
    "tot_len_bwd_pkts",
    "fwd_pkt_len_max",
    "fwd_pkt_len_min",
    "fwd_pkt_len_mean",
    "fwd_pkt_len_std",
    "bwd_pkt_len_max",
    "bwd_pkt_len_min",
    "bwd_pkt_len_mean",
    "bwd_pkt_len_std",
    "flow_bytes_s",
    "flow_pkts_s",
    "flow_iat_mean",
    "flow_iat_std",
    "flow_iat_max",
    "flow_iat_min",
    "fwd_iat_tot",
    "bwd_iat_tot",
    "fwd_psh_flags",
    "bwd_psh_flags",
    "fwd_urg_flags",
    "bwd_urg_flags",
    "fin_flag_cnt",
    "syn_flag_cnt",
    "rst_flag_cnt",
    "psh_flag_cnt",
    "ack_flag_cnt",
    "urg_flag_cnt",
    "down_up_ratio",
    "pkt_size_avg",
    "init_fwd_win_byts",
    "init_bwd_win_byts"
]

# Detection & Graph Hyperparameters
ALERT_RISK_THRESHOLD = 0.65       # Calibrated risk score above which a flow is an Alert
GRAPH_TIME_WINDOW_SECS = 300      # 5 minutes window for host graph slices
ALERT_CORRELATION_WINDOW_SECS = 300 # Max time delta to correlate alerts on shared hosts
INCIDENT_MIN_ALERTS = 1           # Minimum alerts to form an incident candidate

# Attack Label Taxonomy Mapping
LABEL_MAPPING = {
    "BENIGN": 0,
    "PortScan": 1,
    "SSH-Patator": 2,
    "FTP-Patator": 3,
    "DoS-Slowloris": 4,
    "DoS-Hulk": 5,
    "DDoS": 6,
    "Botnet": 7,
    "Infiltration": 8
}
INV_LABEL_MAPPING = {v: k for k, v in LABEL_MAPPING.items()}
