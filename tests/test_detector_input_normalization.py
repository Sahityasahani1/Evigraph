"""Regression coverage for raw CICFlowMeter headers used by frozen detectors."""

import csv

from src.config import CANONICAL_FEATURES
from src.data_loader import FlowDataLoader


def test_raw_cicflowmeter_features_map_to_detector_schema(tmp_path):
    source = tmp_path / "raw_cicflowmeter.csv"
    row = {
        "Flow ID": "flow-001",
        "Source IP": "192.0.2.10",
        "Source Port": 49152,
        "Destination IP": "198.51.100.20",
        "Destination Port": 443,
        "Protocol": 6,
        "Timestamp": "2017-07-03 10:00:00",
        "Label": "BENIGN",
    }
    # Explicit source headers for the three historical aliases that prevented
    # the raw CICFlowMeter CSV from matching the checkpoint feature schema.
    row.update(
        {
            "Flow Duration": 1_000_000,
            "Total Fwd Packets": 10,
            "Total Backward Packets": 5,
            "Total Length of Fwd Packets": 1200,
            "Total Length of Bwd Packets": 600,
            "Flow Bytes/s": 1800.5,
            "Flow Packets/s": 15.0,
            "Fwd Packet Length Max": 200,
            "Fwd Packet Length Min": 40,
            "Fwd Packet Length Mean": 120,
            "Fwd Packet Length Std": 20,
            "Bwd Packet Length Max": 160,
            "Bwd Packet Length Min": 40,
            "Bwd Packet Length Mean": 120,
            "Bwd Packet Length Std": 10,
            "Flow IAT Mean": 100,
            "Flow IAT Std": 20,
            "Flow IAT Max": 200,
            "Flow IAT Min": 10,
            "Fwd IAT Total": 500,
            "Bwd IAT Total": 500,
            "Fwd PSH Flags": 0,
            "Bwd PSH Flags": 0,
            "Fwd URG Flags": 0,
            "Bwd URG Flags": 0,
            "FIN Flag Count": 0,
            "SYN Flag Count": 1,
            "RST Flag Count": 0,
            "PSH Flag Count": 1,
            "ACK Flag Count": 1,
            "URG Flag Count": 0,
            "Down/Up Ratio": 0.5,
            "Average Packet Size": 120,
            "Init_Win_bytes_forward": 8192,
            "Init_Win_bytes_backward": 4096,
        }
    )
    with source.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=row)
        writer.writeheader()
        writer.writerow(row)

    flows = FlowDataLoader().load_dataset(source)

    assert set(CANONICAL_FEATURES).issubset(flows.columns)
    assert flows.loc[0, "tot_len_fwd_pkts"] == 1200
    assert flows.loc[0, "tot_len_bwd_pkts"] == 600
    assert flows.loc[0, "flow_bytes_s"] == 1800.5
    assert flows.loc[0, "flow_duration"] == 1_000_000
    assert flows.loc[0, "label"] == "BENIGN"
