"""Regression coverage for raw CICFlowMeter headers used by frozen detectors."""

import csv
import pytest

from src.config import CANONICAL_FEATURES
from src.data_loader import FlowDataLoader
from src.investigation_pipeline import _load_flows


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

    flows = FlowDataLoader().load_dataset(source, drop_missing=False)

    assert set(CANONICAL_FEATURES).issubset(flows.columns)
    assert flows.loc[0, "tot_len_fwd_pkts"] == 1200
    assert flows.loc[0, "tot_len_bwd_pkts"] == 600
    assert flows.loc[0, "flow_bytes_s"] == 1800.5
    assert flows.loc[0, "flow_duration"] == 1_000_000
    assert flows.loc[0, "label"] == "BENIGN"


def test_cicids2017_equivalent_metadata_mapping(tmp_path):
    """Verify CIC-IDS2017 equivalent header variants map to canonical metadata schema."""
    source = tmp_path / "cicids_metadata_aliases.csv"
    row = {
        "Flow ID": "flow-cic-001",
        "Src IP": "10.0.0.1",
        "Dst IP": "10.0.0.2",
        "Src Port": 50505,
        "Dst Port": 80,
        "Proto": 6,
        "Time Stamp": "04/07/2017 08:30:00",
        "Flow Duration": 500000,
        "Label": "BENIGN",
    }
    with source.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=row)
        writer.writeheader()
        writer.writerow(row)

    flows = FlowDataLoader().load_dataset(source, drop_missing=False)
    for expected_col in ["src_ip", "dst_ip", "src_port", "dst_port", "protocol", "timestamp", "label"]:
        assert expected_col in flows.columns, f"Expected canonical column '{expected_col}' not found"

    assert flows.loc[0, "src_ip"] == "10.0.0.1"
    assert flows.loc[0, "dst_ip"] == "10.0.0.2"
    assert flows.loc[0, "src_port"] == 50505
    assert flows.loc[0, "dst_port"] == 80
    assert flows.loc[0, "protocol"] == 6
    assert flows.loc[0, "timestamp"] == "04/07/2017 08:30:00"
    assert flows.loc[0, "label"] == "BENIGN"

    # Pipeline integration: _load_flows must succeed without ValueError
    loaded = _load_flows(source, source_sha256="fake_sha256_hash")
    assert not loaded.empty
    assert "src_ip" in loaded.columns
    assert "dst_ip" in loaded.columns


def test_cicids2017_case_and_whitespace_variations(tmp_path):
    """Verify headers with extreme whitespace, mixed/upper case, and punctuation resolve properly."""
    source = tmp_path / "cicids_case_whitespace.csv"
    row = {
        "  SOURCE IP  ": "172.16.0.5",
        "  DESTINATION IP  ": "192.168.1.1",
        " SOURCE PORT ": 12345,
        " DESTINATION PORT ": 8080,
        " PROTOCOL ": 17,
        " DATE / TIME ": "2017-07-05 14:00:00",
        " Flow Duration ": 100000,
        " LABEL ": "DDoS",
    }
    with source.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=row)
        writer.writeheader()
        writer.writerow(row)

    flows = FlowDataLoader().load_dataset(source, drop_missing=False)
    assert flows.loc[0, "src_ip"] == "172.16.0.5"
    assert flows.loc[0, "dst_ip"] == "192.168.1.1"
    assert flows.loc[0, "src_port"] == 12345
    assert flows.loc[0, "dst_port"] == 8080
    assert flows.loc[0, "protocol"] == 17
    assert flows.loc[0, "timestamp"] == "2017-07-05 14:00:00"
    assert flows.loc[0, "label"] == "DDoS"


def test_cicids2017_dot_notation_and_xgboost_features(tmp_path):
    """Verify R-style dot notation (Source.IP, Total.Length.of.Fwd.Packets) preserves features and labels."""
    source = tmp_path / "cicids_dots.csv"
    row = {
        "Source.IP": "10.0.1.5",
        "Destination.IP": "10.0.2.10",
        "Source.Port": 4444,
        "Destination.Port": 53,
        "Protocol": 17,
        "Timestamp": "07/07/2017 01:00:00 PM",
        "Total.Length.of.Fwd.Packets": 4096,
        "Total.Length.of.Bwd.Packets": 2048,
        "Flow.Bytes.s": 15000.0,
        "Flow.Duration": 350000,
        "Label": "PortScan",
    }
    with source.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=row)
        writer.writeheader()
        writer.writerow(row)

    flows = FlowDataLoader().load_dataset(source, drop_missing=False)
    assert flows.loc[0, "src_ip"] == "10.0.1.5"
    assert flows.loc[0, "dst_ip"] == "10.0.2.10"
    assert flows.loc[0, "src_port"] == 4444
    assert flows.loc[0, "dst_port"] == 53
    assert flows.loc[0, "tot_len_fwd_pkts"] == 4096
    assert flows.loc[0, "totlen_fwd_pkts"] == 4096
    assert flows.loc[0, "tot_len_bwd_pkts"] == 2048
    assert flows.loc[0, "flow_bytes_s"] == 15000.0
    assert flows.loc[0, "label"] == "PortScan"


def test_missing_required_fields_raises_error_without_inventing_values(tmp_path):
    """Verify missing required metadata fields fail cleanly rather than inventing synthetic values."""
    source = tmp_path / "malformed_missing_fields.csv"
    row = {
        "Destination IP": "10.0.2.10",
        "Source Port": 4444,
        "Destination Port": 80,
        "Protocol": 6,
        "Flow Duration": 1000,
        "Label": "BENIGN",
    }
    with source.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=row)
        writer.writeheader()
        writer.writerow(row)

    flows = FlowDataLoader().load_dataset(source, drop_missing=False)
    assert "src_ip" not in flows.columns
    assert "timestamp" not in flows.columns

    with pytest.raises(ValueError, match="Input is missing required flow metadata columns"):
        _load_flows(source, source_sha256="dummy_sha")
