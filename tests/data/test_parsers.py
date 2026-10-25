"""
Tests for Telemetry Parsers (CICIDS & Zeek)
Verifies Prompt 4 requirements:
- Duration in SECONDS, feat_flow_duration & feat_*_iat_* in MICROSECONDS
- Protocol mapped to int16, proto_name filled
- label_raw stripped and \\x96 encoding fixed
- label_family mapped from versioned YAML taxonomy
- cleaning_report.json mini-experiment tracking counts per label_raw, per day, removed vs kept
"""

import json
import csv
from pathlib import Path

import pytest

from data.parsers import get_last_cleaning_report, parse_cicids, parse_zeek_conn


def test_parse_cicids_sample():
    sample_file = Path("data/samples/sample_cicids2017_flows.csv")
    if sample_file.exists():
        report_file = Path("data/processed/test_sample_cleaning_report.json")
        df = parse_cicids(sample_file, max_rows=50, report_path=report_file)
        assert not df.empty
        assert "flow_id" in df.columns
        assert "tot_len_fwd_pkts" in df.columns
        assert "totlen_fwd_pkts" in df.columns
        assert df["flow_id"].iloc[0].startswith("flw_")

        # 1. Duration in SECONDS vs feat_flow_duration in MICROSECONDS
        assert "duration" in df.columns
        assert "feat_flow_duration" in df.columns
        assert df["duration"].dtype == "float64"
        assert df["feat_flow_duration"].dtype == "float32"

        # Check unit separation: duration is seconds, feat_flow_duration is microseconds
        first_dur = df["duration"].iloc[0]
        first_feat_dur = df["feat_flow_duration"].iloc[0]
        assert first_dur < 1000.0  # seconds
        assert first_feat_dur > 1000.0  # microseconds
        assert first_feat_dur == pytest.approx(first_dur * 1e6, rel=1e-3)

        # IAT model features in microseconds
        assert "feat_flow_iat_mean" in df.columns
        assert df["feat_flow_iat_mean"].dtype == "float32"
        assert df["feat_flow_iat_mean"].iloc[0] > 1000.0

        # 2. Protocol mapped to int16, proto_name filled
        assert df["protocol"].dtype == "int16"
        assert df["protocol"].iloc[0] in (6, 17, 1)
        assert df["proto_name"].iloc[0] in ("TCP", "UDP", "ICMP")

        # 3. label_raw and label_family
        assert "label_raw" in df.columns
        assert "label_family" in df.columns
        assert df["label_raw"].iloc[0] == "BENIGN"
        assert df["label_family"].iloc[0] == "BENIGN"

        # 4. cleaning_report.json report verification
        assert report_file.exists()
        with open(report_file, "r", encoding="utf-8") as f:
            report = json.load(f)

        assert "removed_vs_kept" in report
        assert report["removed_vs_kept"]["kept"] == 50
        assert report["removed_vs_kept"]["raw_total"] == 50
        assert "counts_per_label_raw" in report
        assert "BENIGN" in report["counts_per_label_raw"]
        assert "counts_per_day" in report
        assert "counts_per_label_family" in report


def test_parse_cicids_web_attack_encoding_and_taxonomy(tmp_path):
    """
    Tests handling of non-standard \\x96 dash encoding (latin-1) in CICIDS Web Attack labels
    and validates taxonomy mapping to 'Web-Attack'.
    """
    raw_csv_content = (
        b"Flow ID,Source IP,Source Port,Destination IP,Destination Port,Protocol,Timestamp,Flow Duration,Total Fwd Packets,Total Backward Packets,Total Length of Fwd Packets,Total Length of Bwd Packets,Label\n"
        b"flw_001,192.168.10.50,54321,192.168.10.1,80,6,2026-10-18T10:00:00,500000.0,5,5,500,1000,Web Attack \x96 Brute Force\n"
        b"flw_002,192.168.10.51,54322,192.168.10.1,80,6,2026-10-18T10:00:01,250000.0,4,4,400,800,Web Attack \x96 XSS\n"
        b"flw_003,192.168.10.52,54323,192.168.10.1,443,6,2026-10-18T10:00:02,100000.0,2,2,200,400,  BENIGN   \n"
    )

    test_csv = tmp_path / "web_attacks.csv"
    with open(test_csv, "wb") as f:
        f.write(raw_csv_content)

    report_path = tmp_path / "cleaning_report.json"
    df = parse_cicids(test_csv, report_path=report_path)

    assert len(df) == 3

    # Check that \x96 was converted to standard '-' and whitespace stripped
    labels_raw = df["label_raw"].tolist()
    assert labels_raw[0] == "Web Attack - Brute Force"
    assert labels_raw[1] == "Web Attack - XSS"
    assert labels_raw[2] == "BENIGN"

    # Check taxonomy family mapping from YAML
    families = df["label_family"].tolist()
    assert families[0] == "Web-Attack"
    assert families[1] == "Web-Attack"
    assert families[2] == "BENIGN"

    # Check protocol mapping and proto_name
    assert df["protocol"].tolist() == [6, 6, 6]
    assert df["proto_name"].tolist() == ["TCP", "TCP", "TCP"]

    # Check duration (seconds) vs feat_flow_duration (microseconds)
    assert df["duration"].tolist() == [0.5, 0.25, 0.1]
    assert df["feat_flow_duration"].tolist() == [500000.0, 250000.0, 100000.0]

    # Verify cleaning report contents
    assert report_path.exists()
    with open(report_path, "r", encoding="utf-8") as f:
        report = json.load(f)

    assert report["removed_vs_kept"]["kept"] == 3
    assert report["removed_vs_kept"]["removed"] == 0
    assert report["counts_per_label_raw"]["Web Attack - Brute Force"] == 1
    assert report["counts_per_label_raw"]["Web Attack - XSS"] == 1
    assert report["counts_per_label_raw"]["BENIGN"] == 1
    assert report["counts_per_label_family"]["Web-Attack"] == 2
    assert report["counts_per_label_family"]["BENIGN"] == 1
    assert "2026-10-18" in report["counts_per_day"]


def test_parse_cicids_cleaning_drop_reasons(tmp_path):
    """
    Tests detection and tracking of corrupted flows (inf features, negative durations, repeated headers).
    """
    csv_content = (
        "Flow ID,Source IP,Source Port,Destination IP,Destination Port,Protocol,Timestamp,Flow Duration,Total Fwd Packets,Total Backward Packets,Total Length of Fwd Packets,Total Length of Bwd Packets,Flow Bytes/s,Label\n"
        "flw_valid,192.168.1.10,50000,10.0.0.1,80,6,2026-10-18T10:00:00,1000000.0,10,10,1000,2000,3000.0,BENIGN\n"
        "flw_inf,192.168.1.11,50001,10.0.0.1,80,6,2026-10-18T10:00:01,1000000.0,10,10,1000,2000,Infinity,BENIGN\n"
        "flw_neg,192.168.1.12,50002,10.0.0.1,80,6,2026-10-18T10:00:02,-5000.0,10,10,1000,2000,500.0,BENIGN\n"
        "Flow ID,Source IP,Source Port,Destination IP,Destination Port,Protocol,Timestamp,Flow Duration,Total Fwd Packets,Total Backward Packets,Total Length of Fwd Packets,Total Length of Bwd Packets,Flow Bytes/s,Label\n"
    )

    test_csv = tmp_path / "corrupt_flows.csv"
    with open(test_csv, "w", encoding="utf-8") as f:
        f.write(csv_content)

    report_path = tmp_path / "drop_report.json"
    df = parse_cicids(test_csv, report_path=report_path)

    # Only 1 flow should be valid and kept
    assert len(df) == 1
    assert df["flow_id"].iloc[0] == "flw_valid"

    # Verify report records the mini-experiment drops
    report = get_last_cleaning_report()
    assert report is not None
    assert report["removed_vs_kept"]["raw_total"] == 4
    assert report["removed_vs_kept"]["kept"] == 1
    assert report["removed_vs_kept"]["removed"] == 3
    assert report["drop_reasons"]["inf_or_nan_features"] == 1
    assert report["drop_reasons"]["negative_duration"] == 1
    assert report["drop_reasons"]["repeated_headers"] == 1


@pytest.mark.parametrize(
    ("missing_column", "message"),
    [
        ("Source IP", "missing required network metadata.*src_ip"),
        ("Destination IP", "missing required network metadata.*dst_ip"),
        ("Timestamp", "missing required network metadata.*timestamp"),
    ],
)
def test_parse_cicids_rejects_missing_network_metadata(tmp_path, missing_column, message):
    row = {
        "Source IP": "192.0.2.1",
        "Destination IP": "198.51.100.2",
        "Timestamp": "2026-10-18T10:00:00Z",
        "Source Port": 50000,
        "Destination Port": 443,
        "Protocol": 6,
        "Flow Duration": 1_000_000,
        "Label": "BENIGN",
    }
    del row[missing_column]
    source = tmp_path / "missing_metadata.csv"
    with source.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=row)
        writer.writeheader()
        writer.writerow(row)

    with pytest.raises(ValueError, match=message):
        parse_cicids(source, report_path=tmp_path / "cleaning_report.json")


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("Source IP", "not-an-ip", "src_ip.*missing or invalid IP"),
        ("Timestamp", "not-a-time", "missing or invalid timestamps"),
    ],
)
def test_parse_cicids_rejects_invalid_network_metadata(tmp_path, field, value, message):
    row = {
        "Source IP": "192.0.2.1",
        "Destination IP": "198.51.100.2",
        "Timestamp": "2026-10-18T10:00:00Z",
        "Source Port": 50000,
        "Destination Port": 443,
        "Protocol": 6,
        "Flow Duration": 1_000_000,
        "Label": "BENIGN",
    }
    row[field] = value
    source = tmp_path / "invalid_metadata.csv"
    with source.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=row)
        writer.writeheader()
        writer.writerow(row)

    with pytest.raises(ValueError, match=message):
        parse_cicids(source, report_path=tmp_path / "cleaning_report.json")


def test_parse_zeek_conn_tsv(tmp_path):
    zeek_content = """#separator \\x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	conn
#open	2026-10-18-10-00-00
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	service	duration	orig_bytes	resp_bytes	conn_state	local_orig	local_resp	missed_bytes	history	orig_pkts	orig_ip_bytes	resp_pkts	resp_ip_bytes	tunnel_parents
#types	time	string	addr	port	addr	port	string	string	interval	count	count	string	bool	bool	count	string	count	count	count	count	set[string]
1700000000.123456	C12345	192.168.1.50	52341	10.0.0.1	443	tcp	ssl	0.250	1500	4500	SF	-	-	0	ShADadFf	10	2000	12	5100	-
#close	2026-10-18-10-00-01
"""
    log_file = tmp_path / "conn.log"
    with open(log_file, "w") as f:
        f.write(zeek_content)

    df = parse_zeek_conn(log_file)
    assert len(df) == 1
    assert df["src_ip"].iloc[0] == "192.168.1.50"
    assert df["dst_ip"].iloc[0] == "10.0.0.1"
    assert df["protocol"].iloc[0] == 6  # TCP
    assert df["tot_len_fwd_pkts"].iloc[0] == 1500.0
    assert df["tot_len_bwd_pkts"].iloc[0] == 4500.0
    assert df["tot_fwd_pkts"].iloc[0] == 10
    assert df["tot_bwd_pkts"].iloc[0] == 12
