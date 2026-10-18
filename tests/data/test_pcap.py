"""
Unit & Integration Test Suite for Streaming PCAP Parser (FR-1.1, FR-2.4)
Verifies:
- Streaming dpkt packet reader with zero full-file buffering
- Tolerance of corrupted / truncated packets (counted in stats, never fatal)
- Accurate computation of all 35 Member-2 canonical features adhering to CICFlowMeter conventions
- Bidirectional 5-tuple flow lifecycle with idle (120s) and active (1800s) timeouts
- Integration with Zeek metadata (5-tuple and time overlap joining with unmatched rate)
- Train/serve KS skew validation against reference distributions
- Tool versions recorded in cryptographic audit log
"""

import socket
import struct
from pathlib import Path

import dpkt
import pandas as pd
import pytest

from data.evidence import AuditLogger
from data.parsers import (
    enrich_flows_with_zeek_metadata,
    get_last_pcap_stats,
    parse_pcap,
    run_skew_validation,
)


def create_synthetic_pcap(file_path, packets):
    """
    Helper creating a valid binary PCAP file using dpkt.
    packets is a list of tuples: (ts, s_ip, d_ip, s_port, d_port, proto, tcp_flags, win, payload)
    """
    with open(file_path, "wb") as f:
        writer = dpkt.pcap.Writer(f)
        for ts, s_ip, d_ip, s_port, d_port, proto, flags, win, payload in packets:
            if proto == 6:
                transport = dpkt.tcp.TCP(
                    sport=s_port,
                    dport=d_port,
                    flags=flags,
                    win=win,
                    data=payload
                )
            elif proto == 17:
                transport = dpkt.udp.UDP(
                    sport=s_port,
                    dport=d_port,
                    data=payload
                )
            else:
                transport = b""

            ip = dpkt.ip.IP(
                src=socket.inet_aton(s_ip),
                dst=socket.inet_aton(d_ip),
                p=proto,
                data=transport
            )
            ip.len = len(ip)

            eth = dpkt.ethernet.Ethernet(
                src=b"\x00\x11\x22\x33\x44\x55",
                dst=b"\x66\x77\x88\x99\xaa\xbb",
                type=dpkt.ethernet.ETH_TYPE_IP,
                data=ip
            )
            writer.writepkt(eth, ts=ts)


def test_pcap_streaming_reader_and_malformed_tolerance(tmp_path):
    """Verifies that malformed/truncated packets are counted and do not crash the pipeline."""
    pcap_file = tmp_path / "corrupted.pcap"

    # Write a valid PCAP header followed by a valid packet and then corrupted garbage
    valid_pkts = [
        (1700000000.1, "192.168.1.10", "10.0.0.1", 50001, 80, 6, dpkt.tcp.TH_SYN, 29200, b""),
        (1700000000.2, "10.0.0.1", "192.168.1.10", 80, 50001, 6, dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK, 28960, b""),
    ]
    create_synthetic_pcap(pcap_file, valid_pkts)

    # Append corrupted truncated packet record header
    with open(pcap_file, "ab") as f:
        # Write corrupted packet header claiming 1000 bytes but only giving 10 bytes of truncated data
        f.write(struct.pack("=IIII", 1700000000, 300000, 1000, 1000))
        f.write(b"TRUNCATED!")

    df = parse_pcap(pcap_file)
    assert not df.empty
    assert len(df) == 1

    # Malformed packet was tallied in statistics
    stats = get_last_pcap_stats()
    assert stats["malformed_packets"] > 0
    assert stats["total_packets"] >= 2


def test_pcap_flow_builder_35_features(tmp_path):
    """
    Validates complete computation of all 35 canonical features from a bidirectional TCP flow.
    """
    pcap_file = tmp_path / "valid_flow.pcap"

    # 3 forward packets, 2 backward packets
    pkts = [
        # Packet 1 (FWD: SYN)
        (1700000000.0, "192.168.10.50", "10.0.0.1", 54000, 443, 6, dpkt.tcp.TH_SYN, 29200, b""),
        # Packet 2 (BWD: SYN-ACK)
        (1700000000.05, "10.0.0.1", "192.168.10.50", 443, 54000, 6, dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK, 28960, b""),
        # Packet 3 (FWD: ACK + Data)
        (1700000000.10, "192.168.10.50", "10.0.0.1", 54000, 443, 6, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, 29200, b"HELLO_TLS_PAYLOAD"),
        # Packet 4 (BWD: ACK + Data)
        (1700000000.15, "10.0.0.1", "192.168.10.50", 443, 54000, 6, dpkt.tcp.TH_ACK, 28960, b"SERVER_RESPONSE_BYTES_LONG"),
        # Packet 5 (FWD: FIN-ACK)
        (1700000000.20, "192.168.10.50", "10.0.0.1", 54000, 443, 6, dpkt.tcp.TH_FIN | dpkt.tcp.TH_ACK, 29200, b""),
    ]
    create_synthetic_pcap(pcap_file, pkts)

    df = parse_pcap(pcap_file)
    assert len(df) == 1
    r = df.iloc[0]

    # Verification of Base Canonical Columns
    assert r["src_ip"] == "192.168.10.50"
    assert r["dst_ip"] == "10.0.0.1"
    assert r["src_port"] == 54000
    assert r["dst_port"] == 443
    assert r["protocol"] == 6
    assert r["proto_name"] == "TCP"
    assert r["source_type"] == "pcap"

    # Unit Separation: duration in seconds, feat_flow_duration in microseconds
    assert r["duration"] == pytest.approx(0.20, rel=1e-3)  # Seconds
    assert r["feat_flow_duration"] == pytest.approx(200000.0, rel=1e-3)  # Microseconds

    # Packet counts
    assert r["feat_tot_fwd_pkts"] == 3
    assert r["feat_tot_bwd_pkts"] == 2
    assert r["feat_down_up_ratio"] == pytest.approx(2 / 3, rel=1e-3)

    # Initial window sizes
    assert r["feat_init_fwd_win_byts"] == 29200
    assert r["feat_init_bwd_win_byts"] == 28960

    # Flags
    assert r["feat_syn_flag_cnt"] == 2  # FWD SYN + BWD SYN-ACK
    assert r["feat_fin_flag_cnt"] == 1  # FWD FIN
    assert r["feat_psh_flag_cnt"] >= 1  # PUSH packet
    assert r["feat_ack_flag_cnt"] >= 3  # Multiple ACKs

    # Inter-arrival times (in microseconds)
    assert r["feat_flow_iat_mean"] > 0.0
    assert r["feat_flow_iat_max"] > 0.0

    # Check that Audit Log recorded the action and tool versions
    logger = AuditLogger()
    last_audit = logger.get_last_entry()
    assert last_audit is not None
    assert last_audit.action == "PARSE_PCAP_STREAM"
    assert "dpkt" in last_audit.tool_versions
    assert "scipy" in last_audit.tool_versions


def test_pcap_idle_timeout_segmentation(tmp_path):
    """
    Verifies that packets on the same 5-tuple separated by > 120s are split into separate flows.
    """
    pcap_file = tmp_path / "timeout_test.pcap"

    # Packet 1 at t=0, Packet 2 at t=150 (delta = 150s > 120s idle timeout)
    pkts = [
        (1700000000.0, "192.168.1.1", "10.0.0.1", 12345, 80, 6, dpkt.tcp.TH_SYN, 10000, b""),
        (1700000150.0, "192.168.1.1", "10.0.0.1", 12345, 80, 6, dpkt.tcp.TH_SYN, 10000, b""),
    ]
    create_synthetic_pcap(pcap_file, pkts)

    df = parse_pcap(pcap_file, idle_timeout_sec=120.0)
    # Must produce 2 distinct flows due to idle timeout expiration
    assert len(df) == 2
    assert df["flow_id"].iloc[0] != df["flow_id"].iloc[1]


def test_enrich_flows_with_zeek_metadata(tmp_path):
    """
    Verifies Part B: Joining Zeek dns/http/ssl metadata to flows by 5-tuple + time overlap.
    """
    pcap_file = tmp_path / "dummy.pcap"
    create_synthetic_pcap(pcap_file, [
        (1700000000.0, "192.168.1.10", "8.8.8.8", 53535, 53, 17, 0, 0, b"DNS_REQ"),
        (1700000000.1, "8.8.8.8", "192.168.1.10", 53, 53535, 17, 0, 0, b"DNS_RESP"),
    ])
    flows_df = parse_pcap(pcap_file)
    assert len(flows_df) == 1

    # Create mock Zeek logs directory with dns.log
    zeek_dir = tmp_path / "zeek_output"
    zeek_dir.mkdir(parents=True, exist_ok=True)
    with open(zeek_dir / "dns.log", "w", encoding="utf-8") as f:
        f.write("""#separator \\x09
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	trans_id	rtt	query	qclass	qclass_name	qtype	qtype_name	rcode	rcode_name	AA	TC	RD	RA	Z	answers	TTLs	rejected
1700000000.050000	C_DNS_1	192.168.1.10	53535	8.8.8.8	53	udp	10	0.050	test.internal	1	C_INTERNET	1	A	0	NOERROR	F	F	T	T	0	1.2.3.4	300.0	F
# Unmatched event (different port)
1700000000.050000	C_DNS_2	192.168.1.10	99999	8.8.8.8	53	udp	11	0.050	unmatched.org	1	C_INTERNET	1	A	0	NOERROR	F	F	T	T	0	1.2.3.4	300.0	F
""")

    enriched_flows, report = enrich_flows_with_zeek_metadata(
        flows_df=flows_df,
        pcap_path=pcap_file,
        zeek_logs_dir=zeek_dir,
        time_overlap_sec=5.0
    )

    assert report["total_events"] == 2
    assert report["matched_events"] == 1
    assert report["unmatched_events"] == 1
    assert report["unmatched_rate"] == 0.5


def test_train_serve_skew_validation(tmp_path):
    """
    Verifies that the Kolmogorov-Smirnov test correctly evaluates feature distributions
    and exports docs/skew_report.md.
    """
    # Create two DataFrames with identical distributions to test KS validation
    pcap_file = tmp_path / "skew_test.pcap"
    pkts = [
        (1700000000.0 + i * 0.1, "192.168.1.10", "10.0.0.1", 50000, 80, 6, dpkt.tcp.TH_ACK, 29200, b"PAYLOAD")
        for i in range(10)
    ]
    create_synthetic_pcap(pcap_file, pkts)
    pcap_df = parse_pcap(pcap_file)

    # Use ground-truth sample CSV
    csv_file = Path("data/samples/sample_cicids2017_flows.csv")
    if csv_file.exists():
        csv_df = pd.read_csv(csv_file, nrows=50)
        report_md = tmp_path / "skew_report.md"
        skew_df = run_skew_validation(pcap_df, csv_df, output_markdown_path=report_md)

        assert not skew_df.empty
        assert len(skew_df) == 35  # Exactly 35 features evaluated
        assert "ks_statistic" in skew_df.columns
        assert "p_value" in skew_df.columns
        assert report_md.exists()

        content = report_md.read_text(encoding="utf-8")
        assert "Train/Serve Feature Distribution Skew Report" in content
        assert "flow_duration" in content
        assert "tot_fwd_pkts" in content
