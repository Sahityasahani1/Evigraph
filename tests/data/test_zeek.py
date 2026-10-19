"""
Comprehensive Test Suite for Zeek Telemetry Parsers (FR-1.1, FR-2.4)
Verifies:
- conn.log, dns.log, http.log, ssl.log parsing in BOTH TSV and JSON-lines formats with auto-detection.
- Canonical flow mapping: orig_h/orig_p/resp_h/resp_p, proto, duration in seconds,
  orig_bytes->fwd_bytes, resp_bytes->bwd_bytes, orig_pkts->fwd_pkts, resp_pkts->bwd_pkts, conn_state.
- Null marker handling: "-" and "(empty)" parsed as None/null.
- Preservation of Zeek uid in canonical column zeek_uid.
- Separate Parquet tables (dns_events, http_events, tls_events) with flow_id joined on zeek_uid.
- Attacker-controlled string sanitization: length capped at 256, control characters stripped,
  sanitized stored in main columns and raw stored in *_raw.
- Error tolerance: Malformed lines are counted without crashing.
"""

import json

import pandas as pd
import pytest

from data.parsers import (
    get_last_zeek_stats,
    parse_zeek_bundle,
    parse_zeek_conn,
    parse_zeek_dns,
    parse_zeek_http,
    parse_zeek_ssl,
)


def test_zeek_conn_tsv_and_null_handling(tmp_path):
    """Verifies TSV parsing with #fields header, null handling ('-', '(empty)'), and canonical flow mapping."""
    tsv_content = """#separator \\x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	conn
#open	2026-10-18-10-00-00
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	service	duration	orig_bytes	resp_bytes	conn_state	local_orig	local_resp	missed_bytes	history	orig_pkts	orig_ip_bytes	resp_pkts	resp_ip_bytes	tunnel_parents
#types	time	string	addr	port	addr	port	string	string	interval	count	count	string	bool	bool	count	string	count	count	count	count	set[string]
1700000000.123456	C_CONN_001	192.168.1.50	52341	10.0.0.1	443	tcp	ssl	0.250	1500	4500	SF	-	-	0	ShADadFf	10	2000	12	5100	-
1700000001.000000	C_CONN_002	192.168.1.51	53535	8.8.8.8	53	udp	dns	-	-	-	-	-	-	0	Dd	1	60	1	120	(empty)
#close	2026-10-18-10-00-02
"""
    log_file = tmp_path / "conn.log"
    with open(log_file, "w", encoding="utf-8") as f:
        f.write(tsv_content)

    df = parse_zeek_conn(log_file)
    assert len(df) == 2

    # Row 1: Valid values
    r1 = df.iloc[0]
    assert r1["zeek_uid"] == "C_CONN_001"
    assert r1["src_ip"] == "192.168.1.50"
    assert r1["dst_ip"] == "10.0.0.1"
    assert r1["src_port"] == 52341
    assert r1["dst_port"] == 443
    assert r1["protocol"] == 6
    assert r1["proto_name"] == "TCP"
    assert r1["duration"] == 0.250  # Seconds
    assert r1["feat_flow_duration"] == pytest.approx(250000.0, rel=1e-3)  # Microseconds
    assert r1["fwd_bytes"] == 1500
    assert r1["bwd_bytes"] == 4500
    assert r1["fwd_pkts"] == 10
    assert r1["bwd_pkts"] == 12
    assert r1["conn_state"] == "SF"
    assert r1["source_type"] == "zeek"
    assert str(r1["flow_id"]).startswith("flw_")

    # Row 2: Null handling ('-' and '(empty)' -> 0 or None)
    r2 = df.iloc[1]
    assert r2["zeek_uid"] == "C_CONN_002"
    assert r2["protocol"] == 17
    assert r2["proto_name"] == "UDP"
    assert r2["duration"] == 0.0
    assert r2["feat_flow_duration"] == 0.0
    assert r2["fwd_bytes"] == 0
    assert r2["bwd_bytes"] == 0
    assert r2["conn_state"] is None


def test_zeek_conn_json_and_malformed_tolerance(tmp_path):
    """Verifies JSON-lines auto-detection, parsing, and malformed line tolerance."""
    json_lines = """{"ts": 1700000010.5, "uid": "C_JSON_001", "id.orig_h": "10.1.1.20", "id.orig_p": 44444, "id.resp_h": "10.2.2.30", "id.resp_p": 8080, "proto": "tcp", "duration": 1.5, "orig_bytes": 200, "resp_bytes": 800, "orig_pkts": 3, "resp_pkts": 4, "conn_state": "S0"}
{"this line is corrupted json syntax and should not crash: {[[
{"ts": 1700000011.0, "uid": "C_JSON_002", "id": {"orig_h": "10.1.1.21", "orig_p": 55555, "resp_h": "10.2.2.31", "resp_p": 80}, "proto": "tcp", "duration": "-", "orig_bytes": 50, "resp_bytes": "-", "orig_pkts": 1, "resp_pkts": 0, "conn_state": "-"}
"""
    log_file = tmp_path / "conn.json"
    with open(log_file, "w", encoding="utf-8") as f:
        f.write(json_lines)

    df = parse_zeek_conn(log_file)
    assert len(df) == 2

    # Malformed line was counted, not crashed
    stats = get_last_zeek_stats()
    assert stats["malformed_lines"] == 1
    assert stats["valid_records"] == 2

    r1 = df.iloc[0]
    assert r1["zeek_uid"] == "C_JSON_001"
    assert r1["duration"] == 1.5
    assert r1["feat_flow_duration"] == pytest.approx(1500000.0, rel=1e-3)
    assert r1["conn_state"] == "S0"

    r2 = df.iloc[1]
    assert r2["zeek_uid"] == "C_JSON_002"
    assert r2["src_ip"] == "10.1.1.21"
    assert r2["dst_ip"] == "10.2.2.31"
    assert r2["duration"] == 0.0
    assert r2["bwd_bytes"] == 0
    assert r2["conn_state"] is None


def test_zeek_dns_parsing_and_sanitization(tmp_path):
    """
    Verifies dns.log parsing, joining flow_id on zeek_uid,
    and attacker-controlled string sanitization (capped at 256, stripped control chars).
    """
    conn_file = tmp_path / "conn.log"
    with open(conn_file, "w", encoding="utf-8") as f:
        f.write("""#separator \\x09
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	service	duration	orig_bytes	resp_bytes	conn_state	local_orig	local_resp	missed_bytes	history	orig_pkts	orig_ip_bytes	resp_pkts	resp_ip_bytes	tunnel_parents
1700000020.000000	C_DNS_FLOW	192.168.1.100	50000	8.8.8.8	53	udp	dns	0.010	50	100	SF	-	-	0	Dd	1	78	1	128	-
""")
    conn_df = parse_zeek_conn(conn_file)
    expected_flow_id = conn_df["flow_id"].iloc[0]

    # Create malicious DNS query: over 300 characters, containing control characters (\x00, \x08, \x1b)
    malicious_query_raw = "evil\x00corp\x1btest." + ("subdomain" * 35) + ".example.com"
    assert len(malicious_query_raw) > 300

    dns_file = tmp_path / "dns.log"
    with open(dns_file, "w", encoding="utf-8") as f:
        f.write(f"""#separator \\x09
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	trans_id	rtt	query	qclass	qclass_name	qtype	qtype_name	rcode	rcode_name	AA	TC	RD	RA	Z	answers	TTLs	rejected
1700000020.005000	C_DNS_FLOW	192.168.1.100	50000	8.8.8.8	53	udp	101	0.005	{malicious_query_raw}	1	C_INTERNET	1	A	0	NOERROR	F	F	T	T	0	93.184.216.34	300.0	F
# Malformed line with missing fields:
1700000020.009000	C_BAD	short
""")

    out_parquet = tmp_path / "dns_events.parquet"
    df_dns = parse_zeek_dns(dns_file, conn_df=conn_df, output_parquet=out_parquet)

    assert len(df_dns) == 1
    r = df_dns.iloc[0]

    # Joined flow_id on zeek_uid
    assert r["zeek_uid"] == "C_DNS_FLOW"
    assert r["flow_id"] == expected_flow_id

    # Sanitization verification
    assert len(r["query"]) <= 256
    assert "\x00" not in r["query"]
    assert "\x1b" not in r["query"]
    assert r["query"].startswith("evilcorptest.")

    # Raw preservation
    assert r["query_raw"] == malicious_query_raw
    assert len(r["query_raw"]) > 300

    assert r["qtype_name"] == "A"
    assert r["rcode_name"] == "NOERROR"

    # Parquet file existence and content check
    assert out_parquet.exists()
    df_pq = pd.read_parquet(out_parquet)
    assert len(df_pq) == 1
    assert df_pq["query"].iloc[0] == r["query"]

    # Malformed count check
    stats = get_last_zeek_stats()
    assert stats["malformed_lines"] == 1


def test_zeek_http_parsing_and_sanitization(tmp_path):
    """
    Verifies http.log parsing, joining flow_id on zeek_uid,
    and attacker-controlled string sanitization (uri, user_agent, host).
    """
    uid = "C_HTTP_001"
    uid_map = {uid: "flw_http_verified"}

    # Malicious URI and User-Agent with control characters and excessive length
    malicious_uri_raw = "/api/v1/search?q=" + ("\x08malicious_payload\x1f" * 20)
    malicious_ua_raw = "Mozilla/5.0 \x00ExploitAgent/1.0 (" + ("A" * 300) + ")"

    valid_record = {
        "ts": 1700000030.123,
        "uid": uid,
        "id.orig_h": "192.168.1.10",
        "id.orig_p": 44444,
        "id.resp_h": "10.0.0.80",
        "id.resp_p": 80,
        "method": "GET",
        "host": "target.local",
        "uri": malicious_uri_raw,
        "user_agent": malicious_ua_raw,
        "status_code": 200,
        "status_msg": "OK"
    }

    http_json_file = tmp_path / "http.log"
    with open(http_json_file, "w", encoding="utf-8") as f:
        f.write(json.dumps(valid_record) + "\n")
        f.write('{"malformed line without valid json\n')

    out_parquet = tmp_path / "http_events.parquet"
    df_http = parse_zeek_http(http_json_file, uid_to_flow_id=uid_map, output_parquet=out_parquet)

    assert len(df_http) == 1
    r = df_http.iloc[0]

    # Flow ID joined
    assert r["flow_id"] == "flw_http_verified"
    assert r["zeek_uid"] == uid
    assert r["method"] == "GET"
    assert r["host"] == "target.local"

    # URI sanitized
    assert len(r["uri"]) <= 256
    assert "\x08" not in r["uri"]
    assert "\x1f" not in r["uri"]
    assert r["uri_raw"] == malicious_uri_raw

    # User-Agent sanitized
    assert len(r["user_agent"]) <= 256
    assert "\x00" not in r["user_agent"]
    assert r["user_agent_raw"] == malicious_ua_raw

    assert r["status_code"] == 200
    assert r["status"] == "OK"

    # Parquet check
    assert out_parquet.exists()
    pq_df = pd.read_parquet(out_parquet)
    assert len(pq_df) == 1

    stats = get_last_zeek_stats()
    assert stats["malformed_lines"] == 1


def test_zeek_ssl_tls_parsing_and_sanitization(tmp_path):
    """
    Verifies ssl.log parsing, joining flow_id on zeek_uid,
    and sanitizing ja3, sni, and server_name.
    """
    uid = "C_SSL_001"
    uid_map = {uid: "flw_tls_verified"}

    long_sni_raw = "secure\x00vpn\x07." + ("domain" * 45) + ".com"

    ssl_tsv = tmp_path / "ssl.log"
    with open(ssl_tsv, "w", encoding="utf-8") as f:
        f.write(f"""#separator \\x09
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	version	cipher	curve	server_name	resumed	last_alert	next_protocol	established	cert_chain_fuids	client_cert_chain_fuids	subject	issuer	client_subject	client_issuer	sni	ja3	ja3s
1700000040.500000	{uid}	192.168.1.5	54321	10.0.0.443	443	TLSv13	TLS_AES_128_GCM_SHA256	-	{long_sni_raw}	F	-	-	T	-	-	-	-	-	-	{long_sni_raw}	66918128f1b9b03303d77c6f2eefd128	-
# Malformed TSV line:
1700000040.600000	C_SHORT	192.168.1.5
""")

    out_parquet = tmp_path / "tls_events.parquet"
    df_ssl = parse_zeek_ssl(ssl_tsv, uid_to_flow_id=uid_map, output_parquet=out_parquet)

    assert len(df_ssl) == 1
    r = df_ssl.iloc[0]

    assert r["flow_id"] == "flw_tls_verified"
    assert r["zeek_uid"] == uid
    assert r["version"] == "TLSv13"
    assert r["cipher"] == "TLS_AES_128_GCM_SHA256"
    assert bool(r["established"]) is True

    # SNI and Server Name sanitized
    assert len(r["sni"]) <= 256
    assert "\x00" not in r["sni"]
    assert "\x07" not in r["sni"]
    assert r["sni_raw"] == long_sni_raw

    # JA3 preserved
    assert r["ja3"] == "66918128f1b9b03303d77c6f2eefd128"

    assert out_parquet.exists()
    pq_df = pd.read_parquet(out_parquet)
    assert len(pq_df) == 1

    stats = get_last_zeek_stats()
    assert stats["malformed_lines"] == 1


def test_parse_zeek_bundle_integration(tmp_path):
    """Verifies end-to-end bundling of conn, dns, http, and ssl logs."""
    conn_file = tmp_path / "conn.log"
    with open(conn_file, "w", encoding="utf-8") as f:
        f.write("""#separator \\x09
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	service	duration	orig_bytes	resp_bytes	conn_state	local_orig	local_resp	missed_bytes	history	orig_pkts	orig_ip_bytes	resp_pkts	resp_ip_bytes	tunnel_parents
1700000050.000000	C_BUNDLE_1	192.168.1.10	40001	1.1.1.1	53	udp	dns	0.002	45	80	SF	-	-	0	Dd	1	73	1	108	-
1700000051.000000	C_BUNDLE_2	192.168.1.10	40002	10.0.0.1	80	tcp	http	0.500	120	500	SF	-	-	0	ShADadFf	4	280	5	700	-
""")

    dns_file = tmp_path / "dns.log"
    with open(dns_file, "w", encoding="utf-8") as f:
        f.write("""#separator \\x09
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	trans_id	rtt	query	qclass	qclass_name	qtype	qtype_name	rcode	rcode_name	AA	TC	RD	RA	Z	answers	TTLs	rejected
1700000050.001000	C_BUNDLE_1	192.168.1.10	40001	1.1.1.1	53	udp	10	0.002	example.org	1	C_INTERNET	1	A	0	NOERROR	F	F	T	T	0	93.184.216.34	300.0	F
""")

    http_file = tmp_path / "http.log"
    with open(http_file, "w", encoding="utf-8") as f:
        f.write("""#separator \\x09
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	trans_depth	method	host	uri	referrer	version	user_agent	origin	request_body_len	response_body_len	status_code	status_msg	info_code	info_msg	tags	username	password	proxied	orig_fuids	orig_filenames	orig_mime_types	resp_fuids	resp_filenames	resp_mime_types
1700000051.100000	C_BUNDLE_2	192.168.1.10	40002	10.0.0.1	80	1	GET	example.org	/test	-	1.1	curl/7.68.0	-	0	500	200	OK	-	-	(empty)	-	-	-	-	-	-	-	-	-
""")

    out_dir = tmp_path / "processed_bundle"
    bundle = parse_zeek_bundle(
        conn_log=conn_file,
        dns_log=dns_file,
        http_log=http_file,
        output_dir=out_dir
    )

    assert "conn" in bundle
    assert "dns" in bundle
    assert "http" in bundle

    conn_df = bundle["conn"]
    dns_df = bundle["dns"]
    http_df = bundle["http"]

    assert len(conn_df) == 2
    assert len(dns_df) == 1
    assert len(http_df) == 1

    # Verify flow_id was correctly joined across tables
    bundle_1_flow_id = conn_df[conn_df["zeek_uid"] == "C_BUNDLE_1"]["flow_id"].iloc[0]
    bundle_2_flow_id = conn_df[conn_df["zeek_uid"] == "C_BUNDLE_2"]["flow_id"].iloc[0]

    assert dns_df["flow_id"].iloc[0] == bundle_1_flow_id
    assert http_df["flow_id"].iloc[0] == bundle_2_flow_id

    # Verify output parquet files
    assert (out_dir / "conn_flows.parquet").exists()
    assert (out_dir / "dns_events.parquet").exists()
    assert (out_dir / "http_events.parquet").exists()
