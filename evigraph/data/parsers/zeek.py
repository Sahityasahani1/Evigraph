"""
Zeek (Bro) Forensic Network Telemetry Parser
Implements FR-1.1 & FR-2.4:
- Auto-detects and parses conn.log, dns.log, http.log, ssl.log in BOTH TSV (with #fields header)
  and JSON-lines formats.
- conn.log -> Canonical Schema v1.1 flows (orig_h/orig_p/resp_h/resp_p, proto, duration,
  orig_bytes->fwd_bytes, resp_bytes->bwd_bytes, orig_pkts->fwd_pkts, resp_pkts->bwd_pkts, conn_state).
- Treats "-" and "(empty)" as null/None.
- Preserves Zeek uid in canonical column zeek_uid.
- dns.log / http.log / ssl.log -> separate Parquet tables (dns_events, http_events, tls_events)
  with flow_id obtained by joining on zeek_uid.
- Sanitizes attacker-controlled strings: caps length at 256 chars, strips control chars,
  storing sanitized text in main columns and raw text in *_raw columns.
- Robust error tolerance: Counts and logs malformed lines without crashing.
"""

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

from evigraph.data.flow_id import assign_flow_ids
from evigraph.data.schema import PROTO_NAME_MAP, PROTOCOL_MAP, canonicalize, validate

# Regular expression to match ASCII and C1 control characters (0-31 and 127-159)
CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")

_last_zeek_stats: Dict[str, Any] = {}


def get_last_zeek_stats() -> Dict[str, Any]:
    """Returns statistics from the most recent Zeek parsing execution."""
    global _last_zeek_stats
    return _last_zeek_stats.copy()


def parse_zeek_bool(val: Any) -> Optional[bool]:
    """Parses Zeek boolean representation ('T', 'F', 'True', 'False', 1, 0)."""
    if val is None or pd.isna(val):
        return None
    if isinstance(val, (bool, np.bool_)):
        return bool(val)
    s = str(val).strip().lower()
    if s in ("t", "true", "1", "yes"):
        return True
    if s in ("f", "false", "0", "no", "-", "(empty)"):
        return False
    return None


def sanitize_string(val: Any, max_len: int = 256) -> Optional[str]:
    """
    Sanitizes attacker-controlled string:
    - Strips all ASCII and C1 control characters (ord 0-31, 127-159)
    - Caps length at max_len (default 256) characters
    - Returns None if input is null, empty, or Zeek null marker ('-' or '(empty)')
    """
    if val is None or pd.isna(val):
        return None
    s = str(val).strip()
    if not s or s in ("-", "(empty)"):
        return None
    cleaned = CONTROL_CHAR_RE.sub("", s)
    return cleaned[:max_len]


def raw_string_or_none(val: Any) -> Optional[str]:
    """Converts a raw value to string, handling Zeek null markers ('-', '(empty)')."""
    if val is None or pd.isna(val):
        return None
    s = str(val)
    if s in ("-", "(empty)"):
        return None
    return s


def detect_zeek_format(file_path: Path) -> str:
    """
    Detects whether a Zeek log file is in TSV or JSON-lines format by inspecting initial non-empty lines.
    """
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line_str = line.strip()
            if not line_str:
                continue
            if line_str.startswith("#"):
                return "tsv"
            if line_str.startswith("{"):
                return "json"
            if "\t" in line_str:
                return "tsv"
            try:
                json.loads(line_str)
                return "json"
            except Exception:
                pass
    return "tsv"


def flatten_zeek_record(obj: Dict[str, Any]) -> Dict[str, Any]:
    """Flattens nested JSON records (such as 'id': {'orig_h': ...}) to dot-separated keys."""
    flat: Dict[str, Any] = {}
    for k, v in obj.items():
        if isinstance(v, dict):
            for sub_k, sub_v in v.items():
                flat[f"{k}.{sub_k}"] = sub_v
                flat[sub_k] = sub_v
        else:
            flat[k] = v
    return flat


def read_zeek_log(
    file_path: Path | str,
    max_rows: Optional[int] = None
) -> Tuple[List[Dict[str, Any]], Dict[str, int]]:
    """
    Reads a Zeek log file in either TSV or JSON-lines format.
    Handles '-' and '(empty)' as null.
    Silently counts malformed lines without crashing.

    Returns:
        (records, stats) where stats = {"total_lines": int, "valid_records": int, "malformed_lines": int}
    """
    file_path = Path(file_path)
    if not file_path.exists():
        raise FileNotFoundError(f"Zeek log file not found: {file_path}")

    log_format = detect_zeek_format(file_path)
    records: List[Dict[str, Any]] = []
    stats = {
        "total_lines": 0,
        "valid_records": 0,
        "malformed_lines": 0,
    }

    if log_format == "json":
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                stats["total_lines"] += 1
                line_str = line.strip()
                if not line_str or line_str.startswith("#"):
                    continue
                try:
                    raw_obj = json.loads(line_str)
                    if isinstance(raw_obj, dict):
                        clean_obj = {}
                        for k, v in flatten_zeek_record(raw_obj).items():
                            if v in ("-", "(empty)"):
                                clean_obj[k] = None
                            else:
                                clean_obj[k] = v
                        records.append(clean_obj)
                        stats["valid_records"] += 1
                        if max_rows and len(records) >= max_rows:
                            break
                    else:
                        stats["malformed_lines"] += 1
                except Exception:
                    stats["malformed_lines"] += 1
    else:
        # TSV parsing with #fields header
        sep = "\t"
        unset_field = "-"
        empty_field = "(empty)"
        fields: List[str] = []

        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                stats["total_lines"] += 1
                line_clean = line.strip()
                if not line_clean:
                    continue

                if line_clean.startswith("#separator"):
                    parts = line_clean.split(maxsplit=1)
                    if len(parts) > 1:
                        sep_raw = parts[1].strip()
                        try:
                            sep = bytes(sep_raw, "utf-8").decode("unicode_escape")
                        except Exception:
                            sep = "\t"
                    continue

                if line_clean.startswith("#unset_field"):
                    parts = line_clean.split(maxsplit=1)
                    if len(parts) > 1:
                        unset_field = parts[1].strip()
                    continue

                if line_clean.startswith("#empty_field"):
                    parts = line_clean.split(maxsplit=1)
                    if len(parts) > 1:
                        empty_field = parts[1].strip()
                    continue

                if line_clean.startswith("#fields"):
                    # Extract field names using detected separator
                    raw_fields = line_clean[len("#fields"):].strip().split(sep)
                    fields = [f.strip() for f in raw_fields if f.strip()]
                    continue

                if line_clean.startswith("#"):
                    # Comment or directive line
                    continue

                if not fields:
                    stats["malformed_lines"] += 1
                    continue

                parts = line_clean.split(sep)
                if len(parts) != len(fields):
                    # Malformed TSV column count mismatch
                    stats["malformed_lines"] += 1
                    continue

                row_dict: Dict[str, Any] = {}
                for col_name, val in zip(fields, parts, strict=False):
                    v_str = val.strip()
                    if v_str in (unset_field, empty_field, "-", "(empty)"):
                        row_dict[col_name] = None
                    else:
                        row_dict[col_name] = v_str

                records.append(row_dict)
                stats["valid_records"] += 1
                if max_rows and len(records) >= max_rows:
                    break

    return records, stats


def parse_zeek_conn(
    file_path: Path | str,
    evidence_id: Optional[str] = None,
    evidence_sha256: Optional[str] = None,
    max_rows: Optional[int] = None
) -> pd.DataFrame:
    """
    Parses a Zeek conn.log file (TSV or JSON) into Canonical Schema v1.1.

    Features:
    - orig_h/orig_p/resp_h/resp_p mapped to src_ip, src_port, dst_ip, dst_port
    - proto mapped to int16 protocol (TCP=6, UDP=17, ICMP=1) and proto_name
    - duration preserved in SECONDS for duration, and MICROSECONDS for feat_flow_duration
    - orig_bytes/resp_bytes mapped to fwd_bytes/bwd_bytes
    - orig_pkts/resp_pkts mapped to fwd_pkts/bwd_pkts
    - conn_state preserved (null if '-' or empty)
    - zeek_uid populated from Zeek uid
    - source_type set to 'zeek'
    """
    global _last_zeek_stats
    file_path = Path(file_path)
    ev_id = evidence_id or file_path.stem
    ev_sha = evidence_sha256 or "0000000000000000000000000000000000000000000000000000000000000000"

    records, stats = read_zeek_log(file_path, max_rows=max_rows)
    stats["log_type"] = "conn"
    _last_zeek_stats = stats

    if not records:
        return pd.DataFrame()

    raw_df = pd.DataFrame(records)

    df = pd.DataFrame(index=raw_df.index)
    df["evidence_id"] = ev_id
    df["source_type"] = "zeek"

    # Zeek UID
    df["zeek_uid"] = raw_df["uid"].astype(str) if "uid" in raw_df.columns else None

    # IP addresses & ports
    df["src_ip"] = raw_df["id.orig_h"].fillna("0.0.0.0").astype(str) if "id.orig_h" in raw_df.columns else "0.0.0.0"
    df["dst_ip"] = raw_df["id.resp_h"].fillna("0.0.0.0").astype(str) if "id.resp_h" in raw_df.columns else "0.0.0.0"

    src_p = pd.to_numeric(raw_df.get("id.orig_p", 0), errors="coerce").fillna(0).astype("int32")
    dst_p = pd.to_numeric(raw_df.get("id.resp_p", 0), errors="coerce").fillna(0).astype("int32")
    df["src_port"] = np.clip(src_p, 0, 65535)
    df["dst_port"] = np.clip(dst_p, 0, 65535)

    # Protocol
    proto_str = raw_df.get("proto", "tcp").fillna("tcp").astype(str).str.upper()
    df["protocol"] = proto_str.map(lambda p: PROTOCOL_MAP.get(p, 6)).fillna(6).astype("int16")
    df["proto_name"] = df["protocol"].map(lambda p: PROTO_NAME_MAP.get(int(p), f"PROTO_{p}")).astype(str)

    # Timestamps (Zeek epoch floats -> UTC datetime)
    if "ts" in raw_df.columns:
        ts_numeric = pd.to_numeric(raw_df["ts"], errors="coerce").fillna(0.0)
        df["ts_start"] = pd.to_datetime(ts_numeric, unit="s", utc=True)
    else:
        df["ts_start"] = pd.to_datetime("2026-10-18T00:00:00Z", utc=True)

    # Duration: Zeek records duration in SECONDS
    duration_s = pd.to_numeric(raw_df.get("duration", 0.0), errors="coerce").fillna(0.0)
    duration_s = np.maximum(0.0, duration_s)
    df["duration"] = duration_s.astype("float64")
    df["feat_flow_duration"] = (duration_s * 1e6).astype("float32")  # Microseconds for model features
    df["ts_end"] = df["ts_start"] + pd.to_timedelta(df["duration"], unit="s")

    # Byte volumes
    orig_b = pd.to_numeric(raw_df.get("orig_bytes", 0), errors="coerce").fillna(0)
    resp_b = pd.to_numeric(raw_df.get("resp_bytes", 0), errors="coerce").fillna(0)
    df["fwd_bytes"] = np.maximum(0, orig_b).astype("int64")
    df["bwd_bytes"] = np.maximum(0, resp_b).astype("int64")
    df["tot_len_fwd_pkts"] = df["fwd_bytes"].astype("float32")
    df["tot_len_bwd_pkts"] = df["bwd_bytes"].astype("float32")

    # Packet counts
    orig_pkts = pd.to_numeric(raw_df.get("orig_pkts", 0), errors="coerce").fillna(0)
    resp_pkts = pd.to_numeric(raw_df.get("resp_pkts", 0), errors="coerce").fillna(0)
    df["fwd_pkts"] = np.maximum(0, orig_pkts).astype("int64")
    df["bwd_pkts"] = np.maximum(0, resp_pkts).astype("int64")
    df["tot_fwd_pkts"] = df["fwd_pkts"].astype("float32")
    df["tot_bwd_pkts"] = df["bwd_pkts"].astype("float32")

    # Connection state & labels
    df["conn_state"] = raw_df["conn_state"].where(raw_df["conn_state"].notna(), None) if "conn_state" in raw_df.columns else None
    df["label_raw"] = "BENIGN"
    df["label_family"] = "BENIGN"
    df["label"] = "BENIGN"

    # Rates
    dur_safe = duration_s.replace(0.0, np.nan)
    df["flow_bytes_s"] = ((df["fwd_bytes"] + df["bwd_bytes"]) / dur_safe).fillna(0.0).astype("float32")
    df["flow_pkts_s"] = ((df["fwd_pkts"] + df["bwd_pkts"]) / dur_safe).fillna(0.0).astype("float32")

    # Assign deterministic flow_id
    df = assign_flow_ids(df, evidence_sha256=ev_sha)

    # Canonicalize and validate
    df = canonicalize(df)
    validate(df)
    return df


def parse_zeek_dns(
    file_path: Path | str,
    conn_df: Optional[pd.DataFrame] = None,
    uid_to_flow_id: Optional[Dict[str, str]] = None,
    output_parquet: Optional[Path | str] = None,
    max_rows: Optional[int] = None
) -> pd.DataFrame:
    """
    Parses a Zeek dns.log file into the dns_events table.
    Sanitizes query and host strings (capping at 256 chars and stripping control chars),
    while preserving original values in query_raw and host_raw.
    Obtains flow_id by joining on zeek_uid.
    """
    global _last_zeek_stats
    file_path = Path(file_path)
    records, stats = read_zeek_log(file_path, max_rows=max_rows)
    stats["log_type"] = "dns"
    _last_zeek_stats = stats

    if not records:
        return pd.DataFrame()

    raw_df = pd.DataFrame(records)

    # Build UID -> flow_id map
    flow_map = dict(uid_to_flow_id or {})
    if conn_df is not None and "zeek_uid" in conn_df.columns and "flow_id" in conn_df.columns:
        flow_map.update(dict(zip(conn_df["zeek_uid"], conn_df["flow_id"], strict=False)))

    df = pd.DataFrame(index=raw_df.index)
    df["zeek_uid"] = raw_df["uid"].astype(str) if "uid" in raw_df.columns else None
    df["flow_id"] = df["zeek_uid"].map(flow_map)

    # Timestamps
    if "ts" in raw_df.columns:
        ts_num = pd.to_numeric(raw_df["ts"], errors="coerce").fillna(0.0)
        df["ts"] = pd.to_datetime(ts_num, unit="s", utc=True)
    else:
        df["ts"] = pd.to_datetime("2026-10-18T00:00:00Z", utc=True)

    # DNS query string sanitization
    raw_query = raw_df["query"] if "query" in raw_df.columns else pd.Series([None] * len(raw_df))
    df["query_raw"] = raw_query.apply(raw_string_or_none)
    df["query"] = raw_query.apply(lambda q: sanitize_string(q, max_len=256))

    # Host string
    raw_host = raw_df["host"] if "host" in raw_df.columns else raw_query
    df["host_raw"] = raw_host.apply(raw_string_or_none)
    df["host"] = raw_host.apply(lambda h: sanitize_string(h, max_len=256))

    # Query Type & Rcode
    df["qtype"] = raw_df["qtype"].apply(raw_string_or_none) if "qtype" in raw_df.columns else None
    df["qtype_name"] = raw_df["qtype_name"].apply(raw_string_or_none) if "qtype_name" in raw_df.columns else None
    rcode_raw = raw_df["rcode"] if "rcode" in raw_df.columns else pd.Series([None] * len(raw_df))
    df["rcode"] = pd.to_numeric(rcode_raw, errors="coerce")
    df["rcode_name"] = raw_df["rcode_name"].apply(raw_string_or_none) if "rcode_name" in raw_df.columns else None
    df["answers"] = raw_df["answers"].apply(raw_string_or_none) if "answers" in raw_df.columns else None

    # Connection endpoints if present
    df["src_ip"] = raw_df["id.orig_h"].astype(str) if "id.orig_h" in raw_df.columns else None
    df["dst_ip"] = raw_df["id.resp_h"].astype(str) if "id.resp_h" in raw_df.columns else None
    src_p_raw = raw_df["id.orig_p"] if "id.orig_p" in raw_df.columns else pd.Series([None] * len(raw_df))
    dst_p_raw = raw_df["id.resp_p"] if "id.resp_p" in raw_df.columns else pd.Series([None] * len(raw_df))
    df["src_port"] = pd.to_numeric(src_p_raw, errors="coerce")
    df["dst_port"] = pd.to_numeric(dst_p_raw, errors="coerce")

    if output_parquet:
        out_path = Path(output_parquet)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        table = pa.Table.from_pandas(df, preserve_index=False)
        pq.write_table(table, out_path, compression="snappy")

    return df


def parse_zeek_http(
    file_path: Path | str,
    conn_df: Optional[pd.DataFrame] = None,
    uid_to_flow_id: Optional[Dict[str, str]] = None,
    output_parquet: Optional[Path | str] = None,
    max_rows: Optional[int] = None
) -> pd.DataFrame:
    """
    Parses a Zeek http.log file into the http_events table.
    Sanitizes uri, user_agent, and host strings (capping at 256 chars and stripping control chars),
    while preserving original values in uri_raw, user_agent_raw, and host_raw.
    Obtains flow_id by joining on zeek_uid.
    """
    global _last_zeek_stats
    file_path = Path(file_path)
    records, stats = read_zeek_log(file_path, max_rows=max_rows)
    stats["log_type"] = "http"
    _last_zeek_stats = stats

    if not records:
        return pd.DataFrame()

    raw_df = pd.DataFrame(records)

    # Build UID -> flow_id map
    flow_map = dict(uid_to_flow_id or {})
    if conn_df is not None and "zeek_uid" in conn_df.columns and "flow_id" in conn_df.columns:
        flow_map.update(dict(zip(conn_df["zeek_uid"], conn_df["flow_id"], strict=False)))

    df = pd.DataFrame(index=raw_df.index)
    df["zeek_uid"] = raw_df["uid"].astype(str) if "uid" in raw_df.columns else None
    df["flow_id"] = df["zeek_uid"].map(flow_map)

    # Timestamps
    if "ts" in raw_df.columns:
        ts_num = pd.to_numeric(raw_df["ts"], errors="coerce").fillna(0.0)
        df["ts"] = pd.to_datetime(ts_num, unit="s", utc=True)
    else:
        df["ts"] = pd.to_datetime("2026-10-18T00:00:00Z", utc=True)

    # Host sanitization
    raw_host = raw_df["host"] if "host" in raw_df.columns else pd.Series([None] * len(raw_df))
    df["host_raw"] = raw_host.apply(raw_string_or_none)
    df["host"] = raw_host.apply(lambda h: sanitize_string(h, max_len=256))

    # Method
    df["method"] = raw_df["method"].astype(str).str.upper() if "method" in raw_df.columns else None

    # URI sanitization
    raw_uri = raw_df["uri"] if "uri" in raw_df.columns else pd.Series([None] * len(raw_df))
    df["uri_raw"] = raw_uri.apply(raw_string_or_none)
    df["uri"] = raw_uri.apply(lambda u: sanitize_string(u, max_len=256))

    # User-Agent sanitization
    raw_ua = raw_df["user_agent"] if "user_agent" in raw_df.columns else pd.Series([None] * len(raw_df))
    df["user_agent_raw"] = raw_ua.apply(raw_string_or_none)
    df["user_agent"] = raw_ua.apply(lambda ua: sanitize_string(ua, max_len=256))

    # Status Code / Status
    status_code_raw = raw_df["status_code"] if "status_code" in raw_df.columns else pd.Series([None] * len(raw_df))
    df["status_code"] = pd.to_numeric(status_code_raw, errors="coerce")
    df["status"] = raw_df["status_msg"].apply(raw_string_or_none) if "status_msg" in raw_df.columns else df["status_code"].astype(str)

    # Body lengths
    req_b = raw_df["request_body_len"] if "request_body_len" in raw_df.columns else pd.Series(0, index=raw_df.index)
    resp_b = raw_df["response_body_len"] if "response_body_len" in raw_df.columns else pd.Series(0, index=raw_df.index)
    df["request_body_len"] = pd.to_numeric(req_b, errors="coerce").fillna(0).astype("int64")
    df["response_body_len"] = pd.to_numeric(resp_b, errors="coerce").fillna(0).astype("int64")

    # Connection endpoints if present
    df["src_ip"] = raw_df["id.orig_h"].astype(str) if "id.orig_h" in raw_df.columns else None
    df["dst_ip"] = raw_df["id.resp_h"].astype(str) if "id.resp_h" in raw_df.columns else None
    src_p = raw_df["id.orig_p"] if "id.orig_p" in raw_df.columns else pd.Series([None] * len(raw_df))
    dst_p = raw_df["id.resp_p"] if "id.resp_p" in raw_df.columns else pd.Series([None] * len(raw_df))
    df["src_port"] = pd.to_numeric(src_p, errors="coerce")
    df["dst_port"] = pd.to_numeric(dst_p, errors="coerce")

    if output_parquet:
        out_path = Path(output_parquet)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        table = pa.Table.from_pandas(df, preserve_index=False)
        pq.write_table(table, out_path, compression="snappy")

    return df


def parse_zeek_ssl(
    file_path: Path | str,
    conn_df: Optional[pd.DataFrame] = None,
    uid_to_flow_id: Optional[Dict[str, str]] = None,
    output_parquet: Optional[Path | str] = None,
    max_rows: Optional[int] = None
) -> pd.DataFrame:
    """
    Parses a Zeek ssl.log file into the tls_events table.
    Sanitizes ja3, sni, and server_name strings (capping at 256 chars and stripping control chars),
    while preserving original values in ja3_raw, sni_raw, and server_name_raw.
    Obtains flow_id by joining on zeek_uid.
    """
    global _last_zeek_stats
    file_path = Path(file_path)
    records, stats = read_zeek_log(file_path, max_rows=max_rows)
    stats["log_type"] = "ssl"
    _last_zeek_stats = stats

    if not records:
        return pd.DataFrame()

    raw_df = pd.DataFrame(records)

    # Build UID -> flow_id map
    flow_map = dict(uid_to_flow_id or {})
    if conn_df is not None and "zeek_uid" in conn_df.columns and "flow_id" in conn_df.columns:
        flow_map.update(dict(zip(conn_df["zeek_uid"], conn_df["flow_id"], strict=False)))

    df = pd.DataFrame(index=raw_df.index)
    df["zeek_uid"] = raw_df["uid"].astype(str) if "uid" in raw_df.columns else None
    df["flow_id"] = df["zeek_uid"].map(flow_map)

    # Timestamps
    if "ts" in raw_df.columns:
        ts_num = pd.to_numeric(raw_df["ts"], errors="coerce").fillna(0.0)
        df["ts"] = pd.to_datetime(ts_num, unit="s", utc=True)
    else:
        df["ts"] = pd.to_datetime("2026-10-18T00:00:00Z", utc=True)

    # SNI sanitization
    raw_sni = raw_df["sni"] if "sni" in raw_df.columns else pd.Series([None] * len(raw_df))
    df["sni_raw"] = raw_sni.apply(raw_string_or_none)
    df["sni"] = raw_sni.apply(lambda s: sanitize_string(s, max_len=256))

    # Server Name sanitization
    raw_sn = raw_df["server_name"] if "server_name" in raw_df.columns else raw_sni
    df["server_name_raw"] = raw_sn.apply(raw_string_or_none)
    df["server_name"] = raw_sn.apply(lambda sn: sanitize_string(sn, max_len=256))

    # Host
    df["host_raw"] = df["server_name_raw"].combine_first(df["sni_raw"])
    df["host"] = df["server_name"].combine_first(df["sni"])

    # JA3 sanitization
    raw_ja3 = raw_df["ja3"] if "ja3" in raw_df.columns else pd.Series([None] * len(raw_df))
    df["ja3_raw"] = raw_ja3.apply(raw_string_or_none)
    df["ja3"] = raw_ja3.apply(lambda j: sanitize_string(j, max_len=256))

    # TLS metadata
    df["version"] = raw_df["version"].apply(raw_string_or_none) if "version" in raw_df.columns else None
    df["cipher"] = raw_df["cipher"].apply(raw_string_or_none) if "cipher" in raw_df.columns else None
    df["established"] = raw_df["established"].apply(parse_zeek_bool) if "established" in raw_df.columns else None
    df["resumed"] = raw_df["resumed"].apply(parse_zeek_bool) if "resumed" in raw_df.columns else None

    # Connection endpoints if present
    df["src_ip"] = raw_df["id.orig_h"].astype(str) if "id.orig_h" in raw_df.columns else None
    df["dst_ip"] = raw_df["id.resp_h"].astype(str) if "id.resp_h" in raw_df.columns else None
    src_p_raw = raw_df["id.orig_p"] if "id.orig_p" in raw_df.columns else pd.Series([None] * len(raw_df))
    dst_p_raw = raw_df["id.resp_p"] if "id.resp_p" in raw_df.columns else pd.Series([None] * len(raw_df))
    df["src_port"] = pd.to_numeric(src_p_raw, errors="coerce")
    df["dst_port"] = pd.to_numeric(dst_p_raw, errors="coerce")

    if output_parquet:
        out_path = Path(output_parquet)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        table = pa.Table.from_pandas(df, preserve_index=False)
        pq.write_table(table, out_path, compression="snappy")

    return df


def parse_zeek_bundle(
    conn_log: Path | str,
    dns_log: Optional[Path | str] = None,
    http_log: Optional[Path | str] = None,
    ssl_log: Optional[Path | str] = None,
    output_dir: Optional[Path | str] = None
) -> Dict[str, pd.DataFrame]:
    """
    Parses a complete Zeek session bundle:
    1. Parses conn.log into canonical flows.
    2. Uses resulting zeek_uid -> flow_id mapping to join events.
    3. Parses dns.log, http.log, and ssl.log into event tables.
    4. Writes dns_events.parquet, http_events.parquet, and tls_events.parquet if output_dir specified.
    """
    results: Dict[str, pd.DataFrame] = {}
    out_dir = Path(output_dir) if output_dir else None
    if out_dir:
        out_dir.mkdir(parents=True, exist_ok=True)

    # 1. Parse conn.log
    conn_df = parse_zeek_conn(conn_log)
    results["conn"] = conn_df

    if out_dir and not conn_df.empty:
        pq.write_table(
            pa.Table.from_pandas(conn_df, preserve_index=False),
            out_dir / "conn_flows.parquet",
            compression="snappy"
        )

    # 2. Parse dns.log
    if dns_log and Path(dns_log).exists():
        dns_out = (out_dir / "dns_events.parquet") if out_dir else None
        results["dns"] = parse_zeek_dns(dns_log, conn_df=conn_df, output_parquet=dns_out)

    # 3. Parse http.log
    if http_log and Path(http_log).exists():
        http_out = (out_dir / "http_events.parquet") if out_dir else None
        results["http"] = parse_zeek_http(http_log, conn_df=conn_df, output_parquet=http_out)

    # 4. Parse ssl.log
    if ssl_log and Path(ssl_log).exists():
        ssl_out = (out_dir / "tls_events.parquet") if out_dir else None
        results["ssl"] = parse_zeek_ssl(ssl_log, conn_df=conn_df, output_parquet=ssl_out)

    return results
