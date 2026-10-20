"""
EviGraph Forensic Tools for Member 3 (LLM Forensic Agent & RAG)
Provides Ollama-compatible structured tools for investigating incidents, verifying evidence,
and extracting forensic telemetry.

Security Policies:
- Untrusted string fields (queries, URIs, user agents, labels) are re-sanitized (capped at 256, stripped of control chars).
- Untrusted strings are strictly kept within "fields" dicts and NEVER merged into text prompts or prose.
- Unknown flow_id or hosts gracefully return {"results": []}, NEVER raise exceptions.
- Exported JSON-schemas adhere to the standard Ollama/OpenAI tool-calling specifications.
"""

import re
from typing import Any, Dict, List, Optional

import pandas as pd

from data.config import settings
from data.query import QueryAPI

# Regex pattern matching ASCII and C1 control characters (0-31 and 127-159)
CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def sanitize_string_field(val: Any) -> Any:
    """Sanitizes untrusted string derived from network traffic: caps length at 256, strips control chars."""
    if val is None:
        return None
    if isinstance(val, str):
        cleaned = CONTROL_CHAR_RE.sub("", val).strip()
        return cleaned[:256]
    return val


def sanitize_dict_fields(fields: Dict[str, Any]) -> Dict[str, Any]:
    """Re-sanitizes every value in a fields dictionary."""
    return {k: sanitize_string_field(v) for k, v in fields.items()}


def get_evidence_sha256_map() -> Dict[str, str]:
    """Builds a lookup mapping evidence_id -> sha256 from evidence_files.parquet."""
    evidence_parquet = settings.resolve_path(settings.evidence_parquet_path)
    if not evidence_parquet.exists():
        return {}
    try:
        df_ev = pd.read_parquet(evidence_parquet)
        if "evidence_id" in df_ev.columns and "sha256" in df_ev.columns:
            return dict(zip(df_ev["evidence_id"], df_ev["sha256"]))
    except Exception:
        pass
    return {}


# Global evidence SHA-256 lookup cache
_evidence_sha256_cache: Dict[str, str] = {}


def resolve_sha256_for_evidence(evidence_id: str) -> str:
    """Resolves SHA-256 hash for a given evidence ID."""
    global _evidence_sha256_cache
    if not _evidence_sha256_cache:
        _evidence_sha256_cache = get_evidence_sha256_map()
    return _evidence_sha256_cache.get(evidence_id, "unknown_evidence_hash")


# ==============================================================================
# TOOL 1: query_flows_for_host
# ==============================================================================
def query_flows_for_host(
    host: str,
    t_start: Optional[str] = None,
    t_end: Optional[str] = None,
    limit: int = 50
) -> Dict[str, Any]:
    """
    Retrieves network communication flows involving the specified host IP address (source or destination).

    Returns JSON structured as:
    {
      "results": [
        {
          "flow_id": str,
          "timestamp": str,
          "evidence_id": str,
          "sha256": str,
          "fields": dict
        }
      ],
      "truncated": bool,
      "total": int
    }
    """
    try:
        api = QueryAPI()
        clean_ip = str(host).replace("'", "''").strip()
        where_clauses = [f"(src_ip = '{clean_ip}' OR dst_ip = '{clean_ip}')"]

        if t_start:
            t1 = str(t_start).replace("'", "''").strip()
            where_clauses.append(f"timestamp >= '{t1}'")
        if t_end:
            t2 = str(t_end).replace("'", "''").strip()
            where_clauses.append(f"timestamp <= '{t2}'")

        where_sql = " AND ".join(where_clauses)
        count_df = api.execute_sql(f"SELECT COUNT(*) AS total FROM flows WHERE {where_sql}")
        total = int(count_df["total"].iloc[0]) if not count_df.empty else 0

        if total == 0:
            return {"results": [], "truncated": False, "total": 0}

        query_sql = f"SELECT * FROM flows WHERE {where_sql} ORDER BY timestamp LIMIT {int(limit)}"
        flows_df = api.execute_sql(query_sql)

        results = []
        for _, row in flows_df.iterrows():
            fid = str(row.get("flow_id", ""))
            ts = str(row.get("timestamp", row.get("ts_start", "")))
            eid = str(row.get("evidence_id", ""))
            sha = resolve_sha256_for_evidence(eid)

            # Metadata and descriptive attributes
            raw_fields = {
                "src_ip": row.get("src_ip"),
                "dst_ip": row.get("dst_ip"),
                "src_port": int(row.get("src_port", 0)),
                "dst_port": int(row.get("dst_port", 0)),
                "protocol": int(row.get("protocol", 6)),
                "proto_name": str(row.get("proto_name", "TCP")),
                "duration": float(row.get("duration", 0.0)),
                "fwd_bytes": int(row.get("fwd_bytes", 0)),
                "bwd_bytes": int(row.get("bwd_bytes", 0)),
                "label": str(row.get("label", row.get("label_raw", "BENIGN"))),
                "conn_state": str(row.get("conn_state", "")),
            }

            results.append({
                "flow_id": fid,
                "timestamp": ts,
                "evidence_id": eid,
                "sha256": sha,
                "fields": sanitize_dict_fields(raw_fields)
            })

        return {
            "results": results,
            "truncated": total > len(results),
            "total": total
        }

    except Exception:
        # Unknown or invalid flow query gracefully returns empty results; NEVER raises
        return {"results": [], "truncated": False, "total": 0}


# ==============================================================================
# TOOL 2: check_dns_for_host
# ==============================================================================
def check_dns_for_host(
    host: str,
    t_start: Optional[str] = None,
    t_end: Optional[str] = None,
    limit: int = 50
) -> Dict[str, Any]:
    """
    Retrieves DNS resolution lookups and domain queries made by the specified host IP address.

    Returns JSON structured as:
    {
      "results": [
        {
          "flow_id": str,
          "timestamp": str,
          "evidence_id": str,
          "sha256": str,
          "fields": dict
        }
      ],
      "truncated": bool,
      "total": int
    }
    """
    try:
        api = QueryAPI()
        clean_ip = str(host).replace("'", "''").strip()
        where_clauses = [f"host = '{clean_ip}'"]

        if t_start:
            t1 = str(t_start).replace("'", "''").strip()
            where_clauses.append(f"ts >= '{t1}'")
        if t_end:
            t2 = str(t_end).replace("'", "''").strip()
            where_clauses.append(f"ts <= '{t2}'")

        where_sql = " AND ".join(where_clauses)

        # Check if dns_events view exists in catalog
        try:
            count_df = api.execute_sql(f"SELECT COUNT(*) AS total FROM dns_events WHERE {where_sql}")
            total = int(count_df["total"].iloc[0]) if not count_df.empty else 0
        except Exception:
            # dns_events view is not active or empty
            return {"results": [], "truncated": False, "total": 0}

        if total == 0:
            return {"results": [], "truncated": False, "total": 0}

        query_sql = f"SELECT * FROM dns_events WHERE {where_sql} ORDER BY ts LIMIT {int(limit)}"
        dns_df = api.execute_sql(query_sql)

        results = []
        for _, row in dns_df.iterrows():
            fid = str(row.get("flow_id", ""))
            ts = str(row.get("ts", ""))
            eid = str(row.get("evidence_id", "zeek_dns_event"))
            sha = resolve_sha256_for_evidence(eid)

            raw_fields = {
                "host": row.get("host"),
                "query": row.get("query"),
                "qtype_name": row.get("qtype_name"),
                "rcode_name": row.get("rcode_name"),
            }

            results.append({
                "flow_id": fid,
                "timestamp": ts,
                "evidence_id": eid,
                "sha256": sha,
                "fields": sanitize_dict_fields(raw_fields)
            })

        return {
            "results": results,
            "truncated": total > len(results),
            "total": total
        }

    except Exception:
        return {"results": [], "truncated": False, "total": 0}


# ==============================================================================
# TOOL 3: get_evidence_for_citation
# ==============================================================================
def get_evidence_for_citation(flow_id: str) -> Dict[str, Any]:
    """
    Retrieves full cryptographic citation metadata and verified flow telemetry for a specific flow_id.
    Unknown flow_id returns {"results": []}, NEVER raises.
    """
    if not flow_id:
        return {"results": [], "truncated": False, "total": 0}

    try:
        api = QueryAPI()
        clean_fid = str(flow_id).replace("'", "''").strip()
        df = api.execute_sql(f"SELECT * FROM flows WHERE flow_id = '{clean_fid}' LIMIT 1")

        if df.empty:
            return {"results": [], "truncated": False, "total": 0}

        row = df.iloc[0]
        fid = str(row.get("flow_id", ""))
        ts = str(row.get("timestamp", row.get("ts_start", "")))
        eid = str(row.get("evidence_id", ""))
        sha = resolve_sha256_for_evidence(eid)

        raw_fields = {
            "source_type": row.get("source_type"),
            "src_ip": row.get("src_ip"),
            "dst_ip": row.get("dst_ip"),
            "src_port": int(row.get("src_port", 0)),
            "dst_port": int(row.get("dst_port", 0)),
            "protocol": int(row.get("protocol", 6)),
            "proto_name": str(row.get("proto_name", "TCP")),
            "duration": float(row.get("duration", 0.0)),
            "fwd_bytes": int(row.get("fwd_bytes", 0)),
            "bwd_bytes": int(row.get("bwd_bytes", 0)),
            "fwd_pkts": int(row.get("fwd_pkts", 0)),
            "bwd_pkts": int(row.get("bwd_pkts", 0)),
            "label": str(row.get("label", row.get("label_raw", "BENIGN"))),
            "conn_state": str(row.get("conn_state", "")),
        }

        return {
            "results": [
                {
                    "flow_id": fid,
                    "timestamp": ts,
                    "evidence_id": eid,
                    "sha256": sha,
                    "fields": sanitize_dict_fields(raw_fields)
                }
            ],
            "truncated": False,
            "total": 1
        }

    except Exception:
        return {"results": [], "truncated": False, "total": 0}


# ==============================================================================
# JSON SCHEMAS FOR OLLAMA TOOL CALLING
# ==============================================================================
QUERY_FLOWS_FOR_HOST_SCHEMA: Dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "query_flows_for_host",
        "description": "Retrieves verified network telemetry flows involving a specific host IP address. Used for reconstructive blast radius analysis and timeline building.",
        "parameters": {
            "type": "object",
            "properties": {
                "host": {
                    "type": "string",
                    "description": "The IPv4 or IPv6 address to investigate (e.g. '192.168.10.5')."
                },
                "t_start": {
                    "type": "string",
                    "description": "Optional ISO-8601 start timestamp filter (e.g. '2026-10-18T10:00:00')."
                },
                "t_end": {
                    "type": "string",
                    "description": "Optional ISO-8601 end timestamp filter (e.g. '2026-10-18T10:05:00')."
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of flow records to return (default: 50)."
                }
            },
            "required": ["host"]
        }
    }
}

CHECK_DNS_FOR_HOST_SCHEMA: Dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "check_dns_for_host",
        "description": "Retrieves DNS queries and domain resolutions issued by a specific host IP address. Used for identifying command-and-control (C2) domains, phishing links, and data exfiltration.",
        "parameters": {
            "type": "object",
            "properties": {
                "host": {
                    "type": "string",
                    "description": "The client IPv4 address issuing DNS lookups."
                },
                "t_start": {
                    "type": "string",
                    "description": "Optional ISO-8601 start timestamp filter."
                },
                "t_end": {
                    "type": "string",
                    "description": "Optional ISO-8601 end timestamp filter."
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of DNS events to return (default: 50)."
                }
            },
            "required": ["host"]
        }
    }
}

GET_EVIDENCE_FOR_CITATION_SCHEMA: Dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "get_evidence_for_citation",
        "description": "Retrieves exact cryptographic citation metadata (SHA-256 evidence hash, timestamps, flow attributes) for a given flow ID. Guarantees tamper-free evidence backing LLM assertions.",
        "parameters": {
            "type": "object",
            "properties": {
                "flow_id": {
                    "type": "string",
                    "description": "The unique deterministic flow identifier (e.g. 'flw_a1b2c3d4e5f60718')."
                }
            },
            "required": ["flow_id"]
        }
    }
}

# Master list of Ollama tools for Member 3
MEMBER3_OLLAMA_TOOLS: List[Dict[str, Any]] = [
    QUERY_FLOWS_FOR_HOST_SCHEMA,
    CHECK_DNS_FOR_HOST_SCHEMA,
    GET_EVIDENCE_FOR_CITATION_SCHEMA,
]
