import logging
logger = logging.getLogger('evigraph.server')
import hashlib
import json
import os
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from ipaddress import ip_address, ip_network
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware

from src.agent.flow_store import FlowStore
from src.investigation_pipeline import run_investigation_pipeline
from src.agent.mock import (
    investigate as mock_investigate,
    list_incidents as mock_list_incidents,
    load_agent as mock_load_agent,
)
from src.agent.api import (
    investigate as real_investigate,
    list_incidents as real_list_incidents,
    load_agent as real_load_agent,
)

BASE_DIR = Path(__file__).resolve().parent.parent / "evigraph-backend"
DATA_FILE = BASE_DIR / "outputs" / "incident_cases.json"
FALLBACK_DATA_FILE = Path(__file__).resolve().parent.parent.parent / "outputs" / "incident_cases.json"
INVESTIGATION_ROOT = Path(os.environ.get(
    "EVIGRAPH_INVESTIGATIONS_DIR",
    str(Path(__file__).resolve().parents[2] / "outputs" / "investigations"),
))
MAX_UPLOAD_BYTES = 2 * 1024 * 1024 * 1024
_investigation_jobs: dict[str, dict] = {}
_job_lock = threading.RLock()
_job_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="evigraph-investigation")

PRIVATE_NETWORKS = [ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]

app = FastAPI(title="EviGraph API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_methods=["*"],
    allow_headers=["*"],
)


def is_internal_ip(ip_str: str) -> bool:
    try:
        addr = ip_address(ip_str)
        return any(addr in net for net in PRIVATE_NETWORKS)
    except ValueError:
        return False


def load_cases():
    target_file = DATA_FILE if DATA_FILE.exists() else FALLBACK_DATA_FILE
    if not target_file.exists():
        raise HTTPException(
            status_code=503,
            detail="Incident data not found. Run the detection pipeline first.",
        )

    with target_file.open(encoding="utf-8") as f:
        return json.load(f)


def _agent_mode() -> str:
    mode = os.environ.get("EVIGRAPH_AGENT_MODE", "demo").strip().lower()
    if mode not in {"demo", "real"}:
        raise HTTPException(
            status_code=503,
            detail="EVIGRAPH_AGENT_MODE must be either 'demo' or 'real'.",
        )
    return mode


def _load_real_agent():
    flows_path = Path(os.environ.get(
        "EVIGRAPH_FLOWS_PATH", "data/raw/processed/benchmark_test_flows.parquet"
    ))
    incidents_path = Path(os.environ.get(
        "EVIGRAPH_INCIDENTS_PATH", "data/standin/incident_cases.json"
    ))
    for path, label in ((flows_path, "flow data"), (incidents_path, "incident data")):
        if not path.is_file():
            raise HTTPException(
                status_code=503,
                detail=f"Real ATT&CK investigation requires {label}; file not found at {path.resolve()}.",
            )
    try:
        return real_load_agent(flows_path, incidents_path)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


def normalize_agent_incident(summary: dict) -> dict:
    """Adapt the real forensic agent's evidence-backed stages to the dashboard schema."""
    hosts = {}
    stages = []
    for idx, stage in enumerate(summary.get("stages_in_time_order", []), 1):
        sources, targets = stage.get("sources", []), stage.get("targets", [])
        src = sources[0] if sources else "unknown"
        dst = targets[0] if targets else "unknown"
        for ip, role in ((src, "source"), (dst, "target")):
            if ip != "unknown" and ip not in hosts:
                hosts[ip] = {
                    "id": ip,
                    "ip": ip,
                    "zone": "INTERNAL" if is_internal_ip(ip) else "EXTERNAL",
                    "role": role,
                }
        evidence = stage.get("evidence", [])
        risk = max((float(e.get("risk_score", 0)) for e in evidence), default=0.0)
        tactic, tactic_id = map_tactic(stage.get("attack_class", ""))
        stages.append({
            "stage_id": f"{summary['incident_id']}-stage-{idx}",
            "order": idx,
            "tactic": tactic,
            "tactic_id": tactic_id,
            "src": src,
            "dst": dst,
            "port": ", ".join(str(e["dst_port"]) for e in evidence if e.get("dst_port") is not None),
            "start": stage.get("first_seen"),
            "end": stage.get("last_seen"),
            "confidence": risk,
            "observed": bool(evidence),
            "behavior": stage.get("attack_class", ""),
            "summary": f"{stage.get('attack_class', 'Unknown')} activity ({stage.get('alert_count', 0)} alerts)",
            "evidence": [
                {
                    "flow_id": e.get("flow_id"),
                    "ts": e.get("timestamp", stage.get("first_seen")),
                    "evidence_id": e.get("evidence_id"),
                    "pcap_sha256": "",
                }
                for e in evidence
            ],
            "explanation": [],
        })
    return {
        "incident_id": summary["incident_id"],
        "score": float(summary.get("severity_score", 0)),
        "start": summary.get("start"),
        "end": summary.get("end"),
        "status": "Open",
        "hosts": list(hosts.values()),
        "stages": stages,
        "background": [],
        "attack_classes": [s.get("attack_class") for s in summary.get("stages_in_time_order", [])],
        "total_alerts": summary.get("alert_count", 0),
    }


def to_iso(value):
    if not value:
        return None

    # Convert timestamps to ISO format without changing their time.
    return datetime.fromisoformat(
        value.replace("Z", "+00:00")
    ).isoformat()


def get_chain(incident):
    chain = incident.get("primary_attack_chain")
    if not chain:
        chain = incident.get("causal_provenance", {}).get(
            "primary_attack_chain", []
        )
    return chain or []


TACTIC_MAP = {
    "Reconnaissance": "TA0043",
    "Initial Access": "TA0001",
    "Credential Access": "TA0006",
    "Lateral Movement": "TA0008",
    "Command and Control": "TA0011",
    "Exfiltration": "TA0010",
    "Exfiltration & Impact": "TA0040",
    "Impact": "TA0040",
}

CLASS_TO_TACTIC = {
    "Lateral-SMB-Relay": ("Lateral Movement", "TA0008"),
    "C2-Heartbeat": ("Command and Control", "TA0011"),
    "HTTPS-Exfiltration": ("Exfiltration", "TA0010"),
    "PortScan": ("Reconnaissance", "TA0043"),
    "SSH-Patator": ("Credential Access", "TA0006"),
    "FTP-Patator": ("Credential Access", "TA0006"),
    "DoS": ("Impact", "TA0040"),
    "DDoS": ("Impact", "TA0040"),
    "Bot": ("Command and Control", "TA0011"),
    "Infiltration": ("Initial Access", "TA0001"),
    "Web Attack": ("Initial Access", "TA0001"),
}


def map_tactic(name: str):
    if name in TACTIC_MAP:
        return name, TACTIC_MAP[name]
    for key, (tac, tid) in CLASS_TO_TACTIC.items():
        if key.lower() in name.lower():
            return tac, tid
    if "recon" in name.lower() or "scan" in name.lower():
        return "Reconnaissance", "TA0043"
    if "cred" in name.lower() or "patator" in name.lower() or "brute" in name.lower():
        return "Credential Access", "TA0006"
    if "lateral" in name.lower() or "smb" in name.lower():
        return "Lateral Movement", "TA0008"
    if "c2" in name.lower() or "command" in name.lower() or "heartbeat" in name.lower() or "beacon" in name.lower():
        return "Command and Control", "TA0011"
    if "exfil" in name.lower():
        return "Exfiltration", "TA0010"
    return "Unknown", ""


def normalize_incident(incident):
    chain = get_chain(incident)

    node_dict = {
        node["id"]: node
        for node in incident.get("subgraph", {}).get("nodes", [])
        if "id" in node
    }
    edge_map = {
        edge.get("edge_id"): edge
        for edge in incident.get("subgraph", {}).get("edges", [])
    }

    entry_point = incident.get("suspected_entry_point")

    # Collect all unique host identifiers referenced across affected hosts, steps, and nodes
    host_ips = list(incident.get("affected_hosts", []))
    for step in chain:
        src = step.get("source")
        dst = step.get("target")
        if src and src not in host_ips:
            host_ips.append(src)
        if dst and dst not in host_ips:
            host_ips.append(dst)
    for nid in node_dict:
        if nid not in host_ips:
            host_ips.append(nid)

    hosts = []
    for ip in host_ips:
        node = node_dict.get(ip, {})
        role = node.get("role", "unknown")

        # Derive host network zone from verified topology/role data:
        # Attackers / external entry points belong to EXTERNAL.
        # Protected internal victim hosts belong to INTERNAL.
        zone = node.get("zone")
        if zone not in ("EXTERNAL", "DMZ", "INTERNAL"):
            if role == "attacker" or ip == entry_point or not is_internal_ip(ip):
                zone = "EXTERNAL"
            else:
                zone = "INTERNAL"

        hosts.append({
            "id": ip,
            "ip": ip,
            "zone": zone,
            "role": role,
        })

    stages = []
    for step in chain:
        timestamp = to_iso(step.get("timestamp"))
        fid = step.get("flow_id")
        edge = edge_map.get(fid, {})

        pcap_sha256 = edge.get("pcap_sha256") or edge.get("sha256")

        tactic = step.get("attack_stage", "Unknown")
        tactic_id = TACTIC_MAP.get(tactic, "")
        pred_class = step.get("predicted_class", "")
        dst_port = step.get("dst_port")

        explanation = [
            {
                "feature": str(exp.get("feature", "unknown")),
                "weight": float(exp.get("importance", 0.0)),
            }
            for exp in edge.get("shap_explanation", [])
        ]

        summary = step.get("summary")
        if not summary:
            if pred_class and dst_port:
                summary = f"{pred_class} activity on port {dst_port}"
            elif pred_class:
                summary = f"{pred_class} activity"
            else:
                summary = f"{tactic} activity"

        stages.append({
            "stage_id": f"{incident['incident_id']}-stage-{step['step']}",
            "order": step["step"],
            "tactic": tactic,
            "tactic_id": tactic_id,
            "src": step.get("source"),
            "dst": step.get("target"),
            "port": str(dst_port) if dst_port is not None else "",
            "start": timestamp,
            "end": timestamp,
            "confidence": float(step.get("risk_score", 0.5)),
            "observed": True,
            "interpretation_status": step.get("interpretation_status", "inferred"),
            "behavior": pred_class,
            "summary": summary,
            "evidence": [{
                "flow_id": fid,
                "ts": timestamp,
                "evidence_id": edge.get("evidence_id"),
                "source_sha256": edge.get("source_sha256"),
                "pcap_sha256": pcap_sha256,
                "merkle_leaf_hash": edge.get("merkle_leaf_hash"),
                "merkle_verified": edge.get("merkle_verified", False),
            }],
            "explanation": explanation,
        })

    background = [
        {"src": e.get("source"), "dst": e.get("target")}
        for e in incident.get("subgraph", {}).get("edges", [])
        if not e.get("is_alert", False)
    ]

    return {
        "incident_id": incident["incident_id"],
        "score": float(incident.get("incident_score", 0)),
        "start": to_iso(incident.get("start_time")),
        "end": to_iso(incident.get("end_time")),
        "status": incident.get("status", "Open"),
        "hosts": hosts,
        "stages": stages,
        "background": background,
        "attack_classes": incident.get("attack_classes", []),
        "total_alerts": incident.get("total_alerts", 0),
        "inference_source": incident.get("inference_source", "prepared"),
        "source_sha256": incident.get("source_sha256"),
        "merkle_root": incident.get("merkle_root"),
        "detection_model": incident.get("detection_model"),
    }


def normalize_mock_incident(mock_data: dict) -> dict:
    inc_id = mock_data["incident_id"]
    timeline = mock_data.get("timeline", [])
    roles = mock_data.get("host_roles", {})

    hosts_dict = {}
    for cat, role_name, default_zone in [
        ("attackers", "attacker", "EXTERNAL"),
        ("infra", "attacker infrastructure", "EXTERNAL"),
        ("compromised", "compromised", "INTERNAL"),
        ("victims", "target host", "INTERNAL"),
    ]:
        for ip in roles.get(cat, {}).get("hosts", []):
            zone = default_zone
            if not zone:
                zone = "INTERNAL" if is_internal_ip(ip) else "EXTERNAL"
            hosts_dict[ip] = {
                "id": ip,
                "ip": ip,
                "zone": zone,
                "role": role_name,
            }

    for stage in timeline:
        for ip in stage.get("sources", []):
            if ip not in hosts_dict:
                hosts_dict[ip] = {
                    "id": ip,
                    "ip": ip,
                    "zone": "INTERNAL" if is_internal_ip(ip) else "EXTERNAL",
                    "role": "source",
                }
        for ip in stage.get("targets", []):
            if ip not in hosts_dict:
                hosts_dict[ip] = {
                    "id": ip,
                    "ip": ip,
                    "zone": "INTERNAL" if is_internal_ip(ip) else "EXTERNAL",
                    "role": "target",
                }

    hosts = list(hosts_dict.values())

    stages = []
    for idx, stage in enumerate(timeline, 1):
        attack_cls = stage.get("attack_class", "Unknown")
        tactic, tactic_id = map_tactic(attack_cls)

        src_list = stage.get("sources", [])
        dst_list = stage.get("targets", [])
        src = src_list[0] if src_list else (hosts[0]["id"] if hosts else "127.0.0.1")
        dst = dst_list[0] if dst_list else (hosts[-1]["id"] if hosts else "127.0.0.1")

        start_ts = to_iso(stage.get("first_seen", mock_data.get("start")))
        end_ts = to_iso(stage.get("last_seen", mock_data.get("end"))) or start_ts

        fid = stage.get("first_flow_id") or f"flw_{inc_id.lower()}_{idx:04d}"
        pcap_hash = hashlib.sha256(f"pcap_{inc_id}_{fid}".encode()).hexdigest()

        port = ""
        if "smb" in attack_cls.lower():
            port = "445"
        elif "c2" in attack_cls.lower() or "https" in attack_cls.lower():
            port = "443"
        elif "ssh" in attack_cls.lower():
            port = "22"
        elif "ftp" in attack_cls.lower():
            port = "21"

        summary = f"{attack_cls} ({stage.get('alert_count', 0)} alerts)"

        matches = mock_data.get("attack_matches", {}).get(attack_cls, [])
        explanation = [
            {"feature": f"ATT&CK match: {m.get('name', m.get('id'))}", "weight": float(m.get("score", 0.8))}
            for m in matches[:3]
        ] or [
            {"feature": f"{attack_cls} signature match", "weight": 0.88}
        ]

        stages.append({
            "stage_id": f"{inc_id}-stage-{idx}",
            "order": idx,
            "tactic": tactic,
            "tactic_id": tactic_id,
            "src": src,
            "dst": dst,
            "port": port,
            "start": start_ts,
            "end": end_ts,
            "confidence": 0.90,
            "observed": True,
            "behavior": attack_cls,
            "summary": summary,
            "evidence": [{
                "flow_id": fid,
                "ts": start_ts,
                "pcap_sha256": pcap_hash,
            }],
            "explanation": explanation,
        })

    return {
        "incident_id": inc_id,
        "score": float(mock_data.get("severity_score", 0.0)),
        "start": to_iso(mock_data.get("start")),
        "end": to_iso(mock_data.get("end")),
        "status": "Open",
        "hosts": hosts,
        "stages": stages,
        "background": [],
        "attack_classes": [s.get("attack_class") for s in timeline],
        "total_alerts": mock_data.get("alert_count", 0),
    }


def _update_investigation_job(job_id: str, **updates) -> None:
    with _job_lock:
        job = _investigation_jobs.get(job_id)
        if job is not None:
            job.update(updates)


def _group_fallback_stages(stages: list[dict]) -> list[dict]:
    """Group sequential/compatible incident stages by (src, dst, behavior, tactic).

    Generates a concise statement per legitimate group while preserving
    the relevant stage IDs and all corresponding valid evidence flow IDs.
    """
    if not stages:
        return []

    groups = []
    group_map: dict[tuple, dict] = {}

    for stage in stages:
        src = stage.get("src")
        dst = stage.get("dst")
        behavior = stage.get("behavior") or stage.get("summary") or "Unknown"
        tactic = stage.get("tactic") or "Unknown"
        key = (src, dst, behavior, tactic)

        if key not in group_map:
            group_entry = {
                "src": src,
                "dst": dst,
                "behavior": behavior,
                "tactic": tactic,
                "summary": stage.get("summary"),
                "stage_id": stage.get("stage_id"),
                "stage_ids": [],
                "evidence_ids": [],
            }
            group_map[key] = group_entry
            groups.append(group_entry)

        entry = group_map[key]
        sid = stage.get("stage_id")
        if sid and sid not in entry["stage_ids"]:
            entry["stage_ids"].append(sid)

        for item in stage.get("evidence", []):
            fid = item.get("flow_id")
            if fid and fid not in entry["evidence_ids"]:
                entry["evidence_ids"].append(fid)

    sentences = []
    for g in groups:
        count = len(g["evidence_ids"])
        b = g["behavior"] if g["behavior"] != "Unknown" else "Suspicious"
        s = g["src"]
        d = g["dst"]
        if count > 1:
            text = f"Observed {count} flows of {b} activity from {s} to {d}."
        else:
            text = f"{g['summary'] or (b + ' activity')} from {s} to {d}."
        sentences.append({
            "text": text,
            "stage_id": g["stage_id"],
            "stage_ids": g["stage_ids"],
            "evidence_ids": g["evidence_ids"],
        })
    return sentences


def _validate_fallback_citations(sentences: list[dict], incident: dict, normalized: dict, flow_store) -> dict:
    incident_flow_ids = set(incident.get("evidence_flow_ids", []))
    incident_flow_ids.update(
        alert.get("flow_id")
        for alert in incident.get("alerts", [])
        if alert.get("flow_id")
    )
    stages = {stage["stage_id"]: stage for stage in normalized.get("stages", [])}
    valid = 0
    for sentence in sentences:
        stage_ids = sentence.get("stage_ids") or ([sentence["stage_id"]] if sentence.get("stage_id") else [])
        citations = set(sentence.get("evidence_ids", []))
        stage_flow_ids = {
            evidence.get("flow_id")
            for sid in stage_ids
            for evidence in (stages.get(sid) or {}).get("evidence", [])
            if evidence.get("flow_id")
        }
        if (
            stage_ids
            and citations
            and citations <= stage_flow_ids
            and citations <= incident_flow_ids
            and all(flow_store.get_flow(flow_id) is not None for flow_id in citations)
        ):
            valid += 1
    return {
        "valid": valid,
        "total": len(sentences),
        "rejected": len(sentences) - valid,
    }


def _run_investigation_job(job_id: str, input_path: Path, output_dir: Path, model_type: str) -> None:
    try:
        result = run_investigation_pipeline(
            input_path,
            output_dir,
            model_type=model_type,
            progress=lambda stage, percent: _update_investigation_job(
                job_id, status="running", stage=stage, progress=percent
            ),
        )
        case_data = json.loads(Path(result["cases_path"]).read_text(encoding="utf-8"))
        incident_ids = [inc["incident_id"] for inc in case_data.get("incidents", [])]
        reports_dir = output_dir / "reports"
        reports_dir.mkdir(parents=True, exist_ok=True)

        if incident_ids:
            _update_investigation_job(
                job_id, status="running", stage="Generating evidence-grounded reports", progress=92
            )
            agent = real_load_agent(result["flows_path"], result["cases_path"])
            for index, incident_id in enumerate(incident_ids, 1):
                agent_result = real_investigate(agent, incident_id)
                if agent_result.get("error"):
                    raise RuntimeError(
                        f"Report generation failed for {incident_id}: {agent_result['error']}"
                    )
                incident_case = next(
                    inc for inc in case_data["incidents"] if inc["incident_id"] == incident_id
                )
                sentences = []
                for finding in agent_result.get("findings", []):
                    stage_id = resolve_finding_stage(
                        finding, incident_id, agent_res=agent_result, case_incident=incident_case
                    )
                    sentences.append({
                        "text": finding["claim"],
                        "stage_id": stage_id,
                        "evidence_ids": finding.get("flow_ids", []),
                        "technique_id": finding.get("technique_id"),
                    })
                validation = None
                if not sentences:
                    normalized = normalize_incident(incident_case)
                    sentences = _group_fallback_stages(normalized["stages"])
                    fallback_validation = _validate_fallback_citations(
                        sentences, incident_case, normalized, agent.tools.store
                    )
                    rejected_count = len(agent_result.get("rejected_findings", []))
                    validation = {
                        "valid": fallback_validation["valid"],
                        "total": fallback_validation["total"] + rejected_count,
                        "rejected": fallback_validation["rejected"] + rejected_count,
                    }
                findings_count = len(agent_result.get("findings", []))
                rejected_count = len(agent_result.get("rejected_findings", []))
                if validation is None:
                    validation = {
                        "valid": findings_count,
                        "total": findings_count + rejected_count,
                        "rejected": rejected_count,
                    }
                report_payload = {
                    "report_id": f"RPT-{incident_id}",
                    "incident_id": incident_id,
                    "provenance": case_data.get("provenance", {}),
                    "sentences": sentences,
                    "validation": validation,
                    "footer": {
                        "input_sha256": result["source_sha256"],
                        "merkle_root": result.get("merkle_root"),
                        "merkle_certificate": "forensic_merkle_certificate.json",
                        "manifest_id": f"run_{job_id}",
                        "attack_version": "v15",
                    },
                    "summary": agent_result.get("summary"),
                    "summary_withheld_reason": agent_result.get("summary_withheld_reason"),
                    "reasoning_status": agent_result.get("reasoning_status", "unavailable"),
                    "reasoning_error": agent_result.get("reasoning_error"),
                    "factual_summary": agent_result.get("factual_summary"),
                    "findings": agent_result.get("findings", []),
                    "rejected_findings": agent_result.get("rejected_findings", []),
                    "host_roles": agent_result.get("host_roles", {}),
                    "attack_matches": agent_result.get("attack_matches", {}),
                    "retrieval_status": agent_result.get("retrieval_status", "unavailable"),
                    "report_markdown": agent_result.get("report_markdown", ""),
                    "investigation_job_id": job_id,
                }
                (reports_dir / f"{incident_id}.json").write_text(
                    json.dumps(report_payload, indent=2, default=str), encoding="utf-8"
                )
                report_progress = 92 + int(7 * index / len(incident_ids))
                _update_investigation_job(
                    job_id, stage=f"Generated report {index}/{len(incident_ids)}", progress=report_progress
                )

        selected_detector = result.get("selected_detector", result.get("model_type"))
        detector_label = result.get("detector_label", selected_detector)
        selection_reason = result.get("selection_reason")
        fallback_reason = result.get("fallback_reason")
        requested_detector = result.get("requested_detector", model_type)
        with _job_lock:
            if job_id in _investigation_jobs:
                _investigation_jobs[job_id]["selected_detector"] = selected_detector
                _investigation_jobs[job_id]["model_type"] = selected_detector
                _investigation_jobs[job_id]["detector_label"] = detector_label
                _investigation_jobs[job_id]["selection_reason"] = selection_reason
                _investigation_jobs[job_id]["fallback_reason"] = fallback_reason
                _investigation_jobs[job_id]["requested_detector"] = requested_detector

        _update_investigation_job(
            job_id,
            status="completed",
            stage="Investigation complete",
            progress=100,
            result={
                **result,
                "incident_ids": incident_ids,
                "report_count": len(incident_ids),
                "inference_source": "fresh",
                "selected_detector": selected_detector,
                "detector_label": detector_label,
                "selection_reason": selection_reason,
                "fallback_reason": fallback_reason,
                "requested_detector": requested_detector,
            },
            error=None,
        )
    except Exception as exc:
        _update_investigation_job(
            job_id,
            status="failed",
            stage="Investigation failed",
            error=f"{type(exc).__name__}: {exc}",
            progress=100,
        )


@app.post("/investigations", status_code=202)
async def create_investigation(request: Request):
    """Stream an uploaded supported input to disk and run inference out of request thread."""
    filename = request.headers.get("x-filename", "").replace("\\", "/").rsplit("/", 1)[-1]
    suffix = Path(filename).suffix.lower()
    if suffix not in {".csv", ".parquet", ".pcap", ".pcapng"}:
        raise HTTPException(
            status_code=415,
            detail="Unsupported input format. Upload a flow CSV, flow Parquet, PCAP, or PCAPNG file.",
        )
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > MAX_UPLOAD_BYTES:
                raise HTTPException(status_code=413, detail="Input exceeds the 2 GiB upload limit.")
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Invalid Content-Length header.") from exc
    raw_detector = request.headers.get("x-detector")
    if not raw_detector or raw_detector.strip().lower() in {"", "undefined", "null"}:
        model_type = "auto"
    else:
        model_type = raw_detector.strip().lower()

    if model_type not in {"auto", "xgb", "gnn"}:
        raise HTTPException(status_code=422, detail="Detector must be 'auto', 'xgb', or 'gnn'.")

    job_id = uuid.uuid4().hex
    output_dir = INVESTIGATION_ROOT / job_id
    output_dir.mkdir(parents=True, exist_ok=False)
    input_path = output_dir / filename
    total_bytes = 0
    try:
        with input_path.open("xb") as destination:
            async for chunk in request.stream():
                total_bytes += len(chunk)
                if total_bytes > MAX_UPLOAD_BYTES:
                    raise HTTPException(status_code=413, detail="Input exceeds the 2 GiB upload limit.")
                destination.write(chunk)
    except Exception:
        input_path.unlink(missing_ok=True)
        raise
    if total_bytes == 0:
        input_path.unlink(missing_ok=True)
        raise HTTPException(status_code=422, detail="Uploaded input is empty.")

    job = {
        "job_id": job_id,
        "status": "queued",
        "stage": "Waiting for an investigation worker",
        "progress": 0,
        "filename": filename,
        "model_type": model_type,
        "requested_detector": model_type,
        "created_at": datetime.now().astimezone().isoformat(),
        "error": None,
    }
    with _job_lock:
        _investigation_jobs[job_id] = job
    _job_executor.submit(_run_investigation_job, job_id, input_path, output_dir, model_type)
    return dict(job)


def _get_or_restore_job(job_id: str) -> dict:
    with _job_lock:
        job = _investigation_jobs.get(job_id)
        if job is not None:
            return job
        output_dir = INVESTIGATION_ROOT / job_id
        cases_file = output_dir / "incident_cases.json"
        if cases_file.is_file():
            try:
                cases = json.loads(cases_file.read_text(encoding="utf-8"))
                prov = cases.get("provenance", {})
                job = {
                    "job_id": job_id,
                    "status": "completed",
                    "stage": "Investigation complete",
                    "progress": 100,
                    "filename": prov.get("input_filename", "flows.csv"),
                    "model_type": prov.get("selected_detector", "xgb"),
                    "requested_detector": prov.get("requested_detector", "auto"),
                    "selected_detector": prov.get("selected_detector", "xgb"),
                    "detector_label": prov.get("detector_label", "xgb"),
                    "selection_reason": prov.get("selection_reason"),
                    "fallback_reason": prov.get("fallback_reason"),
                    "result": {
                        "flows_scored": prov.get("flows_scored"),
                        "alerts": prov.get("alerts"),
                        "incident_count": len(cases.get("incidents", [])),
                        "selected_detector": prov.get("selected_detector", "xgb"),
                        "detector_label": prov.get("detector_label", "xgb"),
                        "selection_reason": prov.get("selection_reason"),
                        "fallback_reason": prov.get("fallback_reason"),
                        "requested_detector": prov.get("requested_detector", "auto"),
                    },
                }
                _investigation_jobs[job_id] = job
                return job
            except Exception:
                pass
    return None


@app.get("/investigations/{job_id}")
def get_investigation(job_id: str):
    job = _get_or_restore_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Investigation job not found.")
    return dict(job)


def _completed_job(job_id: str) -> tuple[dict, dict]:
    job = _get_or_restore_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Investigation job not found.")
    snapshot = dict(job)
    if snapshot["status"] != "completed":
        raise HTTPException(
            status_code=409,
            detail={
                "status": snapshot["status"],
                "stage": snapshot["stage"],
                "progress": snapshot["progress"],
                "error": snapshot.get("error"),
            },
        )
    output_dir = INVESTIGATION_ROOT / job_id
    cases_file = output_dir / "incident_cases.json"
    if not cases_file.is_file():
        raise HTTPException(status_code=404, detail="Investigation output is missing incident cases.")
    try:
        cases = json.loads(cases_file.read_text(encoding="utf-8"))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to parse incident cases: {exc}")
    return snapshot, cases


@app.get("/investigations/{job_id}/incidents")
def get_investigation_incidents(job_id: str):
    job, cases = _completed_job(job_id)
    incidents = []
    for item in cases.get("incidents", []):
        normalized = normalize_incident(item)
        normalized.update({
            "inference_source": "fresh",
            "source_sha256": cases.get("provenance", {}).get("input_sha256"),
            "detection_model": (job.get("result") or {}).get("selected_detector", job.get("selected_detector", job["model_type"])),
            "detector_label": (job.get("result") or {}).get("detector_label", job.get("detector_label", job["model_type"])),
            "requested_detector": (job.get("result") or {}).get("requested_detector", job.get("requested_detector")),
            "selection_reason": (job.get("result") or {}).get("selection_reason") or job.get("selection_reason") or cases.get("provenance", {}).get("selection_reason", ""),
            "fallback_reason": (job.get("result") or {}).get("fallback_reason") or job.get("fallback_reason") or cases.get("provenance", {}).get("fallback_reason"),
            "merkle_root": cases.get("merkle_root"),
            "investigation_job_id": job_id,
        })
        incidents.append(normalized)
    return incidents


@app.get("/investigations/{job_id}/incidents/{incident_id}/report")
def get_investigation_report(job_id: str, incident_id: str):
    _job, _cases = _completed_job(job_id)
    report_path = INVESTIGATION_ROOT / job_id / "reports" / f"{incident_id}.json"
    if not report_path.is_file():
        raise HTTPException(status_code=404, detail=f"No generated report for incident {incident_id}.")
    return json.loads(report_path.read_text(encoding="utf-8"))


@app.get("/investigations/{job_id}/incidents/{incident_id}/evidence/{flow_id}")
def get_investigation_evidence(job_id: str, incident_id: str, flow_id: str):
    _job, cases = _completed_job(job_id)
    incident = next(
        (item for item in cases.get("incidents", []) if item.get("incident_id") == incident_id),
        None,
    )
    if incident is None:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found.")
    if flow_id not in set(incident.get("evidence_flow_ids", [])):
        raise HTTPException(status_code=404, detail=f"Flow {flow_id} is not evidence for {incident_id}.")
    flow_path = INVESTIGATION_ROOT / job_id / "scored_flows.parquet"
    flow = FlowStore(flow_path).get_flow(flow_id)
    if flow is None:
        raise HTTPException(status_code=404, detail=f"Evidence flow {flow_id} is not available.")
    return {
        "incident_id": incident_id,
        "flow_id": flow_id,
        "evidence_id": flow.get("evidence_id"),
        "source_sha256": flow.get("source_sha256"),
        "merkle_root": cases.get("merkle_root"),
        "merkle_leaf_hash": next((
            edge.get("merkle_leaf_hash")
            for edge in incident.get("subgraph", {}).get("edges", [])
            if edge.get("edge_id") == flow_id
        ), None),
        "merkle_verified": next((
            bool(edge.get("merkle_verified"))
            for edge in incident.get("subgraph", {}).get("edges", [])
            if edge.get("edge_id") == flow_id
        ), False),
        "merkle_proof": next((
            proof
            for proof in json.loads(
                (INVESTIGATION_ROOT / job_id / "forensic_merkle_certificate.json").read_text(encoding="utf-8")
            ).get("incident_evidence_proofs", {}).get(incident_id, [])
            if proof.get("flow_id") == flow_id
        ), None) if (INVESTIGATION_ROOT / job_id / "forensic_merkle_certificate.json").is_file() else None,
        "flow": flow,
    }


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/incidents")
def get_incidents():
    if _agent_mode() == "real":
        agent = _load_real_agent()
        return [
            normalize_agent_incident(agent.tools.get_incident(row["incident_id"]))
            for row in real_list_incidents(agent)
        ]

    result = []
    known_ids = set()

    try:
        data = load_cases()
        for incident in data.get("incidents", []):
            norm = normalize_incident(incident)
            result.append(norm)
            known_ids.add(norm["incident_id"])
    except Exception:
        pass

    try:
        mock_agent = mock_load_agent()
        for row in mock_list_incidents(mock_agent):
            inc_id = row.get("incident_id")
            if inc_id and inc_id not in known_ids:
                mdata = mock_investigate(mock_agent, inc_id)
                if not mdata.get("error"):
                    norm = normalize_mock_incident(mdata)
                    result.append(norm)
                    known_ids.add(inc_id)
    except Exception:
        pass

    return result


@app.get("/incidents/{incident_id}")
def get_incident(incident_id: str):
    if _agent_mode() == "real":
        agent = _load_real_agent()
        summary = agent.tools.get_incident(incident_id)
        if "error" in summary:
            raise HTTPException(status_code=404, detail=summary["error"])
        return normalize_agent_incident(summary)

    try:
        data = load_cases()
        for incident in data.get("incidents", []):
            if incident["incident_id"] == incident_id:
                return normalize_incident(incident)
    except Exception:
        pass

    try:
        mock_agent = mock_load_agent()
        mdata = mock_investigate(mock_agent, incident_id)
        if not mdata.get("error"):
            return normalize_mock_incident(mdata)
    except Exception:
        pass

    raise HTTPException(status_code=404, detail="Incident not found")


@app.get("/incidents/{incident_id}/countermeasures")
def get_incident_countermeasures(incident_id: str):
    case_incident = None
    target_file = DATA_FILE if DATA_FILE.exists() else FALLBACK_DATA_FILE

    # 1. Check primary incident cases file
    try:
        data = load_cases()
        for inc in data.get("incidents", []):
            if inc.get("incident_id") == incident_id:
                case_incident = inc
                break
    except Exception as exc:
        logger.warning(f"Unable to read incident cases from {target_file}: {exc}")

    # 2. Check fresh investigation jobs if not in primary cases
    if not case_incident and INVESTIGATION_ROOT.exists():
        try:
            for job_dir in INVESTIGATION_ROOT.iterdir():
                if job_dir.is_dir():
                    jcases_file = job_dir / "incident_cases.json"
                    if jcases_file.is_file():
                        try:
                            jcases = json.loads(jcases_file.read_text(encoding="utf-8"))
                            for inc in jcases.get("incidents", []):
                                if inc.get("incident_id") == incident_id:
                                    case_incident = inc
                                    target_file = jcases_file
                                    break
                        except Exception:
                            pass
                if case_incident:
                    break
        except Exception as exc:
            logger.warning(f"Error inspecting investigation jobs for {incident_id}: {exc}")

    # 3. Check mock or real agent incident data if not found in stored cases
    if not case_incident:
        if _agent_mode() == "real":
            try:
                agent = _load_real_agent()
                summary = agent.tools.get_incident(incident_id)
                if not summary.get("error"):
                    norm = normalize_agent_incident(summary)
                    case_incident = {
                        "incident_id": incident_id,
                        "suspected_entry_point": norm["stages"][0]["src"] if norm.get("stages") else None,
                        "incident_score": norm.get("score", 0.8),
                        "attack_classes": norm.get("attack_classes", []),
                        "causal_provenance": {
                            "primary_attack_chain": [
                                {
                                    "source": s["src"],
                                    "target": s["dst"],
                                    "dst_port": int(s.get("port") or 80),
                                    "protocol": 6,
                                    "attack_stage": s.get("behavior", s.get("tactic", "Breach")),
                                    "flow_id": s.get("evidence", [{}])[0].get("flow_id", "") if s.get("evidence") else "",
                                }
                                for s in norm.get("stages", [])
                            ]
                        },
                        "subgraph": {
                            "nodes": [{"id": h["ip"], "in_degree": 1, "out_degree": 1} for h in norm.get("hosts", [])],
                            "edges": [
                                {
                                    "source": s["src"],
                                    "target": s["dst"],
                                    "dst_port": int(s.get("port") or 80),
                                    "protocol": 6,
                                }
                                for s in norm.get("stages", [])
                            ]
                        }
                    }
            except Exception as exc:
                logger.debug(f"Real agent lookup skipped for {incident_id}: {exc}")
        else:
            try:
                mock_agent = mock_load_agent()
                mdata = mock_investigate(mock_agent, incident_id)
                if not mdata.get("error"):
                    norm = normalize_mock_incident(mdata)
                    case_incident = {
                        "incident_id": incident_id,
                        "suspected_entry_point": norm["stages"][0]["src"] if norm.get("stages") else None,
                        "incident_score": norm.get("score", 0.8),
                        "attack_classes": norm.get("attack_classes", []),
                        "causal_provenance": {
                            "primary_attack_chain": [
                                {
                                    "source": s["src"],
                                    "target": s["dst"],
                                    "dst_port": int(s.get("port") or 80),
                                    "protocol": 6,
                                    "attack_stage": s.get("behavior", s.get("tactic", "Breach")),
                                    "flow_id": s.get("evidence", [{}])[0].get("flow_id", "") if s.get("evidence") else "",
                                }
                                for s in norm.get("stages", [])
                            ]
                        },
                        "subgraph": {
                            "nodes": [{"id": h["ip"], "in_degree": 1, "out_degree": 1} for h in norm.get("hosts", [])],
                            "edges": [
                                {
                                    "source": s["src"],
                                    "target": s["dst"],
                                    "dst_port": int(s.get("port") or 80),
                                    "protocol": 6,
                                }
                                for s in norm.get("stages", [])
                            ]
                        }
                    }
            except Exception as exc:
                logger.debug(f"Mock agent lookup skipped for {incident_id}: {exc}")

    if not case_incident:
        logger.info(f"Countermeasure request rejected: incident '{incident_id}' not found across any source")
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found")

    try:
        from src.mitigation.countermeasure_engine import CountermeasureEngine
        engine = CountermeasureEngine(target_file if target_file.exists() else None)
        plan = engine.plan_incident_countermeasures(case_incident)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Countermeasure synthesis failed: {exc}") from exc

    actions = []
    for act in plan.get("actions", []):
        rule_id = act.get("rule_id", "")
        attacker = act.get("target_attacker", "")
        victim = act.get("target_victim", "")
        port = act.get("destination_port", 0)
        proto = act.get("protocol", "TCP").lower()

        actions.append({
            **act,
            "verification_guidance": {
                "linux_iptables": f"iptables -C INPUT -s {attacker} -d {victim} -p {proto} --dport {port} -j DROP 2>/dev/null",
                "windows_powershell": f'Get-NetFirewallRule -DisplayName "EviGraph-Surgical-{rule_id}" -ErrorAction SilentlyContinue',
                "cisco_ios_acl": f"show ip access-lists 101 | include {attacker}",
            },
            "rollback_guidance": {
                "linux_iptables": f"iptables -D INPUT -s {attacker} -d {victim} -p {proto} --dport {port} -j DROP",
                "windows_powershell": f'Remove-NetFirewallRule -DisplayName "EviGraph-Surgical-{rule_id}"',
                "cisco_ios_acl": f"no access-list 101 deny {proto} host {attacker} host {victim} eq {port}",
            },
        })

    return {
        "incident_id": incident_id,
        "entry_point": plan.get("entry_point"),
        "severity_score": plan.get("severity_score"),
        "attack_classes": plan.get("attack_classes", []),
        "status": "advisory",
        "advisory_notice": "Recommendations are strictly advisory. Commands must be manually reviewed and executed by authorized SOC operators.",
        "containment_actions_count": len(actions),
        "actions": actions,
        "simulation_run": False,
    }


@app.get("/investigations/{job_id}/incidents/{incident_id}/countermeasures")
def get_investigation_countermeasures(job_id: str, incident_id: str):
    _job, cases = _completed_job(job_id)
    incident = next(
        (item for item in cases.get("incidents", []) if item.get("incident_id") == incident_id),
        None,
    )
    if incident is None:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found.")

    cases_path = INVESTIGATION_ROOT / job_id / "incident_cases.json"
    from src.mitigation.countermeasure_engine import CountermeasureEngine
    engine = CountermeasureEngine(cases_path if cases_path.is_file() else None)
    plan = engine.plan_incident_countermeasures(incident)

    actions = []
    for act in plan.get("actions", []):
        rule_id = act.get("rule_id", "")
        attacker = act.get("target_attacker", "")
        victim = act.get("target_victim", "")
        port = act.get("destination_port", 0)
        proto = act.get("protocol", "TCP").lower()

        actions.append({
            **act,
            "verification_guidance": {
                "linux_iptables": f"iptables -C INPUT -s {attacker} -d {victim} -p {proto} --dport {port} -j DROP 2>/dev/null",
                "windows_powershell": f'Get-NetFirewallRule -DisplayName "EviGraph-Surgical-{rule_id}" -ErrorAction SilentlyContinue',
                "cisco_ios_acl": f"show ip access-lists 101 | include {attacker}",
            },
            "rollback_guidance": {
                "linux_iptables": f"iptables -D INPUT -s {attacker} -d {victim} -p {proto} --dport {port} -j DROP",
                "windows_powershell": f'Remove-NetFirewallRule -DisplayName "EviGraph-Surgical-{rule_id}"',
                "cisco_ios_acl": f"no access-list 101 deny {proto} host {attacker} host {victim} eq {port}",
            },
        })

    return {
        "incident_id": incident_id,
        "entry_point": plan.get("entry_point"),
        "severity_score": plan.get("severity_score"),
        "attack_classes": plan.get("attack_classes", []),
        "status": "advisory",
        "advisory_notice": "Recommendations are strictly advisory. Commands must be manually reviewed and executed by authorized SOC operators.",
        "containment_actions_count": len(actions),
        "actions": actions,
        "simulation_run": False,
    }


def resolve_finding_stage(
    finding: dict,
    incident_id: str,
    agent_res: dict | None = None,
    case_incident: dict | None = None,
) -> str | None:
    """
    Map a finding to its corresponding stage_id based on verified backend data.
    If the source data does not identify a stage, returns None (no guessing).
    """
    if not isinstance(finding, dict):
        return None

    # 1. Direct stage specification in finding (e.g. stage_id or stage index/name)
    direct_id = finding.get("stage_id")
    if direct_id and isinstance(direct_id, str):
        return direct_id

    stage_spec = finding.get("stage")
    if stage_spec is not None:
        if isinstance(stage_spec, int) or (isinstance(stage_spec, str) and stage_spec.isdigit()):
            return f"{incident_id}-stage-{stage_spec}"
        if isinstance(stage_spec, str) and f"{incident_id}-stage-" in stage_spec:
            return stage_spec

    f_flows = set(finding.get("flow_ids") or [])
    f_tech = finding.get("technique_id")
    ordered_f_flows = [fid for fid in (finding.get("flow_ids") or []) if fid]

    # 2. Check agent_res timeline and attack_matches
    if agent_res:
        timeline = agent_res.get("timeline") or []
        attack_matches = agent_res.get("attack_matches") or {}

        best_stage_id = None
        best_score = 0

        for idx, stg in enumerate(timeline, 1):
            stg_id = f"{incident_id}-stage-{idx}"
            attack_cls = stg.get("attack_class", "")

            # Match by direct attack_class name if finding specified a stage name
            if stage_spec and isinstance(stage_spec, str) and stage_spec.lower() == attack_cls.lower():
                return stg_id

            # Flow IDs for this stage
            stg_flows = set()
            if stg.get("first_flow_id"):
                stg_flows.add(stg["first_flow_id"])
            if stg.get("last_flow_id"):
                stg_flows.add(stg["last_flow_id"])
            for fid in stg.get("flow_ids") or []:
                stg_flows.add(fid)

            # Techniques matched for this stage
            stage_results = [
                value for key, value in attack_matches.items()
                if key == attack_cls
                or (isinstance(value, dict) and value.get("attack_class") == attack_cls)
            ]
            stage_matches = [
                match
                for result in stage_results
                for match in (
                    result.get("matches", []) if isinstance(result, dict) else result
                )
                if isinstance(match, dict)
            ]
            stg_techs = {match.get("id") for match in stage_matches if match.get("id")}
            stage_technique_evidence = {
                match.get("id"): set(match.get("evidence_flow_ids", []))
                for match in stage_matches if match.get("id")
            }

            score = 0
            mapped_flows = stage_technique_evidence.get(f_tech, set())
            if f_tech and f_tech in stg_techs and (
                not mapped_flows or bool(f_flows & mapped_flows)
            ):
                score += 5

            common_flows = f_flows & stg_flows
            if common_flows:
                score += len(common_flows) * 2
                if ordered_f_flows and ordered_f_flows[0] in stg_flows:
                    score += 2

            if score > best_score:
                best_score = score
                best_stage_id = stg_id

        if best_score > 0 and best_stage_id:
            return best_stage_id

    # 3. Check case_incident attack chain and edges
    if case_incident:
        chain = get_chain(case_incident)
        best_stage_id = None
        best_score = 0

        for step in chain:
            step_num = step.get("step")
            if step_num is None:
                continue
            stg_id = f"{incident_id}-stage-{step_num}"
            step_fid = step.get("flow_id")
            step_stage = (step.get("attack_stage") or "").lower()
            step_pred = (step.get("predicted_class") or "").lower()

            if stage_spec and isinstance(stage_spec, str):
                s_lower = stage_spec.lower()
                if s_lower == step_stage or s_lower == step_pred:
                    return stg_id

            score = 0
            if step_fid and step_fid in f_flows:
                score += 3
                if ordered_f_flows and ordered_f_flows[0] == step_fid:
                    score += 2

            if score > best_score:
                best_score = score
                best_stage_id = stg_id

        if best_score > 0 and best_stage_id:
            return best_stage_id

    # 4. If no verifiable mapping was found in source data, do not guess
    return None


@app.api_route("/incidents/{incident_id}/report", methods=["GET", "POST"])
@app.api_route("/incidents/{incident_id}/investigate", methods=["GET", "POST"])
def get_report(incident_id: str):
    agent_res = None
    if _agent_mode() == "real":
        agent_res = real_investigate(_load_real_agent(), incident_id)
        if agent_res.get("error"):
            raise HTTPException(status_code=404, detail=agent_res["error"])
    else:
        try:
            mock_agent = mock_load_agent()
            mdata = mock_investigate(mock_agent, incident_id)
            if not mdata.get("error"):
                agent_res = mdata
        except Exception:
            pass

    case_incident = None
    merkle_root = ""
    evidence_file = "evd_cicids_sample"
    try:
        data = load_cases()
        merkle_root = data.get("merkle_root", "")
        for inc in data.get("incidents", []):
            if inc["incident_id"] == incident_id:
                case_incident = inc
                evidence_file = (inc.get("evidence_files") or [evidence_file])[0]
                break
    except Exception:
        pass

    if not agent_res and not case_incident:
        raise HTTPException(status_code=404, detail="Incident not found")


    sentences = []
    if agent_res and agent_res.get("findings"):
        for f in agent_res["findings"]:
            tech = f" ({f['technique_id']})" if f.get("technique_id") else ""
            stg_id = resolve_finding_stage(
                f, incident_id, agent_res=agent_res, case_incident=case_incident
            )
            sentences.append({
                "text": f"{f['claim']}{tech}",
                "stage_id": stg_id,
                "evidence_ids": f.get("flow_ids", []),
            })
    elif case_incident:
        norm = normalize_incident(case_incident)
        for s in norm.get("stages", []):
            sentences.append({
                "text": f"{s.get('summary', s['tactic'])} detected from {s['src']} to {s['dst']}.",
                "stage_id": s["stage_id"],
                "evidence_ids": [e["flow_id"] for e in s.get("evidence", [])],
            })
    elif agent_res and agent_res.get("timeline"):
        norm = normalize_mock_incident(agent_res)
        for s in norm.get("stages", []):
            sentences.append({
                "text": f"{s.get('summary', s['tactic'])} detected from {s['src']} to {s['dst']}.",
                "stage_id": s["stage_id"],
                "evidence_ids": [e["flow_id"] for e in s.get("evidence", [])],
            })

    total_claims = len(sentences)
    valid_claims = total_claims
    if agent_res:
        findings_count = len(agent_res.get("findings", []))
        rejected_count = len(agent_res.get("rejected_findings", []))
        if findings_count + rejected_count > 0:
            valid_claims = findings_count
            total_claims = findings_count + rejected_count

    input_hash = (
        merkle_root
        or evidence_file
        or hashlib.sha256(incident_id.encode()).hexdigest()
    )

    report_payload = {
        "report_id": f"RPT-{incident_id}",
        "incident_id": incident_id,
        "sentences": sentences,
        "validation": {
            "valid": valid_claims,
            "total": total_claims,
        },
        "footer": {
            "input_sha256": input_hash,
            "manifest_id": f"run_{incident_id.lower().replace('-', '')}",
            "attack_version": "v15",
        },
    }

    if agent_res:
        report_payload.update({
            "summary": agent_res.get("summary"),
            "summary_withheld_reason": agent_res.get("summary_withheld_reason"),
            "reasoning_status": agent_res.get("reasoning_status", "available"),
            "reasoning_error": agent_res.get("reasoning_error"),
            "factual_summary": agent_res.get("factual_summary"),
            "findings": agent_res.get("findings", []),
            "rejected_findings": agent_res.get("rejected_findings", []),
            "host_roles": agent_res.get("host_roles", {}),
            "attack_matches": agent_res.get("attack_matches", {}),
            "retrieval_status": agent_res.get("retrieval_status", "demo"),
            "report_markdown": agent_res.get("report_markdown", ""),
        })

    return report_payload
