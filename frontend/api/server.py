import hashlib
import json
from datetime import datetime
from ipaddress import ip_address, ip_network
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from src.agent.mock import (
    investigate as mock_investigate,
    list_incidents as mock_list_incidents,
    load_agent as mock_load_agent,
)

BASE_DIR = Path(__file__).resolve().parent.parent / "evigraph-backend"
DATA_FILE = BASE_DIR / "outputs" / "incident_cases.json"
FALLBACK_DATA_FILE = Path(__file__).resolve().parent.parent.parent / "outputs" / "incident_cases.json"

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

        # Cryptographic leaf digest from verified Merkle evidence tree / flow record
        pcap_sha256 = edge.get("merkle_leaf_hash") or edge.get("pcap_sha256") or edge.get("sha256")

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
            "behavior": pred_class,
            "summary": summary,
            "evidence": [{
                "flow_id": fid,
                "ts": timestamp,
                "pcap_sha256": pcap_sha256,
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


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/incidents")
def get_incidents():
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
            stg_techs = {
                m.get("id")
                for m in attack_matches.get(attack_cls, [])
                if isinstance(m, dict) and m.get("id")
            }

            score = 0
            if f_tech and f_tech in stg_techs:
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
            "factual_summary": agent_res.get("factual_summary"),
            "findings": agent_res.get("findings", []),
            "rejected_findings": agent_res.get("rejected_findings", []),
            "host_roles": agent_res.get("host_roles", {}),
            "attack_matches": agent_res.get("attack_matches", {}),
            "report_markdown": agent_res.get("report_markdown", ""),
        })

    return report_payload
