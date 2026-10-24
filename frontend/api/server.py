
import json
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

BASE_DIR = Path(__file__).resolve().parent.parent / "evigraph-backend"
DATA_FILE = BASE_DIR / "outputs" / "incident_cases.json"

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


def load_cases():
    if not DATA_FILE.exists():
        raise HTTPException(
            status_code=503,
            detail="Incident data not found. Run the detection pipeline first.",
        )

    with DATA_FILE.open(encoding="utf-8") as f:
        return json.load(f)


def to_iso(value):
    if not value:
        return None

    # Convert timestamps to ISO format without changing their time.
    return datetime.fromisoformat(
        value.replace("Z", "+00:00")
    ).isoformat()


def get_chain(incident):
    # INC-0002 stores its chain under causal_provenance.
    chain = incident.get("primary_attack_chain")
    if not chain:
        chain = incident.get("causal_provenance", {}).get(
            "primary_attack_chain", []
        )
    return chain


def normalize_incident(incident):
    chain = get_chain(incident)

    host_ips = incident.get("affected_hosts", [])
    hosts = []

    for ip in host_ips:
        role = next(
            (
                node.get("role")
                for node in incident.get("subgraph", {}).get("nodes", [])
                if node.get("id") == ip
            ),
            "unknown",
        )

        hosts.append({
            "id": ip,
            "ip": ip,
            "zone": None,
            "role": role,
        })

    stages = []

    for step in chain:
        timestamp = to_iso(step.get("timestamp"))

        stages.append({
            "stage_id": f"{incident['incident_id']}-stage-{step['step']}",
            "order": step["step"],
            "tactic": step.get("attack_stage", "Unknown"),
            "src": step.get("source"),
            "dst": step.get("target"),
            "start": timestamp,
            "end": timestamp,
            "confidence": step.get("risk_score"),
            "observed": True,
            "evidence": [{
                "flow_id": step.get("flow_id"),
                "ts": timestamp,
                "pcap_sha256": None,
            }],
        })

    return {
        "incident_id": incident["incident_id"],
        "score": incident.get("incident_score", 0),
        "start": to_iso(incident.get("start_time")),
        "end": to_iso(incident.get("end_time")),
        "status": incident.get("status", "Open"),
        "hosts": hosts,
        "stages": stages,
        "attack_classes": incident.get("attack_classes", []),
        "total_alerts": incident.get("total_alerts", 0),
    }


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/incidents")
def get_incidents():
    data = load_cases()
    return [
        normalize_incident(incident)
        for incident in data.get("incidents", [])
    ]


@app.get("/incidents/{incident_id}")
def get_incident(incident_id: str):
    data = load_cases()

    for incident in data.get("incidents", []):
        if incident["incident_id"] == incident_id:
            return normalize_incident(incident)

    raise HTTPException(status_code=404, detail="Incident not found")
