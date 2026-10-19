import json
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


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/incidents")
def get_incidents():
    data = load_cases()

    return [
        {
            "incident_id": incident["incident_id"],
            "score": incident.get("incident_score", 0),
            "start": incident.get("start_time"),
            "end": incident.get("end_time"),
            "status": incident.get("status", "Open"),
            "hosts": incident.get("affected_hosts", []),
            "attack_classes": incident.get("attack_classes", []),
            "total_alerts": incident.get("total_alerts", 0),
        }
        for incident in data.get("incidents", [])
    ]


@app.get("/incidents/{incident_id}")
def get_incident(incident_id: str):
    data = load_cases()

    for incident in data.get("incidents", []):
        if incident["incident_id"] == incident_id:
            return incident

    raise HTTPException(status_code=404, detail="Incident not found")