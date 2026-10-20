"""Mock mode: same three functions as api.py, but serves saved reports.
No Ollama and no data files needed. Use it to build the UI, then switch the import to api.py."""
import json
from pathlib import Path

DATA = Path(__file__).parent / "mock_data"


def load_agent(*args, **kwargs):
    """Accepts the same arguments as api.load_agent and ignores them."""
    return {"mock": True}


def _incident_files():
    return sorted(DATA.glob("*.json"))


def list_incidents(agent=None):
    """Same row shape as api.list_incidents, most severe first."""
    rows = []
    for path in _incident_files():
        report = json.loads(path.read_text(encoding="utf-8"))
        classes = {}
        for stage in report.get("timeline") or []:
            name = stage.get("attack_class")
            if name:
                classes[name] = classes.get(name, 0) + stage.get("alert_count", 0)
        rows.append({
            "incident_id": report.get("incident_id"),
            "severity_score": report.get("severity_score"),
            "alert_count": report.get("alert_count"),
            "host_count": report.get("host_count"),
            "classes": classes,
        })
    return sorted(rows, key=lambda r: -(r["severity_score"] or 0))


def investigate(agent, incident_id):
    path = DATA / f"{incident_id}.json"
    if not path.exists():
        known = [p.stem for p in _incident_files()]
        return {"incident_id": incident_id,
                "error": f"Unknown incident {incident_id}. The mock has: {known}"}
    return json.loads(path.read_text(encoding="utf-8"))