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
    rows = []
    for path in _incident_files():
        report = json.loads(path.read_text(encoding="utf-8"))
        rows.append({k: report.get(k) for k in
                     ("incident_id", "severity_score", "start", "end", "alert_count", "host_count")})
    return rows


def investigate(agent, incident_id):
    path = DATA / f"{incident_id}.json"
    if not path.exists():
        known = [p.stem for p in _incident_files()]
        return {"incident_id": incident_id,
                "error": f"Unknown incident {incident_id}. The mock has: {known}"}
    return json.loads(path.read_text(encoding="utf-8"))