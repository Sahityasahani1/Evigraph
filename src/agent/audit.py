"""Run metadata and an append-only audit log of every tool call."""
import hashlib
import json
import os
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

SEED = 0
NUM_CTX = 8192
DEFAULT_LOG = Path("reports/agent_audit.jsonl")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@lru_cache(maxsize=None)
def model_digest(name: str) -> str:
    """The digest Ollama reports for this model, or 'unknown' if Ollama can't be asked."""
    try:
        import ollama

        listing = ollama.list()
        models = listing["models"] if isinstance(listing, dict) else listing.models
        for m in models:
            m_name = m.get("model") or m.get("name")
            if m_name in (name, f"{name}:latest"):
                return m.get("digest") or "unknown"
    except Exception:
        pass
    return "unknown"


def run_info(model: str) -> dict:
    return {"model": model, "model_digest": model_digest(model), "temperature": 0,
            "seed": SEED, "num_ctx": NUM_CTX, "time_utc": _now()}


def audit_target(audit_path=None):
    """Where to write the log, or None to skip. Skipped while pytest runs unless a path is given."""
    if audit_path:
        return Path(audit_path)
    if os.environ.get("EVIGRAPH_AUDIT_LOG") == "off" or "PYTEST_CURRENT_TEST" in os.environ:
        return None
    return Path(os.environ.get("EVIGRAPH_AUDIT_LOG") or DEFAULT_LOG)


def _append(path: Path, record: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, default=str) + "\n")


def log_run(path, incident_id: str, info: dict, calls: list, accepted: int, rejected: int) -> None:
    """Append one line per tool call (with a hash of the call) and one closing line for the report."""
    if path is None:
        return
    for step, call in enumerate(calls, 1):
        body = json.dumps(call, sort_keys=True, default=str)
        _append(path, {"time_utc": _now(), "incident_id": incident_id, "model": info["model"],
                       "step": step, "call": call,
                       "sha256": hashlib.sha256(body.encode("utf-8")).hexdigest()})
    _append(path, {"time_utc": _now(), "incident_id": incident_id, "event": "report_generated",
                   "model": info["model"], "model_digest": info["model_digest"],
                   "accepted": accepted, "rejected": rejected})