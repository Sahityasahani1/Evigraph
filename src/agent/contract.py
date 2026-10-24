"""The data format the LLM agent expects from Member 2's detection engine.

If Member 2's output format changes, change THIS file (and the sample generators), not the rest of the agent.
"""
from datetime import datetime
from pathlib import Path

from pydantic import BaseModel, Field


class Alert(BaseModel):
    alert_id: str
    flow_id: str  # unique ID of the network flow; this is what the agent cites as evidence
    timestamp: datetime
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int  # 6 = TCP, 17 = UDP
    predicted_class: str  # e.g. "C2-Heartbeat", "SYN-Flood"
    risk_score: float = Field(ge=0, le=1)
    evidence_id: str | None = None


class Incident(BaseModel):
    incident_id: str
    severity_score: float = Field(ge=0, le=1)
    hosts: list[str]
    alerts: list[Alert] = Field(min_length=1)


class IncidentCases(BaseModel):
    incidents: list[Incident]


# Flow table columns the agent relies on (the real files have 44; these are the required ones)
FLOW_COLUMNS = [
    "flow_id", "evidence_id", "timestamp", "src_ip", "dst_ip", "src_port", "dst_port",
    "protocol", "flow_duration", "tot_fwd_pkts", "tot_bwd_pkts", "totlen_fwd_pkts",
    "totlen_bwd_pkts", "flow_iat_mean", "syn_flag_cnt", "rst_flag_cnt", "label",
]


def clean(cases: IncidentCases) -> IncidentCases:
    """Drop BENIGN alerts (not attacks) and make `hosts` cover every host named in the alerts."""
    kept = []
    for inc in cases.incidents:
        inc.alerts = [a for a in inc.alerts if a.predicted_class.strip().upper() != "BENIGN"]
        if not inc.alerts:
            continue
        inc.hosts = sorted(set(inc.hosts) | {a.src_ip for a in inc.alerts} | {a.dst_ip for a in inc.alerts})
        kept.append(inc)
    cases.incidents = kept
    return cases


def load_incidents(path: str | Path) -> IncidentCases:
    return clean(IncidentCases.model_validate_json(Path(path).read_text(encoding="utf-8")))