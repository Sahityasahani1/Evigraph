"""The data format the LLM agent expects from Member 2's detection engine.

PROPOSED contract: if Member 2's real output differs, change THIS file
(and the sample generator), not the rest of the agent.
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
    predicted_class: str  # e.g. "SSH-Patator", "PortScan"
    risk_score: float = Field(ge=0, le=1)


class Incident(BaseModel):
    incident_id: str
    severity_score: float = Field(ge=0, le=1)
    hosts: list[str]
    alerts: list[Alert] = Field(min_length=1)


class IncidentCases(BaseModel):
    incidents: list[Incident]


# Flow table columns (from the team's architecture document)
FLOW_COLUMNS = [
    "flow_id", "evidence_id", "timestamp", "src_ip", "dst_ip", "src_port", "dst_port",
    "protocol", "flow_duration", "tot_fwd_pkts", "tot_bwd_pkts", "tot_len_fwd_pkts",
    "tot_len_bwd_pkts", "flow_iat_mean", "syn_flag_cnt", "rst_flag_cnt", "label",
]


def load_incidents(path: str | Path) -> IncidentCases:
    return IncidentCases.model_validate_json(Path(path).read_text(encoding="utf-8"))