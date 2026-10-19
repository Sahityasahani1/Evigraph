"""The functions the LLM agent may call. Small answers only; every flow_id returned is recorded."""
import pandas as pd

from src.agent.contract import IncidentCases
from src.agent.flow_store import FlowStore

MAX_FLOWS = 25


def _pattern(stage_roles: list[dict]) -> str:
    """Label how a host's role changed across stages (computed by code, not by the model)."""
    seen_target = seen_source = False
    target_then_source = source_then_target = False
    for r in stage_roles:
        is_source, is_target = "source" in r["role"], "target" in r["role"]
        if is_source and seen_target:
            target_then_source = True
        if is_target and seen_source:
            source_then_target = True
        seen_target |= is_target
        seen_source |= is_source
    if target_then_source:
        return "target_then_source"
    if source_then_target:
        return "source_then_target"
    if all(r["role"] == "source" for r in stage_roles):
        return "source_in_every_stage"
    if all(r["role"] == "target" for r in stage_roles):
        return "target_in_every_stage"
    return "mixed"


_PATTERN_PRIORITY = {"target_then_source": 0, "source_then_target": 1}


class ForensicTools:
    def __init__(self, store: FlowStore, cases: IncidentCases, kb):
        self.store = store
        self.incidents = {i.incident_id: i for i in cases.incidents}
        self.kb = kb
        self.evidence: set[str] = set()  # every flow_id the agent has been shown
        self.techniques_seen: set[str] = set()  # every ATT&CK ID the agent has been shown

    def _note(self, *flow_ids):
        self.evidence.update(flow_ids)

    def list_incidents(self) -> dict:
        """List all detected incidents with their severity and attack classes."""
        rows = []
        for i in self.incidents.values():
            classes: dict[str, int] = {}
            for a in i.alerts:
                classes[a.predicted_class] = classes.get(a.predicted_class, 0) + 1
            rows.append({
                "incident_id": i.incident_id, "severity_score": i.severity_score,
                "alert_count": len(i.alerts), "host_count": len(i.hosts), "classes": classes,
            })
        return {"incidents": rows}

    def get_incident(self, incident_id: str) -> dict:
        """Get a summary of one incident: time span, hosts, attack stages in time order, top alerts.

        Args:
            incident_id: The incident identifier, for example INC-001
        """
        inc = self.incidents.get(incident_id)
        if inc is None:
            return {"error": f"Unknown incident_id {incident_id!r}", "known": list(self.incidents)}
        alerts = sorted(inc.alerts, key=lambda a: a.timestamp)
        stages: dict[str, list] = {}
        for a in alerts:
            stages.setdefault(a.predicted_class, []).append(a)

        def count_by(group, attr):
            counts: dict[str, int] = {}
            for a in group:
                key = getattr(a, attr)
                counts[key] = counts.get(key, 0) + 1
            return counts

        def ranked(counts, n=5):
            return sorted(counts, key=lambda h: (-counts[h], h))[:n]

        ordered = sorted(stages.items(), key=lambda kv: kv[1][0].timestamp)
        timeline = []
        roles: dict[str, list] = {}
        for cls, group in ordered:
            src_c, dst_c = count_by(group, "src_ip"), count_by(group, "dst_ip")
            timeline.append({
                "attack_class": cls, "alert_count": len(group),
                "first_seen": group[0].timestamp.isoformat(),
                "last_seen": group[-1].timestamp.isoformat(),
                "sources": ranked(src_c), "distinct_sources": len(src_c),
                "targets": ranked(dst_c), "distinct_targets": len(dst_c),
                "first_flow_id": group[0].flow_id, "last_flow_id": group[-1].flow_id,
            })
            self._note(group[0].flow_id, group[-1].flow_id)
            for host in set(src_c) | set(dst_c):
                role = ("source and target" if host in src_c and host in dst_c
                        else "source" if host in src_c else "target")
                roles.setdefault(host, []).append(
                    {"stage": cls, "role": role, "alerts": src_c.get(host, 0) + dst_c.get(host, 0)})

        multi = [h for h, r in roles.items() if len(r) >= 2]
        patterns = {h: _pattern(roles[h]) for h in multi}
        multi.sort(key=lambda h: (_PATTERN_PRIORITY.get(patterns[h], 2), -len(roles[h]),
                                  -sum(x["alerts"] for x in roles[h]), h))
        cross_stage_hosts = [
            {"host_ip": h, "pattern": patterns[h], "stages": roles[h]} for h in multi[:10]
        ]

        src_counts = count_by(inc.alerts, "src_ip")
        dst_counts = count_by(inc.alerts, "dst_ip")

        def top_hosts(counts):
            return [{"host_ip": h, "alerts": counts[h]} for h in ranked(counts)]
        top = sorted(inc.alerts, key=lambda a: -a.risk_score)[:5]
        self._note(*[a.flow_id for a in top])
        return {
            "incident_id": inc.incident_id, "severity_score": inc.severity_score,
            "start": alerts[0].timestamp.isoformat(), "end": alerts[-1].timestamp.isoformat(),
            "alert_count": len(alerts),
            "host_count": len(inc.hosts),
            "top_alert_sources": top_hosts(src_counts),
            "top_alert_targets": top_hosts(dst_counts),
            "stages_in_time_order": timeline,
            "cross_stage_hosts": cross_stage_hosts,
            "top_alerts_by_risk": [
                {"alert_id": a.alert_id, "flow_id": a.flow_id, "timestamp": a.timestamp.isoformat(),
                 "src_ip": a.src_ip, "dst_ip": a.dst_ip, "dst_port": a.dst_port,
                 "attack_class": a.predicted_class, "risk_score": a.risk_score}
                for a in top
            ],
        }

    def host_summary(self, host_ip: str) -> dict:
        """Summarise all network activity of one host: flow counts, ports, bytes, first/last seen.

        Args:
            host_ip: The IP address of the host, for example 10.0.0.5
        """
        s = self.store.host_summary(host_ip)
        return s if s else {"error": f"No flows found for host {host_ip!r}"}

    def get_flows(self, host_ip: str, start_time: str = "", end_time: str = "", limit: int = 10) -> dict:
        """Get individual flow records involving a host, oldest first, optionally within a time window.

        Args:
            host_ip: The IP address of the host, for example 10.0.0.5
            start_time: Optional start of the window, ISO format, for example 2026-01-10T09:20:00
            end_time: Optional end of the window, ISO format
            limit: Maximum number of flows to return (at most 25)
        """
        try:
            start = pd.Timestamp(start_time) if start_time else None
            end = pd.Timestamp(end_time) if end_time else None
        except ValueError:
            return {"error": "start_time and end_time must be ISO timestamps"}
        limit = max(1, min(int(limit), MAX_FLOWS))
        total, rows = self.store.flows_for_host(host_ip, start, end, limit)
        self._note(*[r["flow_id"] for r in rows])
        return {"host_ip": host_ip, "total_matching": total, "returned": len(rows), "flows": rows}

    def search_attack_knowledge(self, query: str) -> dict:
        """Find MITRE ATT&CK techniques matching a description of observed behaviour.

        Args:
            query: Plain-language description, for example many failed SSH logins from one IP
        """
        matches = self.kb.search(query, 5)
        self.techniques_seen.update(m["id"] for m in matches)
        return {"matches": matches,
                "note": "Only cite technique IDs that appear in this list."}