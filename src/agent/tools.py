"""The functions the LLM agent may call. Small answers only; every flow_id returned is recorded."""
import pandas as pd

from src.agent.attack_rag import AttackKnowledgeUnavailableError
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
        self.technique_evidence: dict[str, set[str]] = {}

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
            selected = [group[0], group[-1]]
            selected.extend(sorted(group, key=lambda a: -a.risk_score)[:2])
            evidence = []
            seen_flow_ids = set()
            for alert in selected:
                if alert.flow_id in seen_flow_ids:
                    continue
                seen_flow_ids.add(alert.flow_id)
                flow = self.store.get_flow(alert.flow_id) if self.store is not None else {}
                flow = flow or {}
                row = {
                    "flow_id": alert.flow_id,
                    "timestamp": alert.timestamp.isoformat(),
                    "src_ip": alert.src_ip,
                    "dst_ip": alert.dst_ip,
                    "src_port": alert.src_port,
                    "dst_port": alert.dst_port,
                    "protocol": alert.protocol,
                    "predicted_class": alert.predicted_class,
                    "risk_score": alert.risk_score,
                }
                for key in (
                    "evidence_id", "flow_duration", "tot_fwd_pkts", "tot_bwd_pkts",
                    "totlen_fwd_pkts", "totlen_bwd_pkts", "flow_iat_mean",
                    "syn_flag_cnt", "rst_flag_cnt",
                ):
                    value = flow.get(key)
                    if value is not None:
                        row[key] = value
                evidence.append(row)
            timeline[-1]["evidence"] = evidence
            timeline[-1]["flow_ids"] = [row["flow_id"] for row in evidence]
            self._note(*timeline[-1]["flow_ids"])
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

    def search_attack_knowledge(
        self,
        query: str,
        attack_class: str = "",
        flow_ids: list[str] | None = None,
        incident_id: str = "",
    ) -> dict:
        """Find ATT&CK candidates and record which incident evidence supports the inference.

        Args:
            query: Incident and flow context describing observed network behaviour.
            attack_class: Detector stage label being investigated.
            flow_ids: Incident flow IDs that ground this stage-level search.
            incident_id: Incident whose evidence is being mapped.
        """
        requested_ids = set(flow_ids or [])
        matching_alerts = []
        incident = self.incidents.get(incident_id)
        if incident is not None and attack_class and requested_ids:
            matching_alerts = [
                alert for alert in incident.alerts
                if alert.predicted_class == attack_class and alert.flow_id in requested_ids
            ]
        evidence_ids = {alert.flow_id for alert in matching_alerts}
        evidence_basis = []
        if attack_class and requested_ids and evidence_ids:
            for alert in matching_alerts:
                flow = self.store.get_flow(alert.flow_id) or {}
                protocol = flow.get("protocol", alert.protocol)
                destination_port = flow.get("dst_port", alert.dst_port)
                detail = (
                    f"{alert.flow_id}: detector stage {alert.predicted_class}; "
                    f"protocol {protocol}, destination port {destination_port}"
                )
                if flow.get("evidence_id"):
                    detail += f", evidence file {flow['evidence_id']}"
                evidence_basis.append(detail)

        try:
            kb_status = getattr(self.kb, "status", "available")
            if kb_status != "available":
                matches = []
                retrieval_status = "unavailable"
                retrieval_error = getattr(
                    self.kb, "error", "ATT&CK retrieval index is unavailable."
                )
            else:
                matches = self.kb.search(query, 5)
                retrieval_status = "available" if matches else "no_matches"
                retrieval_error = None
        except AttackKnowledgeUnavailableError as exc:
            matches = []
            retrieval_status = "unavailable"
            retrieval_error = str(exc)

        candidate_matches = []
        evidence_rows_by_flow = {
            flow_id: self.store.get_flow(flow_id) or {}
            for flow_id in evidence_ids
        }
        available_event_ids = {
            str(row["evidence_id"])
            for row in evidence_rows_by_flow.values()
            if row.get("evidence_id")
        }
        for match in matches:
            score_semantics = match.get("score_semantics")
            raw_evidence = match.get("candidate_evidence")
            raw_evidence = raw_evidence if isinstance(raw_evidence, dict) else {}
            raw_flow_ids = raw_evidence.get("flow_ids")
            raw_flow_ids = raw_flow_ids if isinstance(raw_flow_ids, (list, tuple, set)) else []
            raw_event_ids = raw_evidence.get("event_ids")
            raw_event_ids = raw_event_ids if isinstance(raw_event_ids, (list, tuple, set)) else []
            candidate_flow_ids = sorted(
                {str(flow_id) for flow_id in raw_flow_ids}
                & evidence_ids
            )
            candidate_event_ids = sorted(
                {str(event_id) for event_id in raw_event_ids}
                & available_event_ids
            )
            is_evidence_linked = bool(candidate_flow_ids or candidate_event_ids)
            candidate_evidence = {
                "status": "candidate_specific" if is_evidence_linked else "none_available",
                "flow_ids": candidate_flow_ids,
                "event_ids": candidate_event_ids,
                "reason": (
                    str(raw_evidence["reason"])
                    if is_evidence_linked and raw_evidence.get("reason") else None
                ),
            }
            item = {
                **{key: value for key, value in match.items() if key != "score"},
                "source_url": match.get("source_url") or match.get("url"),
                "retrieval_similarity": (
                    match.get("retrieval_similarity", match.get("score"))
                    if score_semantics == "cosine_similarity" else None
                ),
                "score_semantics": score_semantics,
                "retrieval_reason": match.get("retrieval_reason") or (
                    "Ranked by cosine similarity between the stage investigation query "
                    "and the ATT&CK technique text."
                ),
                "candidate_evidence": candidate_evidence,
                "candidate_status": "evidence_linked_candidate" if is_evidence_linked else "retrieved_candidate",
                "review_status": "not_reviewed",
                "assessment": (
                    candidate_evidence["reason"] or "Candidate-specific evidence references were returned; analyst review is required."
                    if is_evidence_linked else
                    "No technique-specific evidence available. This candidate requires analyst review."
                ),
            }
            candidate_matches.append(item)
            self.techniques_seen.add(item["id"])
            if is_evidence_linked:
                self.technique_evidence.setdefault(item["id"], set()).update(candidate_flow_ids)

        return {
            "status": retrieval_status,
            "mapping_status": "retrieved_candidate" if candidate_matches else "unsupported",
            "retrieval_status": retrieval_status,
            "error": retrieval_error,
            "incident_id": incident_id or None,
            "attack_class": attack_class or None,
            "query_context_flow_ids": sorted(evidence_ids),
            "query_context_basis": evidence_basis,
            "matches": candidate_matches,
            "note": (
                "ATT&CK retrieval results are candidates, not confirmed activity. "
                "Stage query context is not technique-specific evidence."
            ),
        }
