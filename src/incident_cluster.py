"""
EviGraph Alert Correlation & Incident Clustering Engine
Adheres to TRD Section 3.4 & FR-4.x:
- Builds Alert Graph connecting alerts by shared host entities & temporal proximity
- Uses Connected Components / Community Detection to cluster alerts into Incidents
- Calculates Incident Severity Score and extracts suspected entry points
- Exports structured, evidence-grounded JSON for the Agent (Member 3)
"""

import networkx as nx
import pandas as pd
import numpy as np
import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional
from src.config import ALERT_CORRELATION_WINDOW_SECS, OUTPUTS_DIR

class IncidentClusterEngine:
    def __init__(self, time_threshold_secs: int = ALERT_CORRELATION_WINDOW_SECS):
        self.time_threshold_secs = time_threshold_secs
        self.alert_graph = nx.Graph()

    def correlate_alerts(self, alerts_df: pd.DataFrame) -> List[Dict[str, Any]]:
        """
        Builds the Alert Graph and extracts incidents.
        alerts_df columns: flow_id, src_ip, dst_ip, timestamp, risk_score, predicted_class, evidence_id
        """
        if len(alerts_df) == 0:
            print("[IncidentEngine] No alerts to cluster.")
            return []

        self.alert_graph.clear()
        alerts_df = alerts_df.copy()
        alerts_df["timestamp"] = pd.to_datetime(alerts_df["timestamp"], format="mixed")
        alerts_df = alerts_df.sort_values(by="timestamp").reset_index(drop=True)

        # 1. Add Alert Nodes
        for _, row in alerts_df.iterrows():
            self.alert_graph.add_node(
                str(row["flow_id"]),
                src_ip=str(row["src_ip"]),
                dst_ip=str(row["dst_ip"]),
                timestamp=row["timestamp"],
                risk_score=float(row["risk_score"]),
                predicted_class=str(row["predicted_class"]),
                evidence_id=str(row.get("evidence_id", "raw_pcap"))
            )

        # 2. Add Correlation Edges using Inverted Host Index (TRD NFR-3 / NFR-5: High-throughput Big Data scaling)
        from collections import defaultdict
        host_to_alerts = defaultdict(list)
        for _, row in alerts_df.iterrows():
            f_id = str(row["flow_id"])
            ts = row["timestamp"]
            host_to_alerts[str(row["src_ip"])].append((f_id, ts))
            host_to_alerts[str(row["dst_ip"])].append((f_id, ts))

        for host, host_alerts in host_to_alerts.items():
            host_alerts.sort(key=lambda x: x[1])
            m = len(host_alerts)
            for i in range(m):
                f1, t1 = host_alerts[i]
                for j in range(i + 1, min(i + 30, m)):  # Temporal neighbor window
                    f2, t2 = host_alerts[j]
                    time_delta = (t2 - t1).total_seconds()
                    if time_delta > self.time_threshold_secs:
                        break
                    if f1 != f2:
                        weight = 1.0 / (1.0 + time_delta / 60.0)
                        self.alert_graph.add_edge(f1, f2, weight=weight)

        # 3. Cluster Connected Components into Incident Candidates
        incidents = []
        components = list(nx.connected_components(self.alert_graph))
        num_alerts = len(alerts_df)
        print(f"[IncidentEngine] Correlated {num_alerts} alerts into {len(components)} incident clusters")

        for inc_idx, comp_nodes in enumerate(components):
            flow_ids = list(comp_nodes)
            sub_alerts = alerts_df[alerts_df["flow_id"].isin(flow_ids)]
            
            src_hosts = set(sub_alerts["src_ip"])
            dst_hosts = set(sub_alerts["dst_ip"])
            all_hosts = list(src_hosts.union(dst_hosts))
            
            t_start = sub_alerts["timestamp"].min()
            t_end = sub_alerts["timestamp"].max()
            duration_secs = (t_end - t_start).total_seconds()
            
            max_risk = float(sub_alerts["risk_score"].max())
            mean_risk = float(sub_alerts["risk_score"].mean())
            raw_classes = [c for c in sub_alerts["predicted_class"].unique() if c != "BENIGN"]
            attack_classes = raw_classes if raw_classes else ["Suspicious-Anomaly"]
            
            # Suspected Entry Point: Source IP of the earliest alert in the incident
            earliest_alert = sub_alerts.sort_values(by="timestamp").iloc[0]
            suspected_entry_point = earliest_alert["src_ip"]
            
            # Composite Incident Score (TRD Sec 3.4)
            # Combines max risk (40%), mean risk (30%), host spread (15%), attack diversity (15%)
            host_factor = min(1.0, len(all_hosts) / 5.0)
            class_factor = min(1.0, len(attack_classes) / 3.0)
            incident_score = round(
                0.40 * max_risk + 0.30 * mean_risk + 0.15 * host_factor + 0.15 * class_factor,
                4
            )

            incident = {
                "incident_id": f"INC-{inc_idx+1:04d}",
                "incident_score": incident_score,
                "status": "candidate",
                "suspected_entry_point": suspected_entry_point,
                "start_time": t_start.isoformat(),
                "end_time": t_end.isoformat(),
                "duration_seconds": duration_secs,
                "total_alerts": len(flow_ids),
                "affected_hosts": all_hosts,
                "attack_classes": attack_classes,
                "evidence_flow_ids": flow_ids,
                "evidence_files": list(sub_alerts["evidence_id"].unique())
            }
            incidents.append(incident)

        # Sort incidents by severity score descending
        incidents.sort(key=lambda x: x["incident_score"], reverse=True)
        return incidents

    def export_agent_case_bundle(
        self, 
        incidents: List[Dict[str, Any]], 
        graph_engine, 
        output_path: Optional[Path] = None
    ) -> Path:
        """
        Exports the final JSON case package containing incidents, risk scores,
        and forensic subgraphs for Member 3 (Agent / Forensic LLM).
        """
        output_file = output_path or (OUTPUTS_DIR / "incident_cases.json")
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Enrich each incident with its extracted suspicious subgraph
        enriched_incidents = []
        for inc in incidents:
            subgraph_data = graph_engine.extract_suspicious_subgraph(inc["evidence_flow_ids"], k_hop=1)
            inc_payload = dict(inc)
            inc_payload["subgraph"] = subgraph_data
            enriched_incidents.append(inc_payload)

        case_package = {
            "version": "1.0",
            "generator": "EviGraph Member 2 (Detection & Graph Engine)",
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "total_incidents": len(enriched_incidents),
            "incidents": enriched_incidents
        }

        with open(output_file, "w") as f:
            json.dump(case_package, f, indent=2)

        print(f"[IncidentEngine] Successfully exported Agent case package to {output_file}")
        return output_file
