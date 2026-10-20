"""
EviGraph Temporal Causal Provenance DAG & Attack Stage FSM Engine (Core USP)
Adheres to Lamport Causality and MITRE ATT&CK Tactical Progression:
- Transforms flat alert clusters into a Directed Acyclic Graph (DAG) of causal transitions
- Evaluates temporal precedence and network propagation dwell times (t_in < t_out)
- Maps attack behaviors across a 6-stage MITRE ATT&CK progression FSM
- Prunes coincidental background noise and extracts the primary attack campaign path
"""

import networkx as nx
import pandas as pd
import numpy as np
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, Set

# MITRE ATT&CK Tactical Stages & Canonical Class Mapping
STAGE_RANKS = {
    "Reconnaissance": 1,
    "Initial Access": 2,
    "Credential Access": 3,
    "Lateral Movement": 4,
    "Command and Control": 5,
    "Exfiltration & Impact": 6
}

ATTACK_CLASS_TO_STAGE = {
    # Stage 1: Reconnaissance / Discovery
    "PortScan": "Reconnaissance",
    "Infiltration-PortScanning": "Reconnaissance",
    "Reconnaissance": "Reconnaissance",

    # Stage 2: Initial Access / Exploitation
    "Exploits": "Initial Access",
    "Web Attack - Brute Force": "Initial Access",
    "Web Attack - XSS": "Initial Access",
    "Web Attack - Sql Injection": "Initial Access",
    "remoteCE": "Initial Access",

    # Stage 3: Credential Access
    "SSH-Patator": "Credential Access",
    "FTP-Patator": "Credential Access",
    "Backdoor": "Credential Access",

    # Stage 4: Lateral Movement
    "Lateral-SMB-Relay": "Lateral Movement",
    "Infiltration": "Lateral Movement",
    "Fuzzers": "Lateral Movement",

    # Stage 5: Command and Control
    "C2-Heartbeat": "Command and Control",
    "Bot": "Command and Control",

    # Stage 6: Exfiltration & Impact
    "HTTPS-Exfiltration": "Exfiltration & Impact",
    "DoS-Slowloris": "Exfiltration & Impact",
    "DoS Hulk": "Exfiltration & Impact",
    "DoS GoldenEye": "Exfiltration & Impact",
    "DoS Slowhttptest": "Exfiltration & Impact",
    "SYN-Flood": "Exfiltration & Impact",
    "DNS-Amplification": "Exfiltration & Impact",
    "NTP-Reflection": "Exfiltration & Impact",
    "DDoS": "Exfiltration & Impact",
    "Heartbleed": "Exfiltration & Impact"
}

class CausalProvenanceEngine:
    """
    Constructs and analyzes the Temporal Causal Provenance DAG for network incidents.
    Enforces Lamport chronological order and MITRE ATT&CK tactical progression.
    """
    def __init__(
        self,
        max_scan_window_secs: float = 300.0,
        min_dwell_time_secs: float = 0.05,
        max_dwell_time_secs: float = 600.0,
        min_causal_confidence: float = 0.40
    ):
        self.max_scan_window_secs = max_scan_window_secs
        self.min_dwell_time_secs = min_dwell_time_secs
        self.max_dwell_time_secs = max_dwell_time_secs
        self.min_causal_confidence = min_causal_confidence

    @staticmethod
    def classify_stage(attack_class: str) -> str:
        """Maps an intrusion class name to its canonical MITRE tactical stage."""
        return ATTACK_CLASS_TO_STAGE.get(attack_class, "Reconnaissance")

    def compute_fsm_score(self, stage_from: str, stage_to: str) -> float:
        """
        Calculates the tactical transition likelihood between two attack stages.
        Forward progression (e.g. Recon -> Access -> Lateral) receives highest score.
        """
        r1 = STAGE_RANKS.get(stage_from, 1)
        r2 = STAGE_RANKS.get(stage_to, 1)

        if r1 < r2:
            # Forward campaign progression
            return 1.00
        elif r1 == r2:
            # Lateral expansion within same tactical phase
            return 0.85
        elif r1 == r2 + 1:
            # Minor tactical fallback (e.g. pivoting host scans new internal subnet)
            return 0.65
        else:
            # Distant regression
            return 0.45

    def build_causal_dag(self, alert_edges: List[Dict[str, Any]]) -> nx.DiGraph:
        """
        Constructs a Directed Acyclic Graph (DAG) connecting alert flows by Lamport causality.
        Nodes are alert flow records; edges represent proven causal trigger transitions.
        """
        dag = nx.DiGraph()
        if not alert_edges:
            return dag

        # 1. Sort alert edges monotonically by timestamp
        def parse_ts(val):
            if isinstance(val, (datetime, pd.Timestamp)):
                return val.timestamp()
            try:
                return pd.to_datetime(val).timestamp()
            except Exception:
                return 0.0

        sorted_alerts = sorted(alert_edges, key=lambda e: parse_ts(e.get("timestamp", 0)))

        # 2. Add nodes to DAG
        for idx, alert in enumerate(sorted_alerts):
            fid = str(alert.get("edge_id", f"flw_{idx}"))
            attack_cls = alert.get("predicted_class", "Anomalous")
            stage = self.classify_stage(attack_cls)
            dag.add_node(
                fid,
                flow_id=fid,
                source=str(alert.get("source")),
                target=str(alert.get("target")),
                timestamp=str(alert.get("timestamp")),
                ts_epoch=parse_ts(alert.get("timestamp", 0)),
                dst_port=int(alert.get("dst_port", 0)),
                protocol=int(alert.get("protocol", 6)),
                risk_score=float(alert.get("risk_score", 0.5)),
                predicted_class=attack_cls,
                attack_stage=stage,
                stage_rank=STAGE_RANKS.get(stage, 1)
            )

        # 3. Add Causal Edges based on Temporal Precedence & Host Provenance
        # Case A: Same Attacker continuing campaign against target(s) (t1 <= t2 <= t1 + max_scan)
        # Case B: Lateral Pivot (Victim of t1 becomes Attacker of t2: t1 + min_dwell <= t2 <= t1 + max_dwell)
        n = len(sorted_alerts)
        for i in range(n):
            u_alert = sorted_alerts[i]
            u_id = str(u_alert.get("edge_id", f"flw_{i}"))
            u_src = str(u_alert.get("source"))
            u_dst = str(u_alert.get("target"))
            u_ts = parse_ts(u_alert.get("timestamp", 0))
            u_stage = self.classify_stage(u_alert.get("predicted_class", ""))

            # Lookahead window (restricted to prevent combinatorial explosion)
            for j in range(i + 1, min(i + 40, n)):
                v_alert = sorted_alerts[j]
                v_id = str(v_alert.get("edge_id", f"flw_{j}"))
                v_src = str(v_alert.get("source"))
                v_dst = str(v_alert.get("target"))
                v_ts = parse_ts(v_alert.get("timestamp", 0))
                v_stage = self.classify_stage(v_alert.get("predicted_class", ""))
                v_risk = float(v_alert.get("risk_score", 0.5))

                dt = v_ts - u_ts
                if dt < 0:
                    continue  # Strict Lamport arrow of time

                is_continuation = (u_src == v_src) and (dt <= self.max_scan_window_secs)
                is_pivot = (u_dst == v_src) and (self.min_dwell_time_secs <= dt <= self.max_dwell_time_secs)

                if is_continuation or is_pivot:
                    fsm_score = self.compute_fsm_score(u_stage, v_stage)
                    time_decay = float(np.exp(-dt / 120.0))
                    pivot_bonus = 0.15 if is_pivot else 0.0

                    causal_confidence = (0.40 * fsm_score) + (0.35 * time_decay) + (0.25 * v_risk) + pivot_bonus
                    causal_confidence = min(1.0, max(0.0, causal_confidence))

                    if causal_confidence >= self.min_causal_confidence:
                        transition_label = (
                            f"Pivot ({u_stage} -> {v_stage})" if is_pivot 
                            else f"Progress ({u_stage} -> {v_stage})"
                        )
                        dag.add_edge(
                            u_id,
                            v_id,
                            source_flow=u_id,
                            target_flow=v_id,
                            transition=transition_label,
                            is_pivot=is_pivot,
                            latency_seconds=round(dt, 3),
                            causal_confidence=round(causal_confidence, 4),
                            weight=causal_confidence
                        )

        return dag

    def extract_primary_attack_chain(self, dag: nx.DiGraph) -> List[Dict[str, Any]]:
        """
        Discovers the primary adversarial attack chain using topological dynamic programming.
        Finds the heaviest causal path through the DAG from entry points to final objective.
        """
        if dag.number_of_nodes() == 0:
            return []

        # Identify candidate entry points (in-degree 0 in causal DAG)
        entry_nodes = [n for n, deg in dag.in_degree() if deg == 0]
        if not entry_nodes:
            # Fallback to earliest timestamp node
            entry_nodes = [min(dag.nodes(), key=lambda n: dag.nodes[n].get("ts_epoch", 0))]

        # Topological dynamic programming to find longest / highest-confidence path
        # Since graph is strictly chronological (t1 < t2), it is an exact DAG
        try:
            topo_order = list(nx.topological_sort(dag))
        except nx.NetworkXUnfeasible:
            # In case of identical timestamps, break cycles if any
            topo_order = list(dag.nodes())

        dist = {n: 0.0 for n in dag.nodes()}
        pred = {n: None for n in dag.nodes()}

        for u in topo_order:
            for _, v, data in dag.out_edges(u, data=True):
                w = data.get("causal_confidence", 1.0)
                if dist[u] + w > dist[v]:
                    dist[v] = dist[u] + w
                    pred[v] = u

        # Find termination node with highest cumulative confidence
        best_end = max(dist.keys(), key=lambda n: dist[n])
        
        # Backtrack path
        path = []
        curr = best_end
        while curr is not None:
            path.append(curr)
            curr = pred[curr]
        path.reverse()

        # Format chain sequence
        chain_steps = []
        for step_idx, fid in enumerate(path, 1):
            nd = dag.nodes[fid]
            step_dict = {
                "step": step_idx,
                "flow_id": fid,
                "source": nd.get("source"),
                "target": nd.get("target"),
                "timestamp": nd.get("timestamp"),
                "dst_port": nd.get("dst_port"),
                "predicted_class": nd.get("predicted_class"),
                "attack_stage": nd.get("attack_stage"),
                "risk_score": nd.get("risk_score")
            }
            if step_idx > 1:
                prev_id = path[step_idx - 2]
                if dag.has_edge(prev_id, fid):
                    edge_data = dag[prev_id][fid]
                    step_dict["transition"] = edge_data.get("transition")
                    step_dict["latency_seconds"] = edge_data.get("latency_seconds")
                    step_dict["causal_confidence"] = edge_data.get("causal_confidence")
            chain_steps.append(step_dict)

        return chain_steps

    def analyze_incident(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        """
        Executes causal provenance analysis on an incident bundle:
        - Builds the Causal Provenance DAG
        - Computes the Primary Attack Chain
        - Identifies root-cause entry point and campaign duration
        """
        subgraph = incident.get("subgraph", {})
        edges = subgraph.get("edges", [])
        if not edges:
            return {"nodes_count": 0, "edges_count": 0, "primary_chain": []}

        dag = self.build_causal_dag(edges)
        primary_chain = self.extract_primary_attack_chain(dag)

        # Serialize DAG edges
        dag_edges_payload = []
        for u, v, d in dag.edges(data=True):
            dag_edges_payload.append({
                "source_flow": str(u),
                "target_flow": str(v),
                "transition": str(d.get("transition")),
                "latency_seconds": float(d.get("latency_seconds", 0.0)),
                "causal_confidence": float(d.get("causal_confidence", 0.0)),
                "is_pivot": bool(d.get("is_pivot", False))
            })

        # Calculate campaign duration along primary chain
        if len(primary_chain) >= 2:
            t_start = pd.to_datetime(primary_chain[0]["timestamp"]).timestamp()
            t_end = pd.to_datetime(primary_chain[-1]["timestamp"]).timestamp()
            campaign_dur = round(max(0.0, t_end - t_start), 3)
        else:
            campaign_dur = incident.get("duration_seconds", 0.0)

        root_cause = primary_chain[0]["flow_id"] if primary_chain else None

        return {
            "causal_dag_nodes_count": dag.number_of_nodes(),
            "causal_dag_edges_count": dag.number_of_edges(),
            "root_cause_entry_flow": root_cause,
            "campaign_duration_seconds": campaign_dur,
            "primary_attack_chain": primary_chain,
            "causal_edges": dag_edges_payload[:200]  # bounded for JSON rendering
        }

    def enrich_incident_case_package(self, incident_cases_path: Path) -> Path:
        """
        Enriches outputs/incident_cases.json with the Causal Provenance DAG
        and primary attack chain for every incident.
        """
        if not Path(incident_cases_path).exists():
            return incident_cases_path

        with open(incident_cases_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        data["causal_provenance_engine"] = "Lamport Temporal DAG & MITRE FSM v1.0"

        for inc in data.get("incidents", []):
            analysis = self.analyze_incident(inc)
            inc["causal_provenance"] = analysis
            inc["primary_attack_chain"] = analysis.get("primary_attack_chain", [])
            inc["root_cause_flow"] = analysis.get("root_cause_entry_flow")

        with open(incident_cases_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

        print(f"[CausalEngine] Enriched case package with Causal Provenance DAGs: {incident_cases_path}")
        return incident_cases_path
