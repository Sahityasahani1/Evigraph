"""
EviGraph Host-Communication Graph Engine
Adheres to TRD Section 3.3.3 & 3.5:
- Builds time-windowed directed host-communication graph (Nodes = Hosts, Edges = Flows)
- Computes host behavioral metrics (fan-out, degrees, unique ports, bytes out vs in)
- Extracts suspicious subgraphs around flagged alerts
- Provides Cytoscape/JSON compatible network serialization for the agent
"""

import networkx as nx
import pandas as pd
import numpy as np
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta

class HostGraphEngine:
    def __init__(self):
        self.graph = nx.MultiDiGraph()

    def build_graph_from_flows(self, flows_df: pd.DataFrame) -> nx.MultiDiGraph:
        """
        Constructs a directed multigraph from flow records.
        flows_df must have: ['flow_id', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'timestamp', 'risk_score', 'predicted_class']
        """
        self.graph.clear()
        
        # 1. Vectorized bulk edge addition (TRD NFR-3 / NFR-5)
        src_ips = flows_df["src_ip"].astype(str).values
        dst_ips = flows_df["dst_ip"].astype(str).values
        flow_ids = flows_df["flow_id"].astype(str).values if "flow_id" in flows_df.columns else [f"flw_{i}" for i in range(len(flows_df))]
        timestamps = flows_df["timestamp"].astype(str).values if "timestamp" in flows_df.columns else [""] * len(flows_df)
        src_ports = flows_df["src_port"].fillna(0).astype(int).values if "src_port" in flows_df.columns else np.zeros(len(flows_df), dtype=int)
        dst_ports = flows_df["dst_port"].fillna(0).astype(int).values if "dst_port" in flows_df.columns else np.zeros(len(flows_df), dtype=int)
        protocols = flows_df["protocol"].fillna(6).astype(int).values if "protocol" in flows_df.columns else np.full(len(flows_df), 6, dtype=int)
        risk_scores = flows_df["risk_score"].fillna(0.0).astype(float).values if "risk_score" in flows_df.columns else np.zeros(len(flows_df), dtype=float)
        pred_classes = flows_df["predicted_class"].astype(str).values if "predicted_class" in flows_df.columns else np.full(len(flows_df), "BENIGN")
        is_alerts = flows_df["is_alert"].astype(bool).values if "is_alert" in flows_df.columns else np.zeros(len(flows_df), dtype=bool)
        fwd_col = "tot_len_fwd_pkts" if "tot_len_fwd_pkts" in flows_df.columns else ("totlen_fwd_pkts" if "totlen_fwd_pkts" in flows_df.columns else None)
        bwd_col = "tot_len_bwd_pkts" if "tot_len_bwd_pkts" in flows_df.columns else ("totlen_bwd_pkts" if "totlen_bwd_pkts" in flows_df.columns else None)
        fwd_bytes = flows_df[fwd_col].fillna(0.0).astype(float).values if fwd_col else np.zeros(len(flows_df), dtype=float)
        bwd_bytes = flows_df[bwd_col].fillna(0.0).astype(float).values if bwd_col else np.zeros(len(flows_df), dtype=float)
        shap_exps = flows_df["shap_explanation"].tolist() if "shap_explanation" in flows_df.columns else [[] for _ in range(len(flows_df))]

        edge_list = [
            (
                s, d, fid,
                {
                    "flow_id": fid,
                    "timestamp": ts,
                    "src_port": sp,
                    "dst_port": dp,
                    "protocol": proto,
                    "risk_score": r,
                    "predicted_class": pc,
                    "is_alert": al,
                    "tot_fwd_bytes": fb,
                    "tot_bwd_bytes": bb,
                    "shap_explanation": se
                }
            )
            for s, d, fid, ts, sp, dp, proto, r, pc, al, fb, bb, se in zip(
                src_ips, dst_ips, flow_ids, timestamps, src_ports, dst_ports,
                protocols, risk_scores, pred_classes, is_alerts, fwd_bytes, bwd_bytes, shap_exps
            )
        ]
        self.graph.add_edges_from(edge_list)

        # 2. Vectorized Host (Node) Behavioral Metrics via pandas groupby (0.1s instead of O(N) loop)
        out_agg = flows_df.groupby("src_ip").agg(
            out_degree=("dst_ip", "count"),
            fan_out=("dst_ip", "nunique"),
            unique_dst_ports=("dst_port", "nunique") if "dst_port" in flows_df.columns else ("dst_ip", "nunique"),
            bytes_out=(fwd_col, "sum") if fwd_col else ("dst_ip", "count"),
            alerts_sent=("is_alert", "sum") if "is_alert" in flows_df.columns else ("dst_ip", "count")
        )
        in_agg = flows_df.groupby("dst_ip").agg(
            in_degree=("src_ip", "count"),
            fan_in=("src_ip", "nunique"),
            bytes_in=(bwd_col, "sum") if bwd_col else ("src_ip", "count"),
            alerts_received=("is_alert", "sum") if "is_alert" in flows_df.columns else ("src_ip", "count")
        )

        out_dict = out_agg.to_dict(orient="index")
        in_dict = in_agg.to_dict(orient="index")

        for node in self.graph.nodes():
            o = out_dict.get(node, {})
            i = in_dict.get(node, {})
            self.graph.nodes[node]["in_degree"] = int(i.get("in_degree", 0))
            self.graph.nodes[node]["out_degree"] = int(o.get("out_degree", 0))
            self.graph.nodes[node]["fan_out"] = int(o.get("fan_out", 0))
            self.graph.nodes[node]["fan_in"] = int(i.get("fan_in", 0))
            self.graph.nodes[node]["port_diversity"] = int(o.get("unique_dst_ports", 0))
            self.graph.nodes[node]["bytes_out"] = float(o.get("bytes_out", 0.0))
            self.graph.nodes[node]["bytes_in"] = float(i.get("bytes_in", 0.0))
            self.graph.nodes[node]["alerts_sent"] = int(o.get("alerts_sent", 0))
            self.graph.nodes[node]["alerts_received"] = int(i.get("alerts_received", 0))

        print(f"[GraphEngine] Built host graph: {self.graph.number_of_nodes()} nodes (hosts), {self.graph.number_of_edges()} edges (flows)")
        return self.graph

    def extract_suspicious_subgraph(
        self, 
        alert_flow_ids: List[str], 
        k_hop: int = 1
    ) -> Dict[str, Any]:
        """
        Extracts the k-hop induced neighborhood around hosts participating in alert flows.
        Returns serialized Cytoscape-compatible JSON structure.
        """
        # Find all hosts involved in alerts with O(1) set lookup
        alert_ids_set = set(alert_flow_ids)
        alert_hosts = set()
        alert_edges = []
        
        for u, v, k, data in self.graph.edges(keys=True, data=True):
            if data.get("flow_id") in alert_ids_set or data.get("is_alert", False):
                alert_hosts.add(u)
                alert_hosts.add(v)
                alert_edges.append((u, v, k, data))

        if not alert_hosts:
            return {"nodes": [], "edges": []}

        # Expand to k-hop neighborhood for forensic context
        subgraph_nodes = set(alert_hosts)
        for _ in range(k_hop):
            neighbors = set()
            for node in subgraph_nodes:
                neighbors.update(self.graph.predecessors(node))
                neighbors.update(self.graph.successors(node))
            subgraph_nodes.update(neighbors)

        # Build subnetwork
        subgraph = self.graph.subgraph(subgraph_nodes)
        
        # Serialize nodes
        nodes_payload = []
        for n, d in subgraph.nodes(data=True):
            role = "victim" if d.get("alerts_received", 0) > d.get("alerts_sent", 0) else "attacker" if d.get("alerts_sent", 0) > 0 else "context_host"
            nodes_payload.append({
                "id": str(n),
                "role": role,
                "in_degree": int(d.get("in_degree", 0)),
                "out_degree": int(d.get("out_degree", 0)),
                "fan_out": int(d.get("fan_out", 0)),
                "alerts_sent": int(d.get("alerts_sent", 0)),
                "alerts_received": int(d.get("alerts_received", 0))
            })
            
        # Serialize edges: PRIORITIZE alert evidence edges first (TRD NFR-4 & AGENTS.md contract)
        alert_edges_payload = []
        context_edges_payload = []
        max_alert_edges = 300
        max_context_edges = 100
        
        for u, v, k, d in subgraph.edges(keys=True, data=True):
            fid = str(d.get("flow_id", str(k)))
            is_incident_alert = (fid in alert_ids_set) or bool(d.get("is_alert", False))
            
            edge_dict = {
                "edge_id": fid,
                "source": str(u),
                "target": str(v),
                "timestamp": str(d.get("timestamp", "")),
                "dst_port": int(d.get("dst_port", 0)),
                "protocol": int(d.get("protocol", 6)),
                "risk_score": float(d.get("risk_score", 0.0)),
                "predicted_class": str(d.get("predicted_class", "BENIGN")),
                "is_alert": is_incident_alert
            }
            if d.get("shap_explanation"):
                edge_dict["shap_explanation"] = d.get("shap_explanation")
                
            if is_incident_alert:
                if len(alert_edges_payload) < max_alert_edges:
                    alert_edges_payload.append(edge_dict)
            else:
                if len(context_edges_payload) < max_context_edges:
                    context_edges_payload.append(edge_dict)

        edges_payload = alert_edges_payload + context_edges_payload

        return {
            "node_count": len(nodes_payload),
            "edge_count": len(edges_payload),
            "nodes": nodes_payload,
            "edges": edges_payload
        }
