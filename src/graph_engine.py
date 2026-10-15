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
        
        # 1. Add edges (each flow is a directed edge src_ip -> dst_ip)
        for _, row in flows_df.iterrows():
            src = str(row["src_ip"])
            dst = str(row["dst_ip"])
            
            # Edge attributes
            edge_attrs = {
                "flow_id": row.get("flow_id", ""),
                "timestamp": str(row.get("timestamp", "")),
                "src_port": int(row.get("src_port", 0)),
                "dst_port": int(row.get("dst_port", 0)),
                "protocol": int(row.get("protocol", 6)),
                "risk_score": float(row.get("risk_score", 0.0)),
                "predicted_class": str(row.get("predicted_class", "BENIGN")),
                "is_alert": bool(row.get("is_alert", False)),
                "tot_fwd_bytes": float(row.get("tot_len_fwd_pkts", 0.0)),
                "tot_bwd_bytes": float(row.get("tot_len_bwd_pkts", 0.0))
            }
            
            self.graph.add_edge(src, dst, key=edge_attrs["flow_id"], **edge_attrs)

        # 2. Compute Host (Node) Behavioral Features (TRD Sec 3.2 & 3.3.3)
        for node in self.graph.nodes():
            out_edges = self.graph.out_edges(node, data=True)
            in_edges = self.graph.in_edges(node, data=True)
            
            unique_destinations = len(set(v for _, v, _ in out_edges))
            unique_sources = len(set(u for u, _, _ in in_edges))
            unique_dst_ports = len(set(d.get("dst_port", 0) for _, _, d in out_edges))
            
            bytes_out = sum(d.get("tot_fwd_bytes", 0) for _, _, d in out_edges)
            bytes_in = sum(d.get("tot_bwd_bytes", 0) for _, _, d in in_edges)
            
            alerts_out = sum(1 for _, _, d in out_edges if d.get("is_alert", False))
            alerts_in = sum(1 for _, _, d in in_edges if d.get("is_alert", False))
            
            self.graph.nodes[node]["in_degree"] = self.graph.in_degree(node)
            self.graph.nodes[node]["out_degree"] = self.graph.out_degree(node)
            self.graph.nodes[node]["fan_out"] = unique_destinations
            self.graph.nodes[node]["fan_in"] = unique_sources
            self.graph.nodes[node]["port_diversity"] = unique_dst_ports
            self.graph.nodes[node]["bytes_out"] = bytes_out
            self.graph.nodes[node]["bytes_in"] = bytes_in
            self.graph.nodes[node]["alerts_sent"] = alerts_out
            self.graph.nodes[node]["alerts_received"] = alerts_in

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
        # Find all hosts involved in alerts
        alert_hosts = set()
        alert_edges = []
        
        for u, v, k, data in self.graph.edges(keys=True, data=True):
            if data.get("flow_id") in alert_flow_ids or data.get("is_alert", False):
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
                "in_degree": d.get("in_degree", 0),
                "out_degree": d.get("out_degree", 0),
                "fan_out": d.get("fan_out", 0),
                "alerts_sent": d.get("alerts_sent", 0),
                "alerts_received": d.get("alerts_received", 0)
            })
            
        # Serialize edges (bounded by max_edges for UI/Agent performance, TRD NFR-4)
        edges_payload = []
        for u, v, k, d in subgraph.edges(keys=True, data=True):
            if len(edges_payload) >= 300:
                break
            edges_payload.append({
                "edge_id": d.get("flow_id", str(k)),
                "source": str(u),
                "target": str(v),
                "timestamp": d.get("timestamp"),
                "dst_port": d.get("dst_port"),
                "protocol": d.get("protocol"),
                "risk_score": d.get("risk_score", 0.0),
                "predicted_class": d.get("predicted_class", "BENIGN"),
                "is_alert": d.get("is_alert", False)
            })

        return {
            "node_count": len(nodes_payload),
            "edge_count": len(edges_payload),
            "nodes": nodes_payload,
            "edges": edges_payload
        }
