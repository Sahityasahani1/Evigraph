"""
Unit Tests for EviGraph Temporal Causal Provenance DAG & Attack Stage FSM Engine
Tests:
1. MITRE ATT&CK tactical stage classification & ranking
2. Forward vs backward FSM tactical transition likelihood scoring
3. Lamport temporal arrow of time and strict DAG acyclicity (nx.is_directed_acyclic_graph)
4. Lateral movement pivoting identification (u -> v followed by v -> w)
5. Primary attack chain discovery via topological dynamic programming
"""

import unittest
import networkx as nx
import pandas as pd
from datetime import datetime

from src.causal_provenance import CausalProvenanceEngine

class TestCausalProvenanceEngine(unittest.TestCase):
    def setUp(self):
        self.engine = CausalProvenanceEngine(
            max_scan_window_secs=120.0,
            min_dwell_time_secs=0.01,
            max_dwell_time_secs=300.0,
            min_causal_confidence=0.30
        )
        # Synthetic multi-stage campaign flows
        # Stage 1: Attacker scans Target Server (PortScan)
        # Stage 2: Attacker brute forces Target Server (SSH-Patator)
        # Stage 3: Target Server pivots and attacks Internal Workstation (Lateral-SMB-Relay)
        # Stage 4: Target Server exfiltrates data (HTTPS-Exfiltration)
        self.sample_edges = [
            {
                "edge_id": "flw_recon_01",
                "source": "172.16.0.100",
                "target": "192.168.10.50",
                "timestamp": "2026-10-15T09:10:00",
                "dst_port": 100,
                "protocol": 6,
                "risk_score": 0.95,
                "predicted_class": "PortScan"
            },
            {
                "edge_id": "flw_ssh_02",
                "source": "172.16.0.100",
                "target": "192.168.10.50",
                "timestamp": "2026-10-15T09:10:30",
                "dst_port": 22,
                "protocol": 6,
                "risk_score": 0.98,
                "predicted_class": "SSH-Patator"
            },
            {
                "edge_id": "flw_pivot_03",
                "source": "192.168.10.50",  # Pivoting from victim server!
                "target": "192.168.10.99",
                "timestamp": "2026-10-15T09:11:00",
                "dst_port": 445,
                "protocol": 6,
                "risk_score": 0.94,
                "predicted_class": "Lateral-SMB-Relay"
            },
            {
                "edge_id": "flw_exfil_04",
                "source": "192.168.10.50",
                "target": "203.0.113.88",
                "timestamp": "2026-10-15T09:12:00",
                "dst_port": 443,
                "protocol": 6,
                "risk_score": 0.96,
                "predicted_class": "HTTPS-Exfiltration"
            }
        ]

    def test_stage_classification(self):
        self.assertEqual(self.engine.classify_stage("PortScan"), "Reconnaissance")
        self.assertEqual(self.engine.classify_stage("SSH-Patator"), "Credential Access")
        self.assertEqual(self.engine.classify_stage("Lateral-SMB-Relay"), "Lateral Movement")
        self.assertEqual(self.engine.classify_stage("HTTPS-Exfiltration"), "Exfiltration & Impact")

    def test_fsm_scores_forward_vs_backward(self):
        # Forward Recon -> Access should score higher than backward Exfil -> Recon
        score_fwd = self.engine.compute_fsm_score("Reconnaissance", "Credential Access")
        score_back = self.engine.compute_fsm_score("Exfiltration & Impact", "Reconnaissance")
        self.assertGreater(score_fwd, score_back)
        self.assertEqual(score_fwd, 1.00)

    def test_dag_strict_acyclicity(self):
        dag = self.engine.build_causal_dag(self.sample_edges)
        self.assertEqual(dag.number_of_nodes(), 4)
        self.assertGreater(dag.number_of_edges(), 0)
        # Mathematical verification: MUST be a strict DAG
        self.assertTrue(nx.is_directed_acyclic_graph(dag), "Causal graph contains cycles! Violates Lamport time.")

    def test_lateral_pivot_edge_detection(self):
        dag = self.engine.build_causal_dag(self.sample_edges)
        # flw_ssh_02 (172.16.0.100 -> 192.168.10.50) to flw_pivot_03 (192.168.10.50 -> 192.168.10.99)
        self.assertTrue(dag.has_edge("flw_ssh_02", "flw_pivot_03"))
        edge_data = dag["flw_ssh_02"]["flw_pivot_03"]
        self.assertTrue(edge_data["is_pivot"], "Failed to detect lateral pivot transition!")
        self.assertIn("Lateral Movement", edge_data["transition"])

    def test_primary_attack_chain_extraction(self):
        dag = self.engine.build_causal_dag(self.sample_edges)
        chain = self.engine.extract_primary_attack_chain(dag)
        self.assertGreaterEqual(len(chain), 3)

        # First step in chain must be the initial entry reconnaissance
        self.assertEqual(chain[0]["flow_id"], "flw_recon_01")
        self.assertEqual(chain[0]["attack_stage"], "Reconnaissance")

        # Must progress through stages
        stages = [step["attack_stage"] for step in chain]
        self.assertIn("Credential Access", stages)

    def test_incident_analysis_payload(self):
        incident_bundle = {
            "incident_id": "INC-TEST-01",
            "duration_seconds": 120.0,
            "subgraph": {
                "edges": self.sample_edges
            }
        }
        analysis = self.engine.analyze_incident(incident_bundle)
        self.assertEqual(analysis["causal_dag_nodes_count"], 4)
        self.assertEqual(analysis["root_cause_entry_flow"], "flw_recon_01")
        self.assertGreater(len(analysis["primary_attack_chain"]), 0)
        self.assertGreater(len(analysis["causal_edges"]), 0)

if __name__ == "__main__":
    unittest.main()
