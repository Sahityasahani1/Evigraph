"""
Unit tests for EviGraph Counterfactual Resilience Simulator
"""

import unittest
import json
from pathlib import Path

from src.simulation.counterfactual_engine import CounterfactualResilienceSimulator
from src.config import OUTPUTS_DIR

class TestCounterfactualResilienceSimulator(unittest.TestCase):
    def setUp(self):
        self.cases_path = OUTPUTS_DIR / "incident_cases.json"
        self.sim = CounterfactualResilienceSimulator(incident_cases_path=self.cases_path)

    def test_incident_dag_reconstruction(self):
        """Test that DAGs are reconstructed for detected incidents."""
        if not self.cases_path.exists():
            self.skipTest("incident_cases.json not found")

        self.assertGreater(len(self.sim.incident_dags), 0)
        for inc_id, dag in self.sim.incident_dags.items():
            self.assertGreater(dag.number_of_nodes(), 0)

    def test_counterfactual_port_blocking(self):
        """Test simulating a port closure policy intervention."""
        if not self.cases_path.exists():
            self.skipTest("incident_cases.json not found")

        res = self.sim.simulate_policy_intervention(
            incident_id="INC-0001",
            intervention_type="BLOCK_PORT",
            parameter=100,
            policy_name="Block Port 100"
        )

        self.assertEqual(res["incident_id"], "INC-0001")
        self.assertIn("defensive_resilience_index", res)
        self.assertGreaterEqual(res["defensive_resilience_index"], 0.0)

    def test_counterfactual_entry_quarantine_extinction(self):
        """Test that isolating the entry host achieves 100% attack extinction."""
        if not self.cases_path.exists():
            self.skipTest("incident_cases.json not found")

        # Entry host for INC-0001 is 172.16.0.105
        res = self.sim.simulate_policy_intervention(
            incident_id="INC-0001",
            intervention_type="ISOLATE_HOST",
            parameter="172.16.0.105",
            policy_name="Quarantine Patient Zero"
        )

        self.assertEqual(res["defensive_resilience_index"], 1.0)
        self.assertTrue(res["attack_extinguished"])
        self.assertTrue(res["single_point_of_failure"])

    def test_simulation_suite_and_export(self):
        """Test comprehensive simulation suite run and artifact generation."""
        if not self.cases_path.exists():
            self.skipTest("incident_cases.json not found")

        j_path, md_path = self.sim.run()
        self.assertTrue(j_path.exists())
        self.assertTrue(md_path.exists())

        with open(j_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertIn("simulations", data)
        self.assertGreater(len(data["simulations"]), 0)

if __name__ == "__main__":
    unittest.main()
