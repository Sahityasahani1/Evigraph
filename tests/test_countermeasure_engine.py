"""
Unit tests for EviGraph Autonomous Surgical Containment & Blast-Radius Engine
"""

import unittest
import json
from pathlib import Path

from src.mitigation.countermeasure_engine import CountermeasureEngine
from src.config import OUTPUTS_DIR

class TestCountermeasureEngine(unittest.TestCase):
    def setUp(self):
        self.cases_path = OUTPUTS_DIR / "incident_cases.json"
        self.engine = CountermeasureEngine(incident_cases_path=self.cases_path)

    def test_blast_radius_calculation(self):
        """Test blast radius computation for critical services vs standard hosts."""
        # DNS port 53 should have high blast radius
        dns_blast = self.engine.compute_blast_radius("192.168.1.53", target_port=53)
        self.assertGreaterEqual(dns_blast["blast_radius_score"], 0.65)
        self.assertEqual(dns_blast["impact_level"], "HIGH_RISK_PRODUCTION_DISRUPTION")
        self.assertEqual(dns_blast["recommended_approach"], "SURGICAL_L4_EDGE_DROP_ONLY")

        # Unknown non-critical workstation port should have low blast radius
        leaf_blast = self.engine.compute_blast_radius("10.0.0.99", target_port=9999)
        self.assertLess(leaf_blast["blast_radius_score"], 0.40)
        self.assertEqual(leaf_blast["impact_level"], "LOW_COLLATERAL_IMPACT")

    def test_remediation_command_synthesis(self):
        """Test that synthesized firewall commands are formatted across platforms."""
        cmds = self.engine.synthesize_remediation_commands(
            rule_id="RULE-TEST-01",
            attacker_ip="172.16.0.105",
            victim_ip="192.168.10.50",
            port=22,
            protocol="TCP",
            action_type="EDGE_DROP"
        )

        self.assertIn("linux_iptables", cmds)
        self.assertIn("linux_nftables", cmds)
        self.assertIn("windows_powershell", cmds)
        self.assertIn("cisco_ios_acl", cmds)

        # Check content
        self.assertIn("172.16.0.105", cmds["linux_iptables"])
        self.assertIn("--dport 22", cmds["linux_iptables"])
        self.assertIn("New-NetFirewallRule", cmds["windows_powershell"])
        self.assertIn("access-list 101 deny tcp host 172.16.0.105", cmds["cisco_ios_acl"])

    def test_containment_plan_generation(self):
        """Test end-to-end containment plan and advisory report generation."""
        if not self.cases_path.exists():
            self.skipTest("incident_cases.json not found")

        plan = self.engine.generate_containment_plan()
        self.assertIn("incident_plans", plan)
        self.assertGreater(plan["total_containment_rules_synthesized"], 0)

        p_path, adv_path = self.engine.run()
        self.assertTrue(p_path.exists())
        self.assertTrue(adv_path.exists())

        with open(p_path, "r", encoding="utf-8") as f:
            saved_plan = json.load(f)
        self.assertIn("incident_plans", saved_plan)

if __name__ == "__main__":
    unittest.main()
