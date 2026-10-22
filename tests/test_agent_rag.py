"""
Unit and Integration Tests for Member 3 Forensic Agent, RAG & Citation Validator
Tests:
1. CitationValidator precision and hallucination rejection
2. ForensicAgent tool-calling telemetry retrieval
3. MITRE ATT&CK tactic/technique mapping consistency
4. End-to-end report generation and faithfulness threshold (>= 95%)
"""

import unittest
from pathlib import Path
import json

from src.agent.citation_validator import CitationValidator
from src.agent.forensic_agent import ForensicAgent, MITRE_ATTACK_MAPPING
from src.config import OUTPUTS_DIR

class TestForensicAgentAndRAG(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases_file = OUTPUTS_DIR / "incident_cases.json"
        if not cls.cases_file.exists():
            raise unittest.SkipTest("outputs/incident_cases.json does not exist. Run main.py first.")

    def test_citation_validator_valid_and_invalid(self):
        validator = CitationValidator(self.cases_file)
        self.assertGreater(len(validator.valid_flow_ids), 0)

        # Pick one genuine flow ID
        sample_valid_id = next(iter(validator.valid_flow_ids))
        fake_id = "flw_hallucinated_9999"

        sample_text = (
            f"The attacker executed lateral movement [E:{sample_valid_id}]. "
            f"The adversary also compromised host X [E:{fake_id}]."
        )
        res = validator.validate_report(sample_text)
        self.assertEqual(res["total_citations"], 2)
        self.assertEqual(res["verified_count"], 1)
        self.assertEqual(res["hallucinated_count"], 1)
        self.assertIn(fake_id, res["hallucinated_flow_ids"])
        self.assertFalse(res["passed_threshold"])

    def test_forensic_agent_tool_calling(self):
        agent = ForensicAgent(self.cases_file)
        # Test 1: get_flow_count tool
        with open(self.cases_file, "r") as f:
            cases_data = json.load(f)
        
        incidents = cases_data.get("incidents", [])
        self.assertGreater(len(incidents), 0)
        entry_ip = incidents[0]["suspected_entry_point"]
        
        flow_count = agent.get_flow_count(entry_ip)
        self.assertIsInstance(flow_count, int)
        self.assertGreater(flow_count, 0)

        # Test 2: unknown host flow count
        self.assertEqual(agent.get_flow_count("199.199.199.199"), 0)

        # Test 3: get_incident_summary tool
        summary = agent.get_incident_summary(incidents[0]["incident_id"])
        self.assertEqual(summary["incident_id"], incidents[0]["incident_id"])

        # Test 4: get_flow_evidence tool
        first_flow = incidents[0]["evidence_flow_ids"][0]
        evidence = agent.get_flow_evidence(first_flow)
        self.assertIn("edge_id", evidence)
        self.assertEqual(evidence["edge_id"], first_flow)

        # Test 5: verify_evidence_merkle_proof tool
        proof_res = agent.verify_evidence_merkle_proof(first_flow)
        self.assertIn("flow_id", proof_res)
        self.assertIn("status", proof_res)

        # Test 6: get_causal_attack_chain tool
        chain_res = agent.get_causal_attack_chain(incidents[0]["incident_id"])
        self.assertIn("incident_id", chain_res)
        self.assertIn("primary_attack_chain", chain_res)

    def test_mitre_attack_mapping(self):
        agent = ForensicAgent(self.cases_file)
        mapping = agent.map_to_mitre_attack("PortScan")
        self.assertEqual(mapping["tactic_id"], "TA0007")
        self.assertEqual(mapping["technique_id"], "T1046")

        mapping_ssh = agent.map_to_mitre_attack("SSH-Patator")
        self.assertEqual(mapping_ssh["tactic_id"], "TA0006")
        self.assertEqual(mapping_ssh["technique_id"], "T1110.001")

    def test_end_to_end_agent_report_generation(self):
        agent = ForensicAgent(self.cases_file)
        report_file = OUTPUTS_DIR / "test_forensic_report.md"
        result_path = agent.run(output_report_path=report_file)
        self.assertTrue(result_path.exists())

        # Validate citation faithfulness
        with open(result_path, "r", encoding="utf-8") as f:
            text = f.read()

        val = agent.validator.validate_report(text)
        self.assertTrue(val["passed_threshold"], f"Faithfulness {val['citation_faithfulness_pct']}% is below 95%")
        self.assertEqual(val["hallucinated_count"], 0)
        self.assertGreater(val["total_citations"], 0)

if __name__ == "__main__":
    unittest.main()
