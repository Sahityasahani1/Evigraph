"""
Unit tests for EviGraph Dual-Agent Adversarial Courtroom Cross-Examiner
Adheres to FRE 902(13)/(14) & ISO/IEC 27037 standards:
- Verifies genuine forensic reports achieve ADMISSIBLE verdict
- Verifies Gate 1 catches corrupted leaf digests & fabricated flows
- Verifies Gate 2 catches impossible Layer-4 protocol violations (e.g. SSH over UDP)
- Verifies Gate 3 catches temporal paradoxes & retrograde causality
- Verifies Gate 4 catches ungrounded factual assertions
"""

import unittest
import json
from pathlib import Path
import tempfile

from src.agent.courtroom_auditor import CourtroomCrossExaminer
from src.config import OUTPUTS_DIR

class TestCourtroomCrossExaminer(unittest.TestCase):
    def setUp(self):
        self.cases_path = OUTPUTS_DIR / "incident_cases.json"
        self.cert_path = OUTPUTS_DIR / "forensic_merkle_certificate.json"
        self.report_path = OUTPUTS_DIR / "forensic_incident_report.md"

        self.examiner = CourtroomCrossExaminer(
            incident_cases_path=self.cases_path,
            merkle_cert_path=self.cert_path,
            report_path=self.report_path
        )

    def test_genuine_report_admissibility(self):
        """Test that the genuine generated report passes all gates with ADMISSIBLE_IN_COURT verdict."""
        if not self.report_path.exists() or not self.cert_path.exists():
            self.skipTest("Incident cases or Merkle certificate not found.")

        result = self.examiner.evaluate_report()

        self.assertIn("verdict", result)
        self.assertEqual(result["verdict"], "ADMISSIBLE_IN_COURT")
        self.assertGreaterEqual(result["admissibility_score"], 0.95)

        gate_scores = result["gate_scores"]
        self.assertEqual(gate_scores["gate1_cryptographic_merkle"], 1.0)
        self.assertEqual(gate_scores["gate2_protocol_feasibility"], 1.0)
        self.assertEqual(gate_scores["gate3_temporal_causal_dag"], 1.0)
        self.assertGreaterEqual(gate_scores["gate4_telemetry_fact_checking"], 0.90)

    def test_adversarial_rejection_fabricated_flow(self):
        """Test that Gate 1 sustains an objection when a hallucinated or fabricated flow ID is cited."""
        fake_report = (
            "# Incident Report\n"
            "The adversary breached internal host via unknown zero-day [E:flw_fabricated_ghost_9999]."
        )
        result = self.examiner.evaluate_report(fake_report)

        # Gate 1 should fail
        self.assertEqual(result["gate_scores"]["gate1_cryptographic_merkle"], 0.0)
        sustained = [o for o in result["cross_examination_objections"] if o.get("status") == "SUSTAINED"]
        objection_types = [o.get("type") for o in sustained]
        self.assertIn("OBJECTION_FABRICATED_OR_MISSING_PROOF", objection_types)
        self.assertEqual(result["verdict"], "INADMISSIBLE")

    def test_adversarial_rejection_tampered_leaf_hash(self):
        """Test that Gate 1 detects cryptographic tampering if a leaf hash is altered."""
        result = self.examiner.cross_examine_tampered_claim("tampered_leaf_hash")
        sustained = [o for o in result["cross_examination_objections"] if o.get("status") == "SUSTAINED"]
        objection_types = [o.get("type") for o in sustained]
        self.assertIn("OBJECTION_CRYPTOGRAPHIC_TAMPERING", objection_types)

    def test_adversarial_rejection_protocol_impossibility(self):
        """Test that Gate 2 sustains an objection when an impossible transport protocol is asserted (e.g. SSH over UDP)."""
        result = self.examiner.cross_examine_tampered_claim("protocol_impossibility")
        sustained = [o for o in result["cross_examination_objections"] if o.get("status") == "SUSTAINED"]
        objection_types = [o.get("type") for o in sustained]
        self.assertIn("OBJECTION_IMPOSSIBLE_LAYER4_PROTOCOL", objection_types)

    def test_adversarial_rejection_retrograde_causality(self):
        """Test that Gate 3 catches temporal paradoxes when attack steps are asserted backwards in time."""
        # Inject backwards timestamp in causal chain
        examiner = CourtroomCrossExaminer(
            incident_cases_path=self.cases_path,
            merkle_cert_path=self.cert_path,
            report_path=self.report_path
        )
        # Mutate first incident causal chain with a retrograde step
        examiner.causal_chains_by_incident = {
            "INC-TEST": [
                {"step": 1, "flow_id": "flw_1", "source": "10.0.0.1", "target": "10.0.0.2", "timestamp": "2026-10-15T12:00:10"},
                {"step": 2, "flow_id": "flw_2", "source": "10.0.0.2", "target": "10.0.0.3", "timestamp": "2026-10-15T11:59:00"}
            ]
        }

        score, objections = examiner.cross_examine_gate3_causal("Test report")
        self.assertEqual(score, 0.0)
        sustained = [o for o in objections if o.get("status") == "SUSTAINED"]
        self.assertEqual(len(sustained), 1)
        self.assertEqual(sustained[0]["type"], "OBJECTION_RETROGRADE_CAUSATION")

    def test_adversarial_rejection_uncited_compromise_assertion(self):
        """Test that Gate 4 catches assertions of compromise that lack evidence citations."""
        uncited_report = (
            "Executive Summary\n"
            "The adversary executed a malicious compromise of the database server without leaving traces."
        )
        # Evaluated citations will be empty
        score, objections = examiner_gate4 = self.examiner.cross_examine_gate4_fact_checking(uncited_report, [])
        sustained = [o for o in objections if o.get("status") == "SUSTAINED"]
        self.assertTrue(any(o.get("type") == "OBJECTION_UNCITED_FACTUAL_ASSERTION" for o in sustained))

    def test_certified_verdict_export(self):
        """Test that run() exports structured verdict JSON and markdown transcript."""
        if not self.report_path.exists() or not self.cert_path.exists():
            self.skipTest("Incident cases or Merkle certificate not found.")

        v_path, md_path = self.examiner.run()
        self.assertTrue(v_path.exists())
        self.assertTrue(md_path.exists())

        with open(v_path, "r", encoding="utf-8") as f:
            v_data = json.load(f)
        self.assertEqual(v_data["verdict"], "ADMISSIBLE_IN_COURT")
        self.assertIn("gate_scores", v_data)
        self.assertIn("cross_examination_objections", v_data)

if __name__ == "__main__":
    unittest.main()
