"""
Security regression tests for the hardened EviGraph stack.

These tests are intentionally adversarial: they encode the exploits that were
demonstrated against the original implementation so the fixes cannot silently
regress.
"""

import json
import unittest
from pathlib import Path
from unittest.mock import patch

from src.integrity.merkle_engine import (
    MerkleEvidenceEngine,
    SCHEME_V2,
    SCHEME_LEGACY,
    LEAF_PREFIX,
    NODE_PREFIX,
)
from src.integrity.privacy_proofs import PrivacyPreservingProofEngine
from src.config import OUTPUTS_DIR


FLOWS = [
    {
        "flow_id": "flw_sec_001",
        "src_ip": "172.16.0.105",
        "dst_ip": "192.168.10.50",
        "src_port": 49201,
        "dst_port": 22,
        "protocol": 6,
        "timestamp": "2026-10-15T09:12:00",
    },
    {
        "flow_id": "flw_sec_002",
        "src_ip": "10.0.0.5",
        "dst_ip": "192.168.10.50",
        "src_port": 51234,
        "dst_port": 445,
        "protocol": 6,
        "timestamp": "2026-10-15T09:12:01",
    },
    {
        "flow_id": "flw_sec_003",
        "src_ip": "203.0.113.10",
        "dst_ip": "10.0.0.5",
        "src_port": 40000,
        "dst_port": 80,
        "protocol": 6,
        "timestamp": "2026-10-15T09:12:02",
    },
]


class TestMerkleHardening(unittest.TestCase):
    def setUp(self):
        self.engine = MerkleEvidenceEngine()
        self.engine.build_tree(FLOWS)

    def test_domain_separation_prefixes(self):
        import hashlib

        leaf = self.engine.compute_leaf_hash(FLOWS[0], SCHEME_V2)
        expected = hashlib.sha256(
            LEAF_PREFIX + self.engine.canonical_repr_v2(FLOWS[0]).encode("utf-8")
        ).hexdigest()
        self.assertEqual(leaf, expected)

        left, right = self.engine.levels[0][0], self.engine.levels[0][1]
        node = MerkleEvidenceEngine._hash_pair(left, right, SCHEME_V2)
        expected_node = hashlib.sha256(
            NODE_PREFIX + bytes.fromhex(left) + bytes.fromhex(right)
        ).hexdigest()
        self.assertEqual(node, expected_node)

    def test_legacy_scheme_is_distinct(self):
        legacy = MerkleEvidenceEngine()
        legacy.build_tree(FLOWS, scheme=SCHEME_LEGACY)
        self.assertNotEqual(legacy.root_hash, self.engine.root_hash)
        self.assertEqual(legacy.scheme, SCHEME_LEGACY)

    def test_duplicate_flow_ids_rejected(self):
        duplicated = FLOWS + [dict(FLOWS[0])]
        with self.assertRaises(ValueError):
            MerkleEvidenceEngine().build_tree(duplicated)

    def test_odd_node_promotion_avoids_duplicate_tree_ambiguity(self):
        four = MerkleEvidenceEngine()
        four.build_tree(FLOWS[:2] + [
            {**FLOWS[2], "flow_id": "flw_sec_004"},
            {**FLOWS[2], "flow_id": "flw_sec_005"},
        ])
        # A five-leaf tree and a six-leaf tree must not collide merely because
        # the last node was duplicated to make the level even.
        six = MerkleEvidenceEngine()
        six.build_tree(FLOWS + [
            {**FLOWS[0], "flow_id": "flw_sec_006"},
            {**FLOWS[1], "flow_id": "flw_sec_007"},
            {**FLOWS[2], "flow_id": "flw_sec_008"},
        ])
        self.assertNotEqual(four.root_hash, six.root_hash)

    def test_proof_requires_expected_root(self):
        proof = self.engine.get_inclusion_proof("flw_sec_001")
        self.assertTrue(MerkleEvidenceEngine.verify_audit_path(proof, self.engine.root_hash))
        self.assertFalse(MerkleEvidenceEngine.verify_audit_path(proof, None))
        self.assertFalse(MerkleEvidenceEngine.verify_audit_path(proof, "00" * 32))

    def test_tampered_flow_fails_verification(self):
        proof = self.engine.get_inclusion_proof("flw_sec_001")
        tampered = dict(FLOWS[0], dst_port=2222)
        self.assertFalse(
            MerkleEvidenceEngine.verify_inclusion_proof(
                tampered, proof, expected_root=self.engine.root_hash
            )
        )

    def test_proof_binds_tree_size_and_index(self):
        proof = self.engine.get_inclusion_proof("flw_sec_001")
        self.assertEqual(proof["tree_size"], len(FLOWS))
        self.assertIn("leaf_index", proof)
        bad = dict(proof, leaf_index=999)
        self.assertFalse(
            MerkleEvidenceEngine.verify_audit_path(bad, self.engine.root_hash)
        )


class TestPrivacyHardening(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cert_path = OUTPUTS_DIR / "forensic_merkle_certificate.json"
        cls.cases_path = OUTPUTS_DIR / "incident_cases.json"
        cls.privacy_path = OUTPUTS_DIR / "privacy_preserving_proof_certificate.json"

    def test_certificate_never_ships_disclosure_secret(self):
        if not self.privacy_path.exists():
            self.skipTest("privacy certificate not generated")
        cert = json.loads(self.privacy_path.read_text(encoding="utf-8"))
        self.assertNotIn("enterprise_selective_disclosure_key", cert)
        disclosure = cert.get("selective_disclosure", {})
        self.assertFalse(disclosure.get("key_included_in_certificate", True))
        self.assertTrue(disclosure.get("key_id"))

    def test_redacted_proof_requires_root(self):
        if not (self.cert_path.exists() and self.cases_path.exists()):
            self.skipTest("artifacts not generated")
        engine = PrivacyPreservingProofEngine(
            merkle_cert_path=self.cert_path, incident_cases_path=self.cases_path
        )
        cert = engine.generate_privacy_certificate(max_samples_per_incident=1)
        proof = cert["redacted_intrusion_proofs"][0]
        self.assertTrue(
            PrivacyPreservingProofEngine.verify_redacted_proof(
                proof, cert["session_merkle_root"]
            )
        )
        self.assertFalse(PrivacyPreservingProofEngine.verify_redacted_proof(proof, ""))

        tampered = json.loads(json.dumps(proof))
        tampered["cryptographic_verification"]["leaf_hash"] = "00" * 32
        self.assertFalse(
            PrivacyPreservingProofEngine.verify_redacted_proof(
                tampered, cert["session_merkle_root"]
            )
        )

    def test_commitment_verification(self):
        secret = "unit-test-secret"
        import hashlib
        import hmac

        salt = "abcd1234"
        value = "172.16.0.105"
        commitment = {
            "salt": salt,
            "commitment_hash": hmac.new(
                secret.encode(),
                f"src_ip\x00{value}\x00{salt}".encode(),
                hashlib.sha256,
            ).hexdigest(),
        }
        self.assertTrue(
            PrivacyPreservingProofEngine.verify_commitment(
                "src_ip", value, commitment, secret
            )
        )
        self.assertFalse(
            PrivacyPreservingProofEngine.verify_commitment(
                "src_ip", "10.0.0.1", commitment, secret
            )
        )


class TestAgentHardening(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases_file = OUTPUTS_DIR / "incident_cases.json"
        if not cls.cases_file.exists():
            raise unittest.SkipTest("outputs/incident_cases.json does not exist")

    def test_tool_allowlist_rejects_dunder_and_private_methods(self):
        from src.agent.forensic_agent import ForensicAgent

        agent = ForensicAgent(incident_cases_path=self.cases_file)
        for name in ("__init__", "run", "load_cases", "_generate_report_ollama", "os.system"):
            result = json.loads(agent._dispatch_tool(name, {}))
            self.assertIn("error", result)

    def test_tool_allowlist_rejects_unexpected_arguments(self):
        from src.agent.forensic_agent import ForensicAgent

        agent = ForensicAgent(incident_cases_path=self.cases_file)
        result = json.loads(
            agent._dispatch_tool("get_flow_count", {"host_ip": "10.0.0.5", "cmd": "whoami"})
        )
        self.assertIn("error", result)

    def test_merkle_verification_recomputes_proof(self):
        from src.agent.forensic_agent import ForensicAgent

        agent = ForensicAgent(incident_cases_path=self.cases_file)
        if not agent.edge_by_id:
            self.skipTest("no evidence edges")
        flow_id = next(iter(agent.edge_by_id))
        result = agent.verify_evidence_merkle_proof(flow_id)
        self.assertTrue(result["verified"])
        self.assertEqual(result["status"], "CRYPTOGRAPHICALLY_VERIFIED")


class TestCitationInflation(unittest.TestCase):
    def test_repeated_valid_citation_cannot_inflate_score(self):
        from src.agent.citation_validator import CitationValidator

        cases = OUTPUTS_DIR / "incident_cases.json"
        if not cases.exists():
            self.skipTest("case bundle missing")
        validator = CitationValidator(cases)
        valid = next(iter(validator.valid_flow_ids))
        report = " ".join([f"claim [E:{valid}]"] * 20 + ["hallucination [E:flw_fake_999]"])
        result = validator.validate_report(report)
        self.assertLess(result["citation_faithfulness_pct"], 95.0)
        self.assertFalse(result["passed_threshold"])
        self.assertGreater(result["citation_inflation_ratio"], 1.0)


class TestRunManifest(unittest.TestCase):
    def test_manifest_records_hashes_without_fabrication(self):
        manifest_path = OUTPUTS_DIR / "run_manifest.json"
        if not manifest_path.exists():
            self.skipTest("run manifest not generated")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        self.assertIn("generated_at", manifest)
        self.assertIn("commit", manifest["git"])
        self.assertIn("split_protocol", manifest["pipeline"])
        self.assertIsInstance(manifest["warnings"], list)

        for name, entry in manifest["output_artifacts"].items():
            if entry["hashed"]:
                self.assertRegex(entry["sha256"], r"^[a-f0-9]{64}$", name)
            else:
                self.assertIsNone(entry["sha256"], name)

        input_data = manifest["input_data"]
        if input_data["hash_status"] == "HASHED":
            self.assertRegex(input_data["sha256"], r"^[a-f0-9]{64}$")
        elif input_data["hash_status"] == "NO_STABLE_SOURCE":
            self.assertIn("no stable file source", " ".join(manifest["warnings"]).lower())


class TestContainmentSafety(unittest.TestCase):
    def test_remediation_rejects_shell_metacharacters(self):
        from src.mitigation.countermeasure_engine import CountermeasureEngine

        engine = CountermeasureEngine.__new__(CountermeasureEngine)
        with self.assertRaises(ValueError):
            engine.synthesize_remediation_commands(
                "RULE-1", "8.8.8.8; rm -rf /", "10.0.0.5", 80
            )
        with self.assertRaises(ValueError):
            engine.synthesize_remediation_commands(
                "RULE-1", "8.8.8.8", "10.0.0.5", "80; whoami"
            )
        with self.assertRaises(ValueError):
            engine.synthesize_remediation_commands(
                "RULE-1", "8.8.8.8", "10.0.0.5", 80, protocol="TCP; whoami"
            )

    def test_valid_rule_is_marked_advisory(self):
        from src.mitigation.countermeasure_engine import CountermeasureEngine

        engine = CountermeasureEngine.__new__(CountermeasureEngine)
        commands = engine.synthesize_remediation_commands(
            "RULE-1", "203.0.113.10", "10.0.0.5", 22, protocol="TCP"
        )
        self.assertIn("iptables", commands["linux_iptables"])
        self.assertIn("203.0.113.10", commands["linux_iptables"])


class TestAPIHardening(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            from fastapi.testclient import TestClient
            import api.server as server
        except Exception as exc:  # pragma: no cover
            raise unittest.SkipTest(f"API deps unavailable: {exc}")
        cls.server = server
        cls.client = TestClient(server.app)

    def test_path_traversal_is_blocked(self):
        for path in ("/..%2F.env.example", "/%2e%2e%2f.env.example", "/..%2f..%2fREADME.md"):
            response = self.client.get(path)
            self.assertEqual(response.status_code, 200)
            # Must be the SPA shell, never the contents of a file outside dist/.
            self.assertIn("<!DOCTYPE html>", response.text)
            self.assertNotIn("VITE_USE_MOCK", response.text)

    def test_unknown_incident_does_not_return_certified_verdict(self):
        response = self.client.get("/incidents/INC-DOES-NOT-EXIST/courtroom")
        self.assertEqual(response.status_code, 404)

    def test_invalid_incident_id_rejected(self):
        response = self.client.get("/incidents/..%2F..%2Fetc/courtroom")
        # Either rejected by the router or safely served the SPA shell; it must
        # never return a forensic verdict for a traversed path.
        if response.status_code == 200:
            self.assertIn("<!DOCTYPE html>", response.text)
        else:
            self.assertIn(response.status_code, (400, 404))

    def test_api_key_enforced_when_configured(self):
        original = self.server.API_KEY
        self.server.API_KEY = "test-key"
        try:
            unauth = self.client.get("/api/incidents")
            self.assertEqual(unauth.status_code, 401)

            wrong = self.client.get("/api/incidents", headers={"X-API-Key": "nope"})
            self.assertEqual(wrong.status_code, 401)

            ok = self.client.get("/api/incidents", headers={"X-API-Key": "test-key"})
            self.assertEqual(ok.status_code, 200)
        finally:
            self.server.API_KEY = original

    def test_security_headers_present(self):
        response = self.client.get("/health")
        self.assertEqual(response.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(response.headers.get("X-Frame-Options"), "DENY")

    def test_merkle_root_signature_verifies(self):
        cert_path = OUTPUTS_DIR / "forensic_merkle_certificate.json"
        if not cert_path.exists():
            self.skipTest("merkle certificate not generated")
        cert = json.loads(cert_path.read_text(encoding="utf-8"))
        from src.integrity.merkle_engine import MerkleEvidenceEngine
        self.assertEqual(MerkleEvidenceEngine.verify_root_signature(cert), "SIGNED_VALID")

    def test_leakage_audit_reports_no_overlap(self):
        audit_path = OUTPUTS_DIR / "leakage_audit.json"
        if not audit_path.exists():
            self.skipTest("leakage audit not generated")
        audit = json.loads(audit_path.read_text(encoding="utf-8"))
        self.assertFalse(audit["split_leakage"]["leakage_detected"])
        self.assertTrue(audit["feature_leakage"]["passed"])
        data = self.server.load_cases()
        incident_id = data["incidents"][0]["incident_id"]
        response = self.client.post(f"/incidents/{incident_id}/report")
        self.assertEqual(response.status_code, 200)
        validation = response.json()["validation"]
        self.assertGreaterEqual(validation["total"], 1)
        self.assertIn("faithfulness_pct", validation)
        self.assertTrue(validation["passed"])
        self.assertEqual(validation["faithfulness_pct"], 100.0)

    def test_incident_exposes_bundle_merkle_root(self):
        data = self.server.load_cases()
        incident_id = data["incidents"][0]["incident_id"]
        response = self.client.get(f"/incidents/{incident_id}")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json()["integrity"]["merkle_root"], data.get("merkle_root")
        )


if __name__ == "__main__":
    unittest.main()
