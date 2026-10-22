"""
Unit tests for EviGraph Privacy-Preserving Redacted Proof Engine
"""

import unittest
import json
from pathlib import Path

from src.integrity.privacy_proofs import PrivacyPreservingProofEngine
from src.config import OUTPUTS_DIR

class TestPrivacyPreservingProofs(unittest.TestCase):
    def setUp(self):
        self.cert_path = OUTPUTS_DIR / "forensic_merkle_certificate.json"
        self.cases_path = OUTPUTS_DIR / "incident_cases.json"
        self.engine = PrivacyPreservingProofEngine(
            merkle_cert_path=self.cert_path,
            incident_cases_path=self.cases_path
        )

    def test_redacted_proof_generation_and_masking(self):
        """Test that IPs and sensitive fields are masked and replaced with commitments."""
        if not self.cert_path.exists():
            self.skipTest("Merkle certificate not found")

        cert = self.engine.generate_privacy_certificate(max_samples_per_incident=2)
        self.assertIn("redacted_intrusion_proofs", cert)
        self.assertGreater(len(cert["redacted_intrusion_proofs"]), 0)

        proof = cert["redacted_intrusion_proofs"][0]
        privacy = proof["privacy_controls"]
        redacted_view = privacy["redacted_canonical_view"]

        # Ensure IPs are redacted in the view
        self.assertIn("[REDACTED]", redacted_view)
        self.assertIn("commitments", privacy)
        self.assertIn("src_ip", privacy["commitments"])
        self.assertIn("commitment_hash", privacy["commitments"]["src_ip"])

    def test_redacted_proof_mathematical_verification(self):
        """Test that redacted proof verifies against session Merkle root without knowing IPs."""
        if not self.cert_path.exists():
            self.skipTest("Merkle certificate not found")

        cert = self.engine.generate_privacy_certificate(max_samples_per_incident=2)
        root = cert["session_merkle_root"]

        for proof in cert["redacted_intrusion_proofs"]:
            is_valid = self.engine.verify_redacted_proof(proof, root)
            self.assertTrue(is_valid, f"Proof for {proof['flow_id']} should recompute to Merkle root")

    def test_redacted_proof_tamper_rejection(self):
        """Test that tampering with leaf hash causes verification failure."""
        if not self.cert_path.exists():
            self.skipTest("Merkle certificate not found")

        cert = self.engine.generate_privacy_certificate(max_samples_per_incident=1)
        proof = cert["redacted_intrusion_proofs"][0]

        # Mutate leaf hash
        mutated_proof = dict(proof)
        mutated_proof["cryptographic_verification"] = dict(proof["cryptographic_verification"])
        mutated_proof["cryptographic_verification"]["leaf_hash"] = "0" * 64

        is_valid = self.engine.verify_redacted_proof(mutated_proof, cert["session_merkle_root"])
        self.assertFalse(is_valid, "Tampered proof must fail verification")

if __name__ == "__main__":
    unittest.main()
