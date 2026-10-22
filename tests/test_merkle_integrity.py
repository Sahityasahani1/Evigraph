"""
Unit Tests for EviGraph Cryptographic Merkle Evidence Tree & Inclusion Proofs
Tests:
1. Deterministic leaf hashing and canonical representation
2. Binary Merkle tree construction & root consistency
3. O(log N) Merkle inclusion proof generation and verification
4. Anti-tampering defense: detection of single-bit perturbations in flow fields
5. Cryptographic Certificate generation and verification
"""

import unittest
import json
from pathlib import Path

from src.integrity.merkle_engine import MerkleEvidenceEngine
from src.config import OUTPUTS_DIR

class TestMerkleEvidenceEngine(unittest.TestCase):
    def setUp(self):
        self.engine = MerkleEvidenceEngine()
        self.sample_flows = [
            {
                "flow_id": "flw_recon_001",
                "src_ip": "172.16.0.105",
                "dst_ip": "192.168.10.50",
                "src_port": 49201,
                "dst_port": 22,
                "protocol": 6,
                "timestamp": "2026-10-15T09:12:00"
            },
            {
                "flow_id": "flw_recon_002",
                "src_ip": "172.16.0.105",
                "dst_ip": "192.168.10.50",
                "src_port": 49202,
                "dst_port": 80,
                "protocol": 6,
                "timestamp": "2026-10-15T09:12:01"
            },
            {
                "flow_id": "flw_recon_003",
                "src_ip": "172.16.0.105",
                "dst_ip": "192.168.10.50",
                "src_port": 49203,
                "dst_port": 443,
                "protocol": 6,
                "timestamp": "2026-10-15T09:12:02"
            },
            {
                "flow_id": "flw_recon_004",
                "src_ip": "172.16.0.105",
                "dst_ip": "192.168.10.50",
                "src_port": 49204,
                "dst_port": 8080,
                "protocol": 6,
                "timestamp": "2026-10-15T09:12:03"
            },
            {
                "flow_id": "flw_recon_005",
                "src_ip": "172.16.0.105",
                "dst_ip": "192.168.10.50",
                "src_port": 49205,
                "dst_port": 3389,
                "protocol": 6,
                "timestamp": "2026-10-15T09:12:04"
            }
        ]

    def test_canonical_representation_determinism(self):
        f1 = dict(self.sample_flows[0])
        f2 = dict(self.sample_flows[0])
        # Re-order dict keys
        f2_reordered = {k: f2[k] for k in reversed(list(f2.keys()))}

        repr1 = self.engine.canonical_repr(f1)
        repr2 = self.engine.canonical_repr(f2_reordered)
        self.assertEqual(repr1, repr2)

        leaf1 = self.engine.compute_leaf_hash(f1)
        leaf2 = self.engine.compute_leaf_hash(f2_reordered)
        self.assertEqual(leaf1, leaf2)
        self.assertEqual(len(leaf1), 64)  # 64 hex chars for SHA-256

    def test_tree_construction_and_root(self):
        root = self.engine.build_tree(self.sample_flows)
        self.assertEqual(root, self.engine.root_hash)
        self.assertEqual(len(root), 64)
        self.assertEqual(self.engine.total_leaves, 5)
        # Tree with 5 leaves has depth 4 (5 -> 3 -> 2 -> 1)
        self.assertEqual(len(self.engine.levels), 4)

    def test_inclusion_proof_valid_flow(self):
        root = self.engine.build_tree(self.sample_flows)
        target_flow = self.sample_flows[2]
        fid = target_flow["flow_id"]

        proof = self.engine.get_inclusion_proof(fid)
        self.assertIsNotNone(proof)
        self.assertEqual(proof["flow_id"], fid)
        self.assertEqual(proof["root_hash"], root)

        # Independent mathematical verification
        is_valid = self.engine.verify_inclusion_proof(target_flow, proof, root)
        self.assertTrue(is_valid, "Merkle inclusion proof verification failed for genuine flow")

    def test_anti_tampering_defense(self):
        """Verify that altering any single field in the flow causes proof verification to fail."""
        root = self.engine.build_tree(self.sample_flows)
        genuine_flow = self.sample_flows[0]
        proof = self.engine.get_inclusion_proof(genuine_flow["flow_id"])

        # Tamper 1: Alter port number (22 -> 2222)
        tampered_flow_port = dict(genuine_flow)
        tampered_flow_port["dst_port"] = 2222
        self.assertFalse(
            self.engine.verify_inclusion_proof(tampered_flow_port, proof, root),
            "Tampered port should have invalidated Merkle proof!"
        )

        # Tamper 2: Alter timestamp by 1 second
        tampered_flow_ts = dict(genuine_flow)
        tampered_flow_ts["timestamp"] = "2026-10-15T09:12:01"
        self.assertFalse(
            self.engine.verify_inclusion_proof(tampered_flow_ts, proof, root),
            "Tampered timestamp should have invalidated Merkle proof!"
        )

        # Tamper 3: Alter IP address
        tampered_flow_ip = dict(genuine_flow)
        tampered_flow_ip["src_ip"] = "192.168.1.1"
        self.assertFalse(
            self.engine.verify_inclusion_proof(tampered_flow_ip, proof, root),
            "Tampered IP should have invalidated Merkle proof!"
        )

    def test_forensic_certificate_generation(self):
        self.engine.build_tree(self.sample_flows)
        cert_path = OUTPUTS_DIR / "test_merkle_certificate.json"
        res_file = self.engine.export_forensic_certificate(output_path=cert_path)
        self.assertTrue(res_file.exists())

        with open(res_file, "r") as f:
            cert_data = json.load(f)

        self.assertEqual(cert_data["session_merkle_root"], self.engine.root_hash)
        self.assertEqual(cert_data["total_telemetry_leaves"], 5)
        self.assertEqual(cert_data["hash_algorithm"], "SHA-256")

if __name__ == "__main__":
    unittest.main()
