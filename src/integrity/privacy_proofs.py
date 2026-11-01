"""
EviGraph Privacy-Preserving Redacted Proof Engine (topology-redacted intrusion proofs)
Adheres to SEC Item 1.05, GDPR Art. 33, and Cyber Insurance Claim Standards:
- Generates mathematically sound Merkle inclusion proofs while redacting confidential fields
- Protects internal IP architecture, subnet topology, and proprietary host roles
- Uses salted HMAC commitments allowing selective, post-hoc disclosure under key custody
- Enables external underwriters and regulators to verify authentic intrusion existence
  without receiving internal enterprise network topology

This is a commitment scheme, not a zero-knowledge proof system. Confidentiality
depends on custody of the disclosure key; low-entropy fields can be brute-forced
by anyone who holds that key.
"""

import os
import sys
import json
import secrets
import hashlib
import hmac
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Set, Any, Optional, Tuple

from src.config import OUTPUTS_DIR
from src.integrity.merkle_engine import (
    MerkleEvidenceEngine,
    CANONICAL_FIELDS,
    SCHEME_V2,
)

# Topology/service information is redacted by default. dst_port is included
# because it fingerprints exposed services even when the IP is hidden.
DEFAULT_REDACTED_FIELDS = ["src_ip", "dst_ip", "src_port", "dst_port"]

class PrivacyPreservingProofEngine:
    """
    Generates and verifies privacy-preserving, redacted intrusion proofs anchored to Merkle roots.
    """
    def __init__(
        self,
        merkle_cert_path: Optional[Path] = None,
        incident_cases_path: Optional[Path] = None
    ):
        self.cert_path = Path(merkle_cert_path or (OUTPUTS_DIR / "forensic_merkle_certificate.json"))
        self.cases_path = Path(incident_cases_path or (OUTPUTS_DIR / "incident_cases.json"))

        self.merkle_cert: Dict[str, Any] = {}
        self.cases_data: Dict[str, Any] = {}
        self.evidence_lookup: Dict[str, Dict[str, Any]] = {}
        self._last_disclosure_secret: str = ""
        self._key_was_generated: bool = False

        self.load_data()

    def load_data(self):
        """Loads Merkle certificate and case bundles."""
        if self.cert_path.exists():
            with open(self.cert_path, "r", encoding="utf-8") as f:
                self.merkle_cert = json.load(f)

        if self.cases_path.exists():
            with open(self.cases_path, "r", encoding="utf-8") as f:
                self.cases_data = json.load(f)

            for inc in self.cases_data.get("incidents", []):
                subgraph = inc.get("subgraph", {})
                for edge in subgraph.get("edges", []):
                    eid = edge.get("edge_id")
                    if eid:
                        self.evidence_lookup[eid] = {
                            "incident_id": inc.get("incident_id"),
                            "predicted_class": edge.get("predicted_class"),
                            "risk_score": edge.get("risk_score"),
                            "timestamp": edge.get("timestamp"),
                            "protocol": edge.get("protocol"),
                            "dst_port": edge.get("dst_port")
                        }

    @staticmethod
    def _parse_canonical(canonical_repr: str, scheme: str) -> List[tuple]:
        """Parse a legacy ``k=v`` or v2 ``k:len:v`` canonical string."""
        if not canonical_repr:
            return []
        if scheme == "legacy":
            return [p.split("=", 1) for p in canonical_repr.split("|") if "=" in p]

        pairs: List[tuple] = []
        i = 0
        n = len(canonical_repr)
        while i < n:
            key_end = canonical_repr.find(":", i)
            if key_end < 0:
                break
            len_end = canonical_repr.find(":", key_end + 1)
            if len_end < 0:
                break
            key = canonical_repr[i:key_end]
            try:
                value_len = int(canonical_repr[key_end + 1:len_end])
            except ValueError:
                break
            start = len_end + 1
            value = canonical_repr[start:start + value_len]
            if value == "\x00NULL":
                value = ""
            pairs.append((key, value))
            i = start + value_len
            if i < n and canonical_repr[i] == "|":
                i += 1
        return pairs

    def generate_redacted_proof(
        self,
        proof_record: Dict[str, Any],
        redact_fields: Optional[List[str]] = None,
        disclosure_secret: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Transforms an unredacted Merkle proof into a privacy-preserving redacted proof.
        Redacted fields are replaced with HMAC commitments using an enterprise secret.
        """
        to_redact = set(redact_fields or DEFAULT_REDACTED_FIELDS)
        secret = (disclosure_secret or secrets.token_hex(32)).encode("utf-8")

        scheme = proof_record.get("scheme", "legacy")
        canonical_repr = proof_record.get("canonical_repr", "")
        pairs = self._parse_canonical(canonical_repr, scheme)

        redacted_pairs = []
        commitments = {}

        for k, v in pairs:
            if k in to_redact:
                # Salted HMAC commitment. The salt prevents cross-certificate
                # rainbow tables; the secret (never shipped in this artifact)
                # is what actually prevents offline enumeration.
                salt = secrets.token_hex(16)
                h = hmac.new(
                    secret,
                    f"{k}\x00{v}\x00{salt}".encode("utf-8"),
                    hashlib.sha256,
                ).hexdigest()
                commitments[k] = {
                    "commitment_hash": h,
                    "salt": salt,
                    "field_redacted": True,
                    "pseudonym": f"[REDACTED_{k.upper()}_{h[:8]}]"
                }
                redacted_pairs.append(f"{k}=[REDACTED]")
            else:
                redacted_pairs.append(f"{k}={v}")

        fid = proof_record.get("flow_id")
        enrichment = self.evidence_lookup.get(fid, {})
        canonical_map = dict(pairs)
        timestamp = (
            enrichment.get("timestamp")
            or canonical_map.get("timestamp")
            or None
        )

        return {
            "flow_id": fid,
            "incident_id": enrichment.get("incident_id", "INC-EXTERNAL"),
            "threat_classification": {
                "attack_class": enrichment.get("predicted_class", "Anomalous"),
                "risk_score": enrichment.get("risk_score"),
                "protocol": enrichment.get("protocol"),
                "timestamp": timestamp,
            },
            "privacy_controls": {
                "redacted_fields": list(to_redact),
                "commitments": commitments,
                "redacted_canonical_view": "|".join(redacted_pairs)
            },
            "cryptographic_verification": {
                "leaf_hash": proof_record.get("leaf_hash"),
                "leaf_index": proof_record.get("leaf_index"),
                "tree_size": proof_record.get("tree_size"),
                "root_hash": proof_record.get("root_hash"),
                "scheme": scheme,
                "proof_steps": proof_record.get("proof_steps", [])
            }
        }

    def generate_privacy_certificate(
        self,
        redact_fields: Optional[List[str]] = None,
        max_samples_per_incident: int = 5
    ) -> Dict[str, Any]:
        """
        Compiles an enterprise Privacy-Preserving Proof Certificate across incidents.
        Can be safely disclosed to insurance underwriters, regulatory auditors, or closed courts.
        """
        session_root = self.merkle_cert.get("session_merkle_root", "")
        incident_proofs_map = self.merkle_cert.get("incident_evidence_proofs", {})

        redacted_proofs = []
        # The disclosure secret is a key-management asset, NOT evidence. It is
        # deliberately never serialized into the certificate (see run()).
        env_secret = os.environ.get("EVIGRAPH_DISCLOSURE_SECRET", "").strip()
        disclosure_secret = env_secret or secrets.token_hex(32)
        self._key_was_generated = not bool(env_secret)
        self._last_disclosure_secret = disclosure_secret
        key_id = hashlib.sha256(disclosure_secret.encode("utf-8")).hexdigest()[:16]

        for inc_id, proofs_list in incident_proofs_map.items():
            sample_proofs = proofs_list[:max_samples_per_incident]
            for p in sample_proofs:
                r_proof = self.generate_redacted_proof(
                    proof_record=p,
                    redact_fields=redact_fields,
                    disclosure_secret=disclosure_secret
                )
                redacted_proofs.append(r_proof)

        certificate = {
            "version": "2.0",
            "standard": "EviGraph Privacy-Preserving Merkle Proof-of-Intrusion (redacted commitments)",
            "compliance": ["SEC Item 1.05 Breach Disclosure", "GDPR Art. 33(3)", "ISO/IEC 27037:2012"],
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "session_merkle_root": session_root,
            "total_leaves_anchored": self.merkle_cert.get("total_telemetry_leaves", 0),
            "redacted_evidence_count": len(redacted_proofs),
            "selective_disclosure": {
                "key_included_in_certificate": False,
                "key_id": key_id,
                "key_management": (
                    "Set EVIGRAPH_DISCLOSURE_SECRET in a secret manager. If no secret "
                    "is supplied, run() generates one and writes it locally to "
                    "outputs/privacy_disclosure_key.secret with 0600 permissions. "
                    "The key must never be distributed with the certificate."
                ),
                "limitations": (
                    "This is a salted HMAC commitment scheme, not a zero-knowledge "
                    "proof. Anyone holding the disclosure key can test low-entropy "
                    "field guesses (e.g. an IPv4 address)."
                ),
            },
            "redacted_intrusion_proofs": redacted_proofs
        }

        return certificate

    @staticmethod
    def verify_commitment(
        field_name: str,
        value: str,
        commitment: Dict[str, Any],
        disclosure_secret: str,
    ) -> bool:
        """Recomputes a salted HMAC commitment for a disclosed field value."""
        if not disclosure_secret:
            return False
        salt = commitment.get("salt", "")
        expected = commitment.get("commitment_hash", "")
        actual = hmac.new(
            disclosure_secret.encode("utf-8"),
            f"{field_name}\x00{value}\x00{salt}".encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return hmac.compare_digest(actual, expected)

    @staticmethod
    def verify_redacted_proof(
        redacted_proof: Dict[str, Any],
        expected_root: str,
    ) -> bool:
        """
        Verifies that a redacted proof mathematically recomputes to the session
        Merkle root WITHOUT knowing or unmasking the redacted fields.

        Fail-closed: ``expected_root`` is mandatory. A proof must never be
        allowed to certify its own claimed root.
        """
        if not expected_root:
            return False

        crypto = redacted_proof.get("cryptographic_verification", {})
        leaf_hash = crypto.get("leaf_hash", "")
        proof_steps = crypto.get("proof_steps", [])

        if not leaf_hash:
            return False

        proof = {
            "leaf_hash": leaf_hash,
            "leaf_index": crypto.get("leaf_index"),
            "tree_size": crypto.get("tree_size"),
            "scheme": crypto.get("scheme", "legacy"),
            "proof_steps": proof_steps,
        }
        return MerkleEvidenceEngine.verify_audit_path(
            proof, expected_root, require_expected_root=True
        )

    def run(
        self,
        output_cert_path: Optional[Path] = None
    ) -> Path:
        """
        Generates and verifies Privacy-Preserving Intrusion Proof Certificate.
        """
        print("=" * 65)
        print("   EVIGRAPH: PRIVACY-PRESERVING REDACTED PROOF ENGINE (USP)")
        print("   SEC Item 1.05 / GDPR Art. 33 Topology-Redacted Proofs")
        print("=" * 65)

        cert = self.generate_privacy_certificate()
        out_path = Path(output_cert_path or (OUTPUTS_DIR / "privacy_preserving_proof_certificate.json"))
        out_path.parent.mkdir(parents=True, exist_ok=True)

        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(cert, f, indent=2)

        # Key material is separated from the distributable evidence artifact.
        # If the secret came from a secret manager, do not copy it to disk.
        key_path = out_path.parent / "privacy_disclosure_key.secret"
        if self._key_was_generated:
            with open(key_path, "w", encoding="utf-8") as f:
                f.write(self._last_disclosure_secret)
            try:
                os.chmod(key_path, 0o600)
            except OSError:
                pass
            print(
                f"[PrivacyProofEngine] [!] Generated disclosure key written separately to {key_path} "
                "(0600). Never ship it with the certificate."
            )
        else:
            print(
                "[PrivacyProofEngine] Disclosure key supplied via environment; "
                "no key file was written."
            )

        print(f"\n[PrivacyProofEngine] Privacy Certificate generated: {out_path}")
        print(f"[PrivacyProofEngine] Session Root: {cert['session_merkle_root']}")
        print(f"[PrivacyProofEngine] Redacted Proofs Anchored: {cert['redacted_evidence_count']}")

        # Independent audit verification test
        print("\n--- Verifying Redacted Proofs without Revealing IPs ---")
        root = cert["session_merkle_root"]
        all_passed = True
        for idx, proof in enumerate(cert["redacted_intrusion_proofs"]):
            fid = proof["flow_id"]
            ok = self.verify_redacted_proof(proof, root)
            if not ok:
                all_passed = False
                print(f"  [!] Flow {fid} FAILED verification!")

        if all_passed:
            print(f"[PrivacyProofEngine] 100% of redacted proofs recompute to the session Merkle root.")
            print(
                "                     Note: this is a commitment proof, not a "
                "zero-knowledge proof; confidentiality depends on key custody."
            )

        return out_path

if __name__ == "__main__":
    engine = PrivacyPreservingProofEngine()
    engine.run()
