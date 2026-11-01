"""
EviGraph Cryptographic Merkle Evidence Tree & Chain-of-Custody Engine
Adheres to PRD NFR-1 (Integrity) and Forensic Proof-of-Existence:
- Derives deterministic SHA-256 leaves for all network telemetry records
- Constructs a binary Merkle tree yielding an immutable session Root Hash
- Generates O(log N) cryptographic inclusion proofs for any cited flow [E:<flow_id>]
- Provides standalone mathematical verification proving zero fabrication/tampering

Security hardening (v2 scheme):
- Domain separation (RFC 6962 style): leaves are H(0x00 || record), nodes are
  H(0x01 || left || right). Without this, an internal node can be replayed as a
  leaf (second-preimage attack).
- Odd nodes are promoted, not duplicated, avoiding CVE-2012-2459-style tree
  ambiguity.
- Canonical encoding is length-prefixed and distinguishes NULL from the empty
  string, preventing field-boundary collisions.
- Proofs bind tree_size and leaf_index, and verification fails closed when an
  expected root is required.
- Duplicate flow IDs are rejected instead of silently overwriting proofs.
"""

import hashlib
import json
import base64
import os
import math
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Union, Tuple
import pandas as pd
import numpy as np

from src.config import OUTPUTS_DIR
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    CRYPTOGRAPHY_AVAILABLE = True
except Exception:
    CRYPTOGRAPHY_AVAILABLE = False

CANONICAL_FIELDS = [
    "flow_id", "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "timestamp"
]

# v2 is the default for newly built ledgers. "legacy" exists only so historical
# certificates produced before the hardening can still be independently audited.
SCHEME_V2 = "evigraph-merkle-v2"
SCHEME_LEGACY = "legacy"
LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"


def _looks_like_nan(value: Any) -> bool:
    try:
        return isinstance(value, (float, np.floating)) and math.isnan(float(value))
    except (TypeError, ValueError):
        return False


class MerkleEvidenceEngine:
    """
    Hierarchical Merkle Tree Engine for Network Forensic Evidence.
    Ensures that every cited flow ID has a mathematically verifiable proof-of-existence
    anchored to the capture's Merkle Root Hash.
    """
    def __init__(self, scheme: str = SCHEME_V2):
        self.levels: List[List[str]] = []
        self.flow_id_to_index: Dict[str, int] = {}
        self.flow_records_by_id: Dict[str, Dict[str, Any]] = {}
        self.root_hash: str = ""
        self.total_leaves: int = 0
        self.built_at: Optional[str] = None
        self.scheme: str = scheme

    @staticmethod
    def canonical_repr(flow: Dict[str, Any]) -> str:
        """
        Legacy canonical representation, retained for auditing certificates
        generated before the v2 hardening. Do not use for new ledgers.
        """
        parts = []
        for key in CANONICAL_FIELDS:
            val = flow.get(key, "")
            if isinstance(val, (datetime, pd.Timestamp)):
                val_str = val.isoformat()
            elif isinstance(val, (float, np.floating)):
                val_str = f"{val:.6f}".rstrip("0").rstrip(".")
            else:
                val_str = str(val).strip()
            parts.append(f"{key}={val_str}")
        return "|".join(parts)

    @staticmethod
    def canonical_repr_v2(flow: Dict[str, Any]) -> str:
        """
        Deterministic, unambiguous encoding for v2 ledgers.

        Each value is length-prefixed so values containing the separator cannot
        collide, NULL is distinct from "", and floats use round-trippable
        precision instead of a lossy 6-decimal truncation.
        """
        parts = []
        for key in CANONICAL_FIELDS:
            val = flow.get(key, None)
            if val is None or _looks_like_nan(val):
                val_str = "\x00NULL"
            elif isinstance(val, (datetime, pd.Timestamp)):
                val_str = val.isoformat()
            elif isinstance(val, (float, np.floating)):
                val_str = format(float(val), ".17g")
            else:
                val_str = str(val).strip()
            parts.append(f"{key}:{len(val_str)}:{val_str}")
        return "|".join(parts)

    @classmethod
    def compute_leaf_hash(cls, flow: Dict[str, Any], scheme: str = SCHEME_V2) -> str:
        """Computes the SHA-256 leaf digest of a canonical flow record."""
        if scheme == SCHEME_LEGACY:
            payload = cls.canonical_repr(flow).encode("utf-8")
        else:
            payload = LEAF_PREFIX + cls.canonical_repr_v2(flow).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()

    @staticmethod
    def _hash_pair(left_hex: str, right_hex: str, scheme: str) -> str:
        if scheme == SCHEME_LEGACY:
            return hashlib.sha256((left_hex + right_hex).encode("utf-8")).hexdigest()
        # Domain-separated: hash raw 32-byte digests, never hex text.
        payload = NODE_PREFIX + bytes.fromhex(left_hex) + bytes.fromhex(right_hex)
        return hashlib.sha256(payload).hexdigest()

    def build_tree(
        self,
        flows: Union[pd.DataFrame, List[Dict[str, Any]]],
        scheme: str = SCHEME_V2,
    ) -> str:
        """
        Builds a binary Merkle tree across all input network flows.
        Returns the hexadecimal Merkle Root Hash.
        """
        if scheme not in (SCHEME_V2, SCHEME_LEGACY):
            raise ValueError(f"Unsupported Merkle scheme: {scheme}")
        self.scheme = scheme

        if isinstance(flows, pd.DataFrame):
            records = flows.to_dict(orient="records")
        else:
            records = flows

        if not records:
            self.root_hash = hashlib.sha256(b"empty_evigraph_ledger").hexdigest()
            self.levels = [[self.root_hash]]
            self.total_leaves = 0
            self.built_at = datetime.now(timezone.utc).isoformat()
            return self.root_hash

        self.flow_id_to_index.clear()
        self.flow_records_by_id.clear()

        # 1. Compute leaf hashes and reject duplicate flow IDs. A duplicate ID
        # would make a proof ambiguous (one ID mapping to two different records).
        leaves: List[str] = []
        for idx, flow in enumerate(records):
            fid = str(flow.get("flow_id", f"flw_idx_{idx}"))
            if fid in self.flow_id_to_index:
                raise ValueError(
                    f"Duplicate flow_id '{fid}' at records {self.flow_id_to_index[fid]} "
                    f"and {idx}; refusing to build an ambiguous evidence ledger."
                )
            leaf_h = self.compute_leaf_hash(flow, scheme)
            leaves.append(leaf_h)
            self.flow_id_to_index[fid] = idx
            self.flow_records_by_id[fid] = {
                k: flow.get(k) for k in CANONICAL_FIELDS if k in flow
            }

        self.levels = [leaves]
        self.total_leaves = len(leaves)

        # 2. Iteratively construct parent tree levels.
        current_level = leaves
        while len(current_level) > 1:
            next_level: List[str] = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                if i + 1 < len(current_level):
                    right = current_level[i + 1]
                elif scheme == SCHEME_V2:
                    # Odd node is promoted unchanged. Duplicating it (legacy
                    # behaviour) creates two distinct trees with the same root.
                    next_level.append(left)
                    continue
                else:
                    right = left  # legacy compatibility only
                next_level.append(self._hash_pair(left, right, scheme))
            self.levels.append(next_level)
            current_level = next_level

        self.root_hash = self.levels[-1][0]
        self.built_at = datetime.now(timezone.utc).isoformat()
        return self.root_hash

    def get_inclusion_proof(self, flow_id: str) -> Optional[Dict[str, Any]]:
        """
        Generates an O(log N) Merkle Inclusion Proof for a given flow ID.
        Returns sibling hashes and relative branch positions up to the Merkle Root.
        """
        if flow_id not in self.flow_id_to_index:
            return None

        leaf_idx = self.flow_id_to_index[flow_id]
        leaf_hash = self.levels[0][leaf_idx]
        flow_record = self.flow_records_by_id.get(flow_id, {})

        proof_steps: List[Dict[str, str]] = []
        current_idx = leaf_idx

        # Ascend tree levels up to the root level.
        for level_idx in range(len(self.levels) - 1):
            level = self.levels[level_idx]
            is_right_child = (current_idx % 2 == 1)

            if is_right_child:
                sibling_idx = current_idx - 1
                position = "left"
            elif current_idx + 1 < len(level):
                sibling_idx = current_idx + 1
                position = "right"
            elif self.scheme == SCHEME_LEGACY:
                # Legacy trees duplicated the final odd node. Reproduce that so
                # historical proofs remain auditable.
                sibling_idx = current_idx
                position = "right"
            else:
                # Odd node promoted without hashing; no sibling step.
                current_idx //= 2
                continue

            proof_steps.append({
                "sibling_hash": level[sibling_idx],
                "position": position,
            })
            current_idx //= 2

        return {
            "flow_id": flow_id,
            "scheme": self.scheme,
            "leaf_hash": leaf_hash,
            "leaf_index": leaf_idx,
            "tree_size": self.total_leaves,
            "root_hash": self.root_hash,
            "canonical_repr": (
                self.canonical_repr(flow_record)
                if self.scheme == SCHEME_LEGACY
                else self.canonical_repr_v2(flow_record)
            ),
            "proof_steps": proof_steps,
        }

    @classmethod
    def verify_audit_path(
        cls,
        proof: Dict[str, Any],
        expected_root: Optional[str],
        require_expected_root: bool = True,
    ) -> bool:
        """
        Verifies a proof using only its leaf hash and audit path.

        Fail-closed: when ``require_expected_root`` is True, a missing expected
        root is a verification failure. This prevents a self-signed proof from
        certifying its own root.
        """
        if require_expected_root and not expected_root:
            return False
        if not isinstance(proof, dict):
            return False

        scheme = proof.get("scheme", SCHEME_LEGACY)
        if scheme not in (SCHEME_V2, SCHEME_LEGACY):
            return False

        current_hash = str(proof.get("leaf_hash", ""))
        if len(current_hash) != 64:
            return False

        steps = proof.get("proof_steps", [])
        leaf_index = proof.get("leaf_index")
        tree_size = proof.get("tree_size")
        if leaf_index is not None and tree_size is not None:
            if not (0 <= int(leaf_index) < int(tree_size)):
                return False
            # An audit path can never be longer than the tree height + 1.
            if int(tree_size) > 0 and len(steps) > int(tree_size).bit_length():
                return False

        try:
            for step in steps:
                sibling = str(step["sibling_hash"])
                if len(sibling) != 64:
                    return False
                pos = step["position"]
                if pos == "left":
                    current_hash = cls._hash_pair(sibling, current_hash, scheme)
                elif pos == "right":
                    current_hash = cls._hash_pair(current_hash, sibling, scheme)
                else:
                    return False
        except (KeyError, TypeError, ValueError):
            return False

        target_root = expected_root or proof.get("root_hash")
        if not target_root:
            return False
        return current_hash.lower() == str(target_root).lower()

    @classmethod
    def verify_inclusion_proof(
        cls,
        flow_record: Dict[str, Any],
        proof: Dict[str, Any],
        expected_root: Optional[str] = None,
    ) -> bool:
        """
        Mathematically verifies a Merkle Inclusion Proof without requiring the rest of the dataset.
        Reconstructs the parent hashes along the audit path to match the Merkle Root.
        """
        if not isinstance(proof, dict):
            return False

        scheme = proof.get("scheme", SCHEME_LEGACY)
        if scheme not in (SCHEME_V2, SCHEME_LEGACY):
            return False

        computed_leaf = cls.compute_leaf_hash(flow_record, scheme)
        claimed_leaf = proof.get("leaf_hash")
        if not claimed_leaf or computed_leaf != claimed_leaf:
            return False

        # If the proof carries a canonical representation, it must match the
        # record we were handed; otherwise the proof/record pair was mixed.
        if proof.get("canonical_repr"):
            trusted = (
                cls.canonical_repr(flow_record)
                if scheme == SCHEME_LEGACY
                else cls.canonical_repr_v2(flow_record)
            )
            if trusted != proof["canonical_repr"]:
                return False

        return cls.verify_audit_path(
            proof,
            expected_root=expected_root or proof.get("root_hash"),
            require_expected_root=expected_root is not None,
        )

    def _signing_key_paths(self) -> Tuple[Path, Path]:
        private_path = Path(
            os.environ.get("EVIGRAPH_SIGNING_KEY_PATH", str(OUTPUTS_DIR / "merkle_signing_key.pem"))
        )
        public_path = private_path.with_name(private_path.stem + ".public.pem")
        return private_path, public_path

    def _load_or_create_signing_key(self) -> Optional[Any]:
        if not CRYPTOGRAPHY_AVAILABLE:
            return None
        private_path, public_path = self._signing_key_paths()
        if private_path.exists():
            try:
                with private_path.open("rb") as handle:
                    key = serialization.load_pem_private_key(handle.read(), password=None)
                if not public_path.exists():
                    public_bytes = key.public_key().public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo,
                    )
                    public_path.write_bytes(public_bytes)
                return key
            except Exception:
                return None

        key = Ed25519PrivateKey.generate()
        private_bytes = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_bytes = key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        private_path.parent.mkdir(parents=True, exist_ok=True)
        private_path.write_bytes(private_bytes)
        public_path.write_bytes(public_bytes)
        try:
            os.chmod(private_path, 0o600)
        except OSError:
            pass
        return key

    def sign_root(self) -> Dict[str, Any]:
        if not CRYPTOGRAPHY_AVAILABLE or not self.root_hash:
            return {
                "algorithm": "Ed25519",
                "status": "UNAVAILABLE",
                "signature": None,
                "key_id": None,
                "public_key_path": None,
            }
        key = self._load_or_create_signing_key()
        if key is None:
            return {
                "algorithm": "Ed25519",
                "status": "KEY_ERROR",
                "signature": None,
                "key_id": None,
                "public_key_path": None,
            }
        signature = key.sign(self.root_hash.encode("ascii"))
        public_bytes = key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        key_id = hashlib.sha256(public_bytes).hexdigest()[:16]
        _, public_path = self._signing_key_paths()
        return {
            "algorithm": "Ed25519",
            "status": "SIGNED",
            "signature": base64.b64encode(signature).decode("ascii"),
            "key_id": key_id,
            "public_key_path": str(public_path),
        }

    @staticmethod
    def verify_root_signature(certificate: Dict[str, Any], public_key_path: Optional[Path] = None) -> str:
        if not CRYPTOGRAPHY_AVAILABLE:
            return "UNAVAILABLE"
        sig_meta = certificate.get("root_signature")
        if not isinstance(sig_meta, dict) or not sig_meta.get("signature"):
            return "UNSIGNED"
        path = Path(public_key_path or sig_meta.get("public_key_path", ""))
        if not path.exists():
            return "PUBLIC_KEY_MISSING"
        try:
            with path.open("rb") as handle:
                public_key = serialization.load_pem_public_key(handle.read())
            signature = base64.b64decode(sig_meta["signature"], validate=True)
            public_key.verify(signature, str(certificate.get("session_merkle_root", "")).encode("ascii"))
            return "SIGNED_VALID"
        except Exception:
            return "SIGNED_INVALID"

    def export_forensic_certificate(
        self,
        output_path: Optional[Path] = None,
        incident_cases_path: Optional[Path] = None
    ) -> Path:
        """
        Generates and saves the Cryptographic Merkle Certificate linking all cited
        incident evidence flows to the session Merkle Root.
        """
        out_file = Path(output_path or (OUTPUTS_DIR / "forensic_merkle_certificate.json"))
        out_file.parent.mkdir(parents=True, exist_ok=True)

        incident_proofs: Dict[str, List[Dict[str, Any]]] = {}
        unanchored: Dict[str, List[str]] = {}

        if incident_cases_path and Path(incident_cases_path).exists():
            with open(incident_cases_path, "r") as f:
                case_bundle = json.load(f)

            for inc in case_bundle.get("incidents", []):
                inc_id = inc.get("incident_id", "INC-0000")
                proofs_list = []
                missing = []
                for fid in inc.get("evidence_flow_ids", []):
                    proof = self.get_inclusion_proof(fid)
                    if proof:
                        proofs_list.append(proof)
                    else:
                        missing.append(fid)
                incident_proofs[inc_id] = proofs_list
                if missing:
                    unanchored[inc_id] = missing

        certificate = {
            "version": "2.0",
            "standard": (
                "Domain-separated binary Merkle audit path "
                "(RFC 6962 construction: 0x00 leaf / 0x01 node)"
            ),
            "merkle_scheme": self.scheme,
            "hash_algorithm": "SHA-256",
            "session_merkle_root": self.root_hash,
            "total_telemetry_leaves": self.total_leaves,
            "tree_depth": len(self.levels),
            "generated_at": self.built_at or datetime.now(timezone.utc).isoformat(),
            "incident_evidence_proofs": incident_proofs,
            "unanchored_evidence_ids": unanchored,
            "root_signature": self.sign_root(),
        }

        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(certificate, f, indent=2)

        print(f"[MerkleEngine] Cryptographic Certificate exported to: {out_file}")
        print(f"               Root Hash: {self.root_hash}")
        print(f"               Evidence Proofs Anchored: {sum(len(p) for p in incident_proofs.values())}")
        if unanchored:
            print(f"               [!] WARNING: unanchored evidence IDs: {unanchored}")
        return out_file

    def enrich_incident_case_package(self, incident_cases_path: Path) -> Path:
        """
        Enriches outputs/incident_cases.json with session Merkle Root and proof metadata.
        A proof is only marked verified after it is actually recomputed against the
        session root; the full audit path is embedded for independent replay.
        """
        if not Path(incident_cases_path).exists():
            return incident_cases_path

        with open(incident_cases_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        data["merkle_root"] = self.root_hash
        data["merkle_leaves_count"] = self.total_leaves
        data["merkle_scheme"] = self.scheme
        data["cryptographic_standard"] = (
            "SHA-256 domain-separated binary Merkle tree (RFC 6962-style)"
        )

        verified_count = 0
        unanchored: List[str] = []
        for inc in data.get("incidents", []):
            subgraph = inc.get("subgraph", {})
            for edge in subgraph.get("edges", []):
                eid = edge.get("edge_id")
                if not eid:
                    continue
                proof = self.get_inclusion_proof(eid)
                if proof and self.verify_audit_path(proof, self.root_hash):
                    edge["merkle_leaf_hash"] = proof["leaf_hash"]
                    edge["merkle_proof"] = proof
                    edge["merkle_verified"] = True
                    edge["merkle_scheme"] = self.scheme
                    verified_count += 1
                else:
                    edge["merkle_verified"] = False
                    edge["merkle_verification_error"] = "NO_PROOF_FOR_EDGE_ID"
                    unanchored.append(eid)

        data["merkle_verified_edges"] = verified_count
        data["merkle_unanchored_edges"] = unanchored

        with open(incident_cases_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

        print(
            f"[MerkleEngine] Enriched case package: {verified_count} verified edges, "
            f"{len(unanchored)} unanchored"
        )
        return incident_cases_path
