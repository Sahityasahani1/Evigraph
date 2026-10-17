"""
EviGraph Cryptographic Integrity & Evidence Ledger Package
Implements binary Merkle trees, inclusion proofs, and tamper-proof chain-of-custody.
"""

from .merkle_engine import MerkleEvidenceEngine
from .privacy_proofs import PrivacyPreservingProofEngine

__all__ = ["MerkleEvidenceEngine", "PrivacyPreservingProofEngine"]
