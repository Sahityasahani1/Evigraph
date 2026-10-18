"""
EviGraph Data & Traffic Pipeline (Member 1)
Core package handling telemetry ingestion, normalization, anti-leakage feature extraction,
evidence integrity, Parquet storage, and DuckDB analytical query services.
"""

from data.adapters import export_member2
from data.config import CANONICAL_FEATURES, FEATURE_COLUMNS, DataPipelineSettings, settings
from data.evidence import (
    AuditLogger,
    EvidenceRecord,
    EvidenceStore,
    IntegrityError,
    compute_file_sha256,
    register_evidence,
    verify_chain,
)
from data.features import FlowFeatureExtractor, HostFeatureExtractor
from data.flow_id import (
    assign_flow_ids,
    compute_flow_5tuple_str,
    generate_flow_id,
    make_flow_ids,
)
from data.query import QueryAPI
from data.schema import (
    CANONICAL_ARROW_SCHEMA,
    CANONICAL_SCHEMA,
    FEAT_COLUMNS,
    MEMBER2_FEATURES,
    canonicalize,
    validate,
    validate_and_canonicalize,
)
from data.storage import DuckDBCatalog, ParquetStorageEngine

__all__ = [
    "DataPipelineSettings",
    "settings",
    "generate_flow_id",
    "make_flow_ids",
    "assign_flow_ids",
    "compute_flow_5tuple_str",
    "compute_file_sha256",
    "AuditLogger",
    "EvidenceRecord",
    "EvidenceStore",
    "IntegrityError",
    "register_evidence",
    "verify_chain",
    "CANONICAL_SCHEMA",
    "CANONICAL_ARROW_SCHEMA",
    "CANONICAL_FEATURES",
    "FEATURE_COLUMNS",
    "MEMBER2_FEATURES",
    "FEAT_COLUMNS",
    "validate",
    "canonicalize",
    "validate_and_canonicalize",
    "FlowFeatureExtractor",
    "HostFeatureExtractor",
    "ParquetStorageEngine",
    "DuckDBCatalog",
    "QueryAPI",
    "export_member2",
]
