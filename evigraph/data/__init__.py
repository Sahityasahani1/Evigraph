"""
EviGraph Data & Traffic Pipeline (Member 1)
Core package handling telemetry ingestion, normalization, anti-leakage feature extraction,
evidence integrity, Parquet storage, and DuckDB analytical query services.
"""

from evigraph.data.config import DataPipelineSettings, settings
from evigraph.data.evidence import (
    AuditLogger,
    EvidenceRecord,
    EvidenceStore,
    IntegrityError,
    compute_file_sha256,
    register_evidence,
    verify_chain,
)
from evigraph.data.features import FlowFeatureExtractor, HostFeatureExtractor
from evigraph.data.flow_id import (
    assign_flow_ids,
    compute_flow_5tuple_str,
    generate_flow_id,
    make_flow_ids,
)
from evigraph.data.query import QueryAPI
from evigraph.data.schema import (
    CANONICAL_ARROW_SCHEMA,
    CANONICAL_SCHEMA,
    FEAT_COLUMNS,
    MEMBER2_FEATURES,
    canonicalize,
    validate,
    validate_and_canonicalize,
)
from evigraph.data.storage import DuckDBCatalog, ParquetStorageEngine

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
]
