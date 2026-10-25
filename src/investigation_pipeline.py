"""Fresh flow-file inference using EviGraph's existing detectors and case engines."""

import hashlib
from ipaddress import ip_address
import json
from pathlib import Path
from typing import Callable

import numpy as np
import pandas as pd

from src.baseline_detector import BaselineDetector
from src.causal_provenance import CausalProvenanceEngine
from src.config import MODELS_DIR
from src.data_loader import FlowDataLoader
from src.graph_engine import HostGraphEngine
from src.incident_cluster import IncidentClusterEngine
from src.integrity.merkle_engine import MerkleEvidenceEngine

ProgressCallback = Callable[[str, int], None]


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_flows(path: Path, source_sha256: str) -> pd.DataFrame:
    suffix = path.suffix.lower()
    evidence_id = f"evidence_{source_sha256[:16]}"
    if suffix in {".pcap", ".pcapng"}:
        from data.parsers.pcap import parse_pcap

        flows = parse_pcap(path, evidence_id=evidence_id, evidence_sha256=source_sha256)
        if flows.empty:
            raise ValueError("The capture contains no supported IP flows.")
        for column in list(flows.columns):
            if column.startswith("feat_"):
                feature = column.removeprefix("feat_")
                if feature not in flows.columns:
                    flows[feature] = flows[column]
        flows["timestamp"] = flows["ts_start"]
    elif suffix in {".csv", ".parquet"}:
        flows = FlowDataLoader().load_dataset(path, drop_missing=False)
        if "timestamp" not in flows and "ts_start" in flows:
            flows["timestamp"] = flows["ts_start"]
        for column in list(flows.columns):
            if column.startswith("feat_"):
                feature = column.removeprefix("feat_")
                if feature not in flows.columns:
                    flows[feature] = flows[column]
    else:
        raise ValueError(
            "Unsupported input format. Use a flow CSV, flow Parquet, PCAP, or PCAPNG file."
        )

    required_metadata = {
        "timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
    }
    missing = sorted(required_metadata - set(flows.columns))
    if missing:
        raise ValueError(f"Input is missing required flow metadata columns: {missing}.")

    missing_flow_ids = (
        flows["flow_id"].isna()
        | flows["flow_id"].astype("string").str.strip().eq("").fillna(True)
        if "flow_id" in flows.columns else None
    )
    if "flow_id" not in flows.columns or missing_flow_ids.any():
        from data.flow_id import assign_flow_ids

        flows = assign_flow_ids(flows, evidence_sha256=source_sha256, overwrite=True)
    flows["flow_id"] = flows["flow_id"].astype(str)
    if flows["flow_id"].duplicated().any():
        raise ValueError("Input flow_id values must be unique.")

    if "evidence_id" not in flows.columns:
        flows["evidence_id"] = evidence_id
    else:
        flows["evidence_id"] = flows["evidence_id"].fillna(evidence_id).astype(str)
        flows.loc[flows["evidence_id"].str.strip().eq(""), "evidence_id"] = evidence_id

    timestamps = pd.to_datetime(flows["timestamp"], format="mixed", utc=True, errors="coerce")
    if timestamps.isna().any():
        raise ValueError("Input contains missing or invalid flow timestamps.")
    flows["timestamp"] = timestamps
    for column in ("src_port", "dst_port", "protocol"):
        flows[column] = pd.to_numeric(flows[column], errors="coerce")
        if flows[column].isna().any():
            raise ValueError(f"Input contains missing or invalid {column} values.")
        values = flows[column].to_numpy(dtype=float)
        if not np.isfinite(values).all() or not np.equal(values, np.floor(values)).all():
            raise ValueError(f"Input contains non-integer or invalid {column} values.")
        upper = 255 if column == "protocol" else 65535
        if (values < 0).any() or (values > upper).any():
            raise ValueError(f"Input {column} values must be in range [0, {upper}].")
    for column in ("src_ip", "dst_ip"):
        endpoints = flows[column].astype("string").str.strip()
        if endpoints.isna().any() or endpoints.eq("").any():
            raise ValueError(f"Input contains missing or invalid {column} values.")
        try:
            endpoints.map(ip_address)
        except ValueError as exc:
            raise ValueError(f"Input contains malformed {column} values; expected IP addresses.") from exc
        flows[column] = endpoints.astype(str)
    flows["source_sha256"] = source_sha256
    return flows


def _detector_features(flows: pd.DataFrame, expected: list[str]) -> pd.DataFrame:
    missing = [column for column in expected if column not in flows.columns]
    if missing:
        raise ValueError(
            "Input feature schema does not match the loaded detector. "
            f"Missing required features: {missing}."
        )
    features = flows.loc[:, expected].copy()
    for column in expected:
        converted = pd.to_numeric(features[column], errors="coerce")
        malformed = features[column].notna() & converted.isna()
        if malformed.any():
            raise ValueError(
                f"Input contains non-numeric values in detector feature {column!r}."
            )
        features[column] = converted
    features = features.replace([np.inf, -np.inf], np.nan).fillna(0.0)
    if features.empty:
        raise ValueError("Input contains no flows to score.")
    return features


def run_investigation_pipeline(
    input_path: str | Path,
    output_dir: str | Path,
    model_type: str = "auto",
    progress: ProgressCallback | None = None,
) -> dict:
    """Run inference and case construction on one uploaded flow file or capture."""
    source_path = Path(input_path)
    target_dir = Path(output_dir)
    req_model = (model_type or "auto").strip().lower()
    if req_model not in {"auto", "xgb", "gnn"}:
        raise ValueError("Detector must be 'auto', 'xgb', or 'gnn'.")
    if not source_path.is_file():
        raise FileNotFoundError(f"Input file not found: {source_path}")
    target_dir.mkdir(parents=True, exist_ok=True)
    update = progress or (lambda _message, _percent: None)

    # Check for missing model directory or baseline artifact early
    xgb_artifact = MODELS_DIR / "xgboost_baseline.joblib"
    gnn_migrated = MODELS_DIR / "gnn_edge_sage.migrated-legacy-v2.pt"
    gnn_pt = MODELS_DIR / "gnn_edge_sage.pt"
    if req_model == "xgb" and not xgb_artifact.is_file():
        raise FileNotFoundError(f"XGBoost model artifact not found at {xgb_artifact}")
    if req_model == "gnn" and not gnn_migrated.is_file() and not gnn_pt.is_file():
        raise FileNotFoundError(f"GNN model artifact not found at {gnn_pt}")
    if req_model == "auto" and not xgb_artifact.is_file() and not gnn_migrated.is_file() and not gnn_pt.is_file():
        raise FileNotFoundError(f"Model artifacts not found in {MODELS_DIR} (missing {xgb_artifact.name})")

    update("Hashing input", 5)
    source_sha256 = sha256_file(source_path)
    update("Parsing and normalizing flows", 15)
    flows = _load_flows(source_path, source_sha256)

    metadata_columns = [
        "flow_id", "evidence_id", "timestamp", "src_ip", "dst_ip",
        "src_port", "dst_port", "protocol", "source_sha256",
    ]
    metadata = flows.loc[:, metadata_columns].copy()
    # Ground-truth labels, if present in a source dataset, are intentionally excluded.
    metadata = metadata.drop(columns=["label"], errors="ignore")

    from src.detector_selector import select_detector

    selection = select_detector(
        flows,
        metadata,
        requested=req_model,
        models_dir=MODELS_DIR,
        baseline_cls=BaselineDetector,
    )
    selected_detector = selection.selected_detector
    selection_reason = selection.selection_reason
    fallback_reason = selection.fallback_reason

    update(f"Loading {selected_detector.upper()} checkpoint", 30)
    if selected_detector == "gnn":
        from src.gnn_detector import GNNDetector

        detector = GNNDetector(model_name="gnn_edge_sage")
        checkpoint_path = gnn_migrated if gnn_migrated.is_file() else gnn_pt
        detector.load(checkpoint_path)
        if detector.migration_metadata:
            # Fresh inference is supported, while temporal evaluation remains unverified.
            detector_label = "gnn_legacy_migrated"
            temporal_isolation_verified = False
        else:
            detector.validate_inference_split(metadata)
            detector_label = "gnn"
            temporal_isolation_verified = True
        expected_features = detector.builder.feature_columns
    else:
        detector = BaselineDetector(model_name="xgboost_baseline")
        detector.load(MODELS_DIR)
        expected_features = detector.feature_columns
        detector_label = "xgb"
        temporal_isolation_verified = False

    features = _detector_features(flows, expected_features)
    update("Running fresh flow inference", 50)
    scored = detector.score_flows(features, metadata)

    scored["source_sha256"] = source_sha256
    alerts = scored.loc[scored["is_alert"].astype(bool)].copy()
    update(f"Building host graph and correlating {len(alerts)} alerts", 65)
    graph_engine = HostGraphEngine()
    graph_engine.build_graph_from_flows(scored)
    incident_engine = IncidentClusterEngine()
    incidents = incident_engine.correlate_alerts(alerts)
    for incident in incidents:
        incident["source_sha256"] = source_sha256
        incident["detection_model"] = selected_detector
        incident["detector_label"] = detector_label
        incident["requested_detector"] = req_model
        incident["selection_reason"] = selection_reason
        incident["fallback_reason"] = fallback_reason
        incident["inference_source"] = "fresh"

    flows_path = target_dir / "scored_flows.parquet"
    scored.to_parquet(flows_path, index=False)
    cases_path = incident_engine.export_agent_case_bundle(
        incidents, graph_engine, target_dir / "incident_cases.json"
    )
    merkle_engine = MerkleEvidenceEngine()
    merkle_root = merkle_engine.build_tree(scored)
    merkle_engine.enrich_incident_case_package(cases_path)
    certificate_path = merkle_engine.export_forensic_certificate(
        output_path=target_dir / "forensic_merkle_certificate.json",
        incident_cases_path=cases_path,
    )
    update("Reconstructing temporal attack chains", 78)
    CausalProvenanceEngine().enrich_incident_case_package(cases_path)

    package = json.loads(cases_path.read_text(encoding="utf-8"))
    package["provenance"] = {
        "inference_source": "fresh",
        "input_filename": source_path.name,
        "input_sha256": source_sha256,
        "input_format": source_path.suffix.lower().lstrip("."),
        "detector": selected_detector,
        "requested_detector": req_model,
        "selected_detector": selected_detector,
        "selection_reason": selection_reason,
        "fallback_reason": fallback_reason,
        "detector_label": detector_label,
        "temporal_isolation_verified": temporal_isolation_verified,
        "flows_scored": len(scored),
        "alerts": len(alerts),
        "labels_used_for_inference": False,
        "merkle_root": merkle_root,
        "merkle_certificate": certificate_path.name,
    }
    cases_path.write_text(json.dumps(package, indent=2, default=str), encoding="utf-8")

    update("Fresh detection and incident construction complete", 90)
    return {
        "source_sha256": source_sha256,
        "input_filename": source_path.name,
        "input_format": source_path.suffix.lower().lstrip("."),
        "model_type": selected_detector,
        "requested_detector": req_model,
        "selected_detector": selected_detector,
        "selection_reason": selection_reason,
        "fallback_reason": fallback_reason,
        "detector_label": detector_label,
        "temporal_isolation_verified": temporal_isolation_verified,
        "merkle_root": merkle_root,
        "merkle_certificate_path": str(certificate_path),
        "flows_scored": len(scored),
        "alerts": len(alerts),
        "incident_count": len(incidents),
        "flows_path": str(flows_path),
        "cases_path": str(cases_path),
    }
