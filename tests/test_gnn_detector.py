from pathlib import Path
import re

import numpy as np
import pandas as pd
import pytest

from src.data_loader import FlowDataLoader
from src.gnn_detector import GNNDetector, GraphDataBuilder
from src.graph_engine import HostGraphEngine
from src.incident_cluster import IncidentClusterEngine


FEATURES = ["flow_duration", "totlen_fwd_pkts", "totlen_bwd_pkts"]


def make_flows(start: str, count: int) -> tuple[pd.DataFrame, pd.Series, pd.DataFrame]:
    times = pd.date_range(start, periods=count, freq="min", tz="UTC")
    prefix = pd.Timestamp(start).strftime("%Y%m%d%H%M")
    metadata = pd.DataFrame({
        "flow_id": [f"flw_{prefix}_{i:04d}" for i in range(count)],
        "evidence_id": ["capture-a"] * count,
        "timestamp": times,
        "src_ip": ["10.0.0.1"] * count,
        "dst_ip": ["10.0.0.2"] * count,
        "src_port": [40000 + i for i in range(count)],
        "dst_port": [443] * count,
        "protocol": [6] * count,
        "label": ["PortScan" if i % 2 else "BENIGN" for i in range(count)],
    })
    features = pd.DataFrame({
        "flow_duration": np.arange(count, dtype=np.float32) + 1,
        "totlen_fwd_pkts": np.arange(count, dtype=np.float32) * 10 + 20,
        "totlen_bwd_pkts": np.arange(count, dtype=np.float32) * 5 + 10,
    })
    return features, metadata["label"], metadata


def train_detector(
    tmp_path: Path,
) -> tuple[GNNDetector, Path, pd.DataFrame, pd.DataFrame]:
    x_train, y_train, train_meta = make_flows("2026-10-15T09:00:00Z", 8)
    x_val, y_val, val_meta = make_flows("2026-10-15T09:20:00Z", 4)
    detector = GNNDetector(hidden_dim=8, dropout=0.0)
    detector.train(x_train, y_train, train_meta, x_val, y_val, val_meta, epochs=1)
    checkpoint = tmp_path / "gnn_edge_sage.pt"
    detector.save(checkpoint)
    return detector, checkpoint, x_val, val_meta


def test_checkpoint_round_trip_and_inference_schema(tmp_path):
    detector, checkpoint, features, metadata = train_detector(tmp_path)
    restored = GNNDetector(hidden_dim=128)
    restored.load(checkpoint)
    assert restored.hidden_dim == detector.hidden_dim
    assert restored.builder.feature_columns == FEATURES
    assert restored.training_provenance == detector.training_provenance

    scored = restored.score_flows(features[FEATURES[::-1]], metadata)
    assert scored["flow_id"].tolist() == metadata["flow_id"].tolist()
    assert scored["timestamp"].tolist() == metadata["timestamp"].tolist()
    assert scored["evidence_id"].tolist() == ["capture-a"] * len(metadata)
    assert scored["label"].tolist() == metadata["label"].tolist()
    assert scored["risk_score"].shape == (len(metadata),)
    assert np.isfinite(scored["risk_score"]).all()
    assert scored["risk_score"].between(0, 1).all()
    assert scored["is_alert"].shape == (len(metadata),)
    assert scored["predicted_class"].shape == (len(metadata),)


def test_legacy_checkpoint_migrates_without_claiming_provenance(tmp_path):
    import torch

    _, source, features, metadata = train_detector(tmp_path)
    legacy_path = tmp_path / "legacy-v1.pt"
    migrated_path = tmp_path / "migrated-v2.pt"
    original = torch.load(source, map_location="cpu", weights_only=False)
    legacy = {key: original[key] for key in (
        "model_state", "optimal_threshold", "hidden_dim", "node_to_idx",
        "feature_columns", "node_scaler", "edge_scaler",
    )}
    torch.save(legacy, legacy_path)
    before = legacy_path.read_bytes()

    GNNDetector.migrate_legacy_checkpoint(legacy_path, migrated_path)
    assert legacy_path.read_bytes() == before
    migrated = torch.load(migrated_path, map_location="cpu", weights_only=False)
    assert migrated["model_state"].keys() == legacy["model_state"].keys()
    assert migrated["feature_columns"] == legacy["feature_columns"]
    assert migrated["node_scaler"] is not None
    assert migrated["edge_scaler"] is not None
    assert migrated["hidden_dim"] == legacy["hidden_dim"]
    assert migrated["optimal_threshold"] == legacy["optimal_threshold"]
    assert migrated["dropout"] == 0.2
    assert migrated["training_provenance"] is None
    assert migrated["migration_metadata"]["training_graph_window_seconds"] is None

    detector = GNNDetector()
    detector.load(migrated_path)
    scored = detector.score_flows(features, metadata)
    assert scored["risk_score"].between(0, 1).all()
    with pytest.raises(ValueError, match="temporally isolated evaluation"):
        detector.validate_inference_split(metadata)
    with pytest.raises(FileExistsError):
        GNNDetector.migrate_legacy_checkpoint(legacy_path, migrated_path)


def test_checkpoint_missing_reports_exact_path(tmp_path):
    missing = tmp_path / "missing-gnn.pt"
    with pytest.raises(FileNotFoundError, match=re.escape(str(missing))):
        GNNDetector().load(missing)


def test_feature_schema_rejects_missing_and_unexpected_features(tmp_path):
    _, checkpoint, features, metadata = train_detector(tmp_path)
    detector = GNNDetector()
    detector.load(checkpoint)

    with pytest.raises(ValueError, match="Missing features"):
        detector.score_flows(features.drop(columns=["flow_duration"]), metadata)
    with pytest.raises(ValueError, match="unexpected features"):
        detector.score_flows(features.assign(unexpected_feature=1), metadata)


def test_graphs_are_disjoint_across_time_windows():
    features, _, metadata = make_flows("2026-10-15T09:00:00Z", 7)
    builder = GraphDataBuilder(window_seconds=300)
    graph = builder.build_graph(features, metadata, is_train=True)

    assert graph.edge_index.shape == (2, len(metadata))
    assert graph.flow_order.tolist() == list(range(len(metadata)))
    assert graph.x.shape[0] == 4
    first_window_nodes = set(graph.edge_index[:, :5].flatten().tolist())
    second_window_nodes = set(graph.edge_index[:, 5:].flatten().tolist())
    assert first_window_nodes.isdisjoint(second_window_nodes)


def test_inference_split_must_follow_training_horizon(tmp_path):
    _, checkpoint, features, metadata = train_detector(tmp_path)
    detector = GNNDetector()
    detector.load(checkpoint)
    detector.validate_inference_split(metadata)

    overlapping = metadata.copy()
    overlapping["timestamp"] = pd.Timestamp("2026-10-15T09:00:00Z")
    with pytest.raises(ValueError, match="temporal leakage check failed"):
        detector.validate_inference_split(overlapping)


def test_gnn_scores_feed_alert_incident_graph_with_provenance(tmp_path):
    _, checkpoint, features, metadata = train_detector(tmp_path)
    detector = GNNDetector()
    detector.load(checkpoint)
    detector.optimal_threshold = 0.0
    scored = detector.score_flows(features, metadata)

    alerts = scored.loc[scored["is_alert"]].copy()
    assert len(alerts) == len(metadata)
    graph_engine = HostGraphEngine()
    graph_engine.build_graph_from_flows(scored)
    incidents = IncidentClusterEngine(time_threshold_secs=300).correlate_alerts(alerts)

    assert incidents
    incident = incidents[0]
    assert set(incident["evidence_flow_ids"]) == set(metadata["flow_id"])
    assert incident["evidence_files"] == ["capture-a"]
    assert incident["total_alerts"] == len(metadata)
    subgraph = graph_engine.extract_suspicious_subgraph(
        incident["evidence_flow_ids"], k_hop=0
    )
    assert {edge["edge_id"] for edge in subgraph["edges"]} == set(metadata["flow_id"])


def test_pipeline_temporal_split_has_disjoint_global_time_ranges():
    first_x, _, first_meta = make_flows("2026-10-15T09:00:00Z", 20)
    second_x, _, second_meta = make_flows("2026-10-15T09:30:00Z", 20)
    second_meta["flow_id"] = [f"flw_second_{i:04d}" for i in range(len(second_meta))]
    data = pd.concat([
        pd.concat([first_meta, first_x], axis=1),
        pd.concat([second_meta, second_x], axis=1),
    ], ignore_index=True)
    data.loc[::3, "label"] = "PortScan"

    parts = FlowDataLoader().prepare_temporal_split(
        data, train_ratio=0.6, val_ratio=0.2, per_class=False
    )
    train_meta, val_meta, test_meta = parts[2], parts[5], parts[8]

    assert train_meta["timestamp"].max() < val_meta["timestamp"].min()
    assert val_meta["timestamp"].max() < test_meta["timestamp"].min()
    assert set(train_meta["flow_id"]).isdisjoint(val_meta["flow_id"])
    assert set(train_meta["flow_id"]).isdisjoint(test_meta["flow_id"])
    assert set(val_meta["flow_id"]).isdisjoint(test_meta["flow_id"])


def test_main_pipeline_dispatches_gnn_without_writing_repository_artifacts(
    tmp_path, monkeypatch
):
    import main

    features, _, metadata = make_flows("2026-10-15T09:00:00Z", 36)
    raw_flows = pd.concat([metadata, features], axis=1)
    monkeypatch.setattr(main, "MODELS_DIR", tmp_path / "models")

    output_path = tmp_path / "incident_cases.json"

    class StubIncidentEngine:
        def __init__(self, time_threshold_secs):
            assert time_threshold_secs == 300

        def correlate_alerts(self, alerts):
            return []

        def export_agent_case_bundle(self, incidents, graph_engine):
            return output_path

    class StubMerkleEngine:
        def build_tree(self, scored_flows):
            return "test-root"

        def enrich_incident_case_package(self, incident_path):
            assert incident_path == output_path

        def export_forensic_certificate(self, incident_cases_path):
            assert incident_cases_path == output_path
            return tmp_path / "certificate.json"

    class StubCausalEngine:
        def __init__(self):
            pass

        def enrich_incident_case_package(self, incident_path):
            assert incident_path == output_path

    monkeypatch.setattr(main, "IncidentClusterEngine", StubIncidentEngine)
    monkeypatch.setattr(
        "src.integrity.merkle_engine.MerkleEvidenceEngine", StubMerkleEngine
    )
    monkeypatch.setattr("src.causal_provenance.CausalProvenanceEngine", StubCausalEngine)

    result = main.run_pipeline(raw_df=raw_flows, model_type="gnn")

    assert result == output_path
    assert (tmp_path / "models" / "gnn_edge_sage.pt").is_file()
