"""Tests for automatic and manual detector selection in EviGraph."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pandas as pd
import pytest

from src.config import MODELS_DIR
from src.detector_selector import (
    check_gnn_compatibility,
    check_xgboost_compatibility,
    select_detector,
)


def make_metadata(count: int = 4) -> pd.DataFrame:
    start = pd.Timestamp("2026-10-15T09:00:00Z")
    return pd.DataFrame({
        "flow_id": [f"flw_{i:03d}" for i in range(count)],
        "evidence_id": ["ev-test"] * count,
        "timestamp": [(start + pd.Timedelta(seconds=i * 30)).isoformat() for i in range(count)],
        "src_ip": ["10.0.0.1", "10.0.0.2", "10.0.0.1", "10.0.0.3"][:count],
        "dst_ip": ["10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.1"][:count],
        "src_port": [40000 + i for i in range(count)],
        "dst_port": [443, 22, 445, 80][:count],
        "protocol": [6] * count,
        "source_sha256": ["feedface" * 8] * count,
    })


def make_xgb_features(count: int = 4) -> pd.DataFrame:
    """31 standard XGBoost baseline features."""
    import joblib

    meta = joblib.load(MODELS_DIR / "xgboost_baseline_meta.joblib")
    features = meta["features"]
    data = {col: [1.0 + i for i in range(count)] for col in features}
    return pd.DataFrame(data)


def make_gnn_features(count: int = 4) -> pd.DataFrame:
    """35 features expected by the migrated GNN checkpoint."""
    df = make_xgb_features(count)
    for col in ("urg_flag_cnt", "fwd_urg_flags", "bwd_urg_flags", "syn_flag_cnt"):
        df[col] = [0.0] * count
    return df


def test_auto_selects_xgboost_when_it_is_the_only_compatible_model():
    # flows DataFrame has only 31 features (lacks the 4 extra GNN features)
    flows = make_xgb_features(4)
    metadata = make_metadata(4)

    res = select_detector(flows, metadata, requested="auto", models_dir=MODELS_DIR)

    assert res.selected_detector == "xgb"
    assert res.detector_label == "xgb"
    assert "Auto selected XGBoost" in res.selection_reason
    assert res.fallback_reason is not None
    assert "GraphSAGE GNN incompatible" in res.fallback_reason
    assert "required GNN edge feature" in res.fallback_reason
    assert res.xgb_compatibility.is_compatible is True
    assert res.gnn_compatibility.is_compatible is False


def test_auto_prefers_xgboost_when_both_models_are_compatible():
    # flows DataFrame contains all 35 features and valid graph metadata
    flows = make_gnn_features(4)
    metadata = make_metadata(4)

    res = select_detector(flows, metadata, requested="auto", models_dir=MODELS_DIR)

    assert res.selected_detector == "xgb"
    assert res.detector_label == "xgb"
    assert "preferred production detector when both models are compatible" in res.selection_reason
    assert res.fallback_reason is None
    assert res.xgb_compatibility.is_compatible is True
    assert res.gnn_compatibility.is_compatible is True


def test_auto_selects_gnn_only_when_all_compatibility_checks_pass_and_xgb_incompatible():
    flows = make_gnn_features(4)
    metadata = make_metadata(4)

    # Simulate XGBoost model missing or incompatible
    with patch("src.detector_selector.check_xgboost_compatibility") as mock_xgb:
        from src.detector_selector import DetectorCompatibility

        mock_xgb.return_value = DetectorCompatibility(
            detector="xgb",
            is_compatible=False,
            reason="XGBoost model checkpoint corrupted or missing.",
        )

        res = select_detector(flows, metadata, requested="auto", models_dir=MODELS_DIR)

        assert res.selected_detector == "gnn"
        assert res.detector_label == "gnn_legacy_migrated"
        assert "Auto selected GraphSAGE GNN" in res.selection_reason
        assert res.fallback_reason is None


def test_incompatible_or_missing_gnn_checkpoint_triggers_safe_fallback(tmp_path):
    flows = make_xgb_features(4)
    metadata = make_metadata(4)

    # Point to a directory containing only XGBoost model, with no GNN checkpoint
    import joblib

    xgb_meta = joblib.load(MODELS_DIR / "xgboost_baseline_meta.joblib")
    joblib.dump(xgb_meta, tmp_path / "xgboost_baseline_meta.joblib")
    (tmp_path / "xgboost_baseline.joblib").write_text("mock", encoding="utf-8")

    res = select_detector(flows, metadata, requested="auto", models_dir=tmp_path)

    assert res.selected_detector == "xgb"
    assert res.fallback_reason is not None
    assert "GNN model checkpoint not found" in res.fallback_reason


def test_legacy_v1_gnn_checkpoint_triggers_fallback_with_schema_explanation(tmp_path):
    flows = make_gnn_features(4)
    metadata = make_metadata(4)

    # Copy XGBoost files and only the legacy v1 gnn_edge_sage.pt checkpoint
    import joblib
    import shutil

    xgb_meta = joblib.load(MODELS_DIR / "xgboost_baseline_meta.joblib")
    joblib.dump(xgb_meta, tmp_path / "xgboost_baseline_meta.joblib")
    (tmp_path / "xgboost_baseline.joblib").write_text("mock", encoding="utf-8")
    shutil.copyfile(MODELS_DIR / "gnn_edge_sage.pt", tmp_path / "gnn_edge_sage.pt")

    res = select_detector(flows, metadata, requested="auto", models_dir=tmp_path)

    assert res.selected_detector == "xgb"
    assert res.fallback_reason is not None
    assert "schema version 1" in res.fallback_reason or "requires schema version 2" in res.fallback_reason


def test_unsupported_input_produces_clear_error():
    # Flows has neither XGBoost nor GNN features
    flows = pd.DataFrame({"arbitrary_column": [1, 2, 3]})
    metadata = make_metadata(3)

    with pytest.raises(ValueError, match="No compatible detector available for this input"):
        select_detector(flows, metadata, requested="auto", models_dir=MODELS_DIR)


def test_manual_xgboost_selection_respected_when_compatible():
    flows = make_xgb_features(4)
    metadata = make_metadata(4)

    res = select_detector(flows, metadata, requested="xgb", models_dir=MODELS_DIR)
    assert res.selected_detector == "xgb"
    assert "Manual selection: XGBoost" in res.selection_reason
    assert res.fallback_reason is None


def test_manual_gnn_selection_fails_explicitly_when_incompatible():
    # Only 31 features (missing 4 GNN features)
    flows = make_xgb_features(4)
    metadata = make_metadata(4)

    with pytest.raises(ValueError, match="Requested detector 'gnn' cannot process input"):
        select_detector(flows, metadata, requested="gnn", models_dir=MODELS_DIR)


def test_manual_selection_does_not_silently_override_choice():
    # When user requests GNN, but GNN cannot run, it MUST NOT silently return XGBoost
    flows = make_xgb_features(4)
    metadata = make_metadata(4)

    try:
        select_detector(flows, metadata, requested="gnn", models_dir=MODELS_DIR)
        pytest.fail("Should have raised ValueError for incompatible manual GNN selection")
    except ValueError as exc:
        assert "Requested detector 'gnn' cannot process input" in str(exc)
        assert "xgb" not in str(exc).lower() or "missing" in str(exc).lower()


def test_invalid_requested_detector_rejected():
    flows = make_xgb_features(2)
    metadata = make_metadata(2)

    with pytest.raises(ValueError, match="Detector must be 'auto', 'xgb', or 'gnn'"):
        select_detector(flows, metadata, requested="invalid_model", models_dir=MODELS_DIR)


def test_api_server_accepts_auto_header_and_records_selection(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    import frontend.api.server as server

    monkeypatch.setattr(server, "INVESTIGATION_ROOT", tmp_path / "jobs")
    monkeypatch.setattr(server._job_executor, "submit", lambda *args, **kwargs: None)

    with TestClient(server.app) as client:
        # POST with X-Detector: auto
        res = client.post(
            "/investigations",
            content=b"dummy flow content",
            headers={
                "X-Filename": "flows.csv",
                "X-Detector": "auto",
                "Content-Type": "application/octet-stream",
            },
        )
        assert res.status_code == 202
        job_data = res.json()
        assert job_data["model_type"] == "auto"
        assert job_data["requested_detector"] == "auto"

        # Invalid detector header
        bad = client.post(
            "/investigations",
            content=b"dummy",
            headers={
                "X-Filename": "flows.csv",
                "X-Detector": "unsupported_detector",
                "Content-Type": "application/octet-stream",
            },
        )
        assert bad.status_code == 422
        assert "Detector must be 'auto', 'xgb', or 'gnn'" in bad.json()["detail"]
