"""Automatic detector selection and compatibility validation for EviGraph."""

from dataclasses import dataclass, field
import importlib
from pathlib import Path
from typing import Any, Dict, List, Optional, Type

import numpy as np
import pandas as pd

from src.config import METADATA_COLS, MODELS_DIR


@dataclass
class DetectorCompatibility:
    detector: str  # "xgb" or "gnn"
    is_compatible: bool
    reason: str
    missing_features: List[str] = field(default_factory=list)
    missing_metadata: List[str] = field(default_factory=list)
    missing_dependencies: List[str] = field(default_factory=list)
    checkpoint_path: Optional[Path] = None
    checkpoint_version: Optional[int] = None
    is_legacy_migrated: bool = False
    temporal_isolation_verified: bool = False
    expected_features: List[str] = field(default_factory=list)


@dataclass
class SelectionResult:
    requested_detector: str        # "auto", "xgb", or "gnn"
    selected_detector: str         # "xgb" or "gnn"
    detector_label: str            # "xgb", "gnn", or "gnn_legacy_migrated"
    selection_reason: str          # Detailed human-readable explanation
    fallback_reason: Optional[str] # Explanation if fallback occurred, else None
    xgb_compatibility: DetectorCompatibility
    gnn_compatibility: DetectorCompatibility


def check_xgboost_compatibility(
    flows: pd.DataFrame,
    models_dir: Path = MODELS_DIR,
    baseline_cls: Optional[Type[Any]] = None,
) -> DetectorCompatibility:
    """Validate whether the XGBoost baseline classifier can process the input."""
    missing_deps = []
    for dep in ("xgboost", "joblib", "sklearn"):
        try:
            importlib.import_module(dep)
        except ImportError:
            missing_deps.append(dep)
    if missing_deps:
        return DetectorCompatibility(
            detector="xgb",
            is_compatible=False,
            reason=f"Missing required XGBoost dependencies: {', '.join(missing_deps)}.",
            missing_dependencies=missing_deps,
        )

    import joblib

    model_dir = Path(models_dir)
    model_path = model_dir / "xgboost_baseline.joblib"
    meta_path = model_dir / "xgboost_baseline_meta.joblib"

    # Allow custom / mocked BaselineDetector class if it supplies feature columns
    expected_features: List[str] = []
    if baseline_cls is not None and hasattr(baseline_cls, "feature_columns") and baseline_cls.feature_columns:
        expected_features = list(baseline_cls.feature_columns)
    elif meta_path.is_file():
        try:
            meta = joblib.load(meta_path)
            expected_features = meta.get("features", [])
        except Exception as exc:
            return DetectorCompatibility(
                detector="xgb",
                is_compatible=False,
                reason=f"Failed to read XGBoost metadata at {meta_path.name}: {exc}.",
                checkpoint_path=meta_path,
            )
    elif not model_path.is_file():
        return DetectorCompatibility(
            detector="xgb",
            is_compatible=False,
            reason=f"XGBoost model checkpoint not found at {model_path}.",
            checkpoint_path=model_path,
        )

    if not expected_features and model_path.is_file():
        try:
            loaded = joblib.load(model_path)
            if hasattr(loaded, "feature_names_in_"):
                expected_features = list(loaded.feature_names_in_)
        except Exception:
            pass

    if not expected_features:
        return DetectorCompatibility(
            detector="xgb",
            is_compatible=False,
            reason="XGBoost expected feature list could not be determined.",
            checkpoint_path=model_path if model_path.is_file() else None,
        )

    # Check feature presence
    missing_features = [col for col in expected_features if col not in flows.columns]
    if missing_features:
        return DetectorCompatibility(
            detector="xgb",
            is_compatible=False,
            reason=(
                f"Input missing {len(missing_features)} required XGBoost feature(s): "
                f"{sorted(missing_features)[:5]}{'...' if len(missing_features) > 5 else ''}."
            ),
            missing_features=missing_features,
            checkpoint_path=model_path if model_path.is_file() else None,
            expected_features=expected_features,
        )

    # Check numeric validity of required features
    for col in expected_features:
        converted = pd.to_numeric(flows[col], errors="coerce")
        malformed = flows[col].notna() & converted.isna()
        if malformed.any():
            return DetectorCompatibility(
                detector="xgb",
                is_compatible=False,
                reason=f"XGBoost feature '{col}' contains non-numeric values.",
                checkpoint_path=model_path if model_path.is_file() else None,
                expected_features=expected_features,
            )

    return DetectorCompatibility(
        detector="xgb",
        is_compatible=True,
        reason=f"XGBoost baseline compatible ({len(expected_features)} features verified).",
        checkpoint_path=model_path if model_path.is_file() else None,
        expected_features=expected_features,
    )


def check_gnn_compatibility(
    flows: pd.DataFrame,
    metadata: pd.DataFrame,
    models_dir: Path = MODELS_DIR,
    gnn_cls: Optional[Type[Any]] = None,
) -> DetectorCompatibility:
    """Validate whether the GraphSAGE GNN detector can process the input."""
    # 1. Check dependencies
    missing_deps = []
    try:
        import torch
    except ImportError:
        missing_deps.append("torch")
    try:
        import torch_geometric
        from torch_geometric.nn import SAGEConv
    except ImportError:
        missing_deps.append("torch_geometric")

    if missing_deps:
        return DetectorCompatibility(
            detector="gnn",
            is_compatible=False,
            reason=f"Missing required GNN dependencies: {', '.join(missing_deps)}.",
            missing_dependencies=missing_deps,
        )

    # 2. Check checkpoint availability and schema version
    model_dir = Path(models_dir)
    migrated_path = model_dir / "gnn_edge_sage.migrated-legacy-v2.pt"
    default_path = model_dir / "gnn_edge_sage.pt"
    checkpoint_path = migrated_path if migrated_path.is_file() else default_path

    if not checkpoint_path.is_file():
        return DetectorCompatibility(
            detector="gnn",
            is_compatible=False,
            reason=f"GNN model checkpoint not found at {checkpoint_path}.",
            checkpoint_path=checkpoint_path,
        )

    # Read checkpoint metadata
    try:
        try:
            ckpt = torch.load(checkpoint_path, map_location="cpu", weights_only=False)
        except TypeError:
            ckpt = torch.load(checkpoint_path, map_location="cpu")
    except Exception as exc:
        return DetectorCompatibility(
            detector="gnn",
            is_compatible=False,
            reason=f"Failed to load GNN checkpoint at {checkpoint_path.name}: {exc}.",
            checkpoint_path=checkpoint_path,
        )

    if not isinstance(ckpt, dict):
        return DetectorCompatibility(
            detector="gnn",
            is_compatible=False,
            reason="Invalid GNN checkpoint format (expected dictionary).",
            checkpoint_path=checkpoint_path,
        )

    checkpoint_version = ckpt.get("checkpoint_version")
    if checkpoint_version != 2:
        return DetectorCompatibility(
            detector="gnn",
            is_compatible=False,
            reason=(
                f"GNN checkpoint at {checkpoint_path.name} uses schema version "
                f"{checkpoint_version or 1}; current pipeline requires schema version 2 "
                "with time-windowed graph metadata."
            ),
            checkpoint_path=checkpoint_path,
            checkpoint_version=checkpoint_version,
        )

    migration_metadata = ckpt.get("migration_metadata")
    is_legacy_migrated = (
        isinstance(migration_metadata, dict) and migration_metadata.get("kind") == "migrated_legacy_gnn"
    )
    training_provenance = ckpt.get("training_provenance")
    temporal_isolation_verified = (
        training_provenance is not None and isinstance(training_provenance, dict)
    )

    expected_features = ckpt.get("feature_columns", [])
    if not isinstance(expected_features, list) or not expected_features:
        return DetectorCompatibility(
            detector="gnn",
            is_compatible=False,
            reason="GNN checkpoint feature column list is missing or invalid.",
            checkpoint_path=checkpoint_path,
            checkpoint_version=checkpoint_version,
            is_legacy_migrated=is_legacy_migrated,
            temporal_isolation_verified=temporal_isolation_verified,
        )

    # 3. Check graph and metadata requirements
    missing_metadata = sorted({"src_ip", "dst_ip", "timestamp"} - set(metadata.columns))
    if missing_metadata:
        return DetectorCompatibility(
            detector="gnn",
            is_compatible=False,
            reason=f"GNN graph construction requires metadata columns: {', '.join(missing_metadata)}.",
            missing_metadata=missing_metadata,
            checkpoint_path=checkpoint_path,
            checkpoint_version=checkpoint_version,
            is_legacy_migrated=is_legacy_migrated,
            temporal_isolation_verified=temporal_isolation_verified,
            expected_features=expected_features,
        )

    if len(flows) == 0:
        return DetectorCompatibility(
            detector="gnn",
            is_compatible=False,
            reason="Input contains no flows to construct host graph.",
            checkpoint_path=checkpoint_path,
            checkpoint_version=checkpoint_version,
            is_legacy_migrated=is_legacy_migrated,
            temporal_isolation_verified=temporal_isolation_verified,
            expected_features=expected_features,
        )

    # Check timestamps
    timestamps = pd.to_datetime(metadata["timestamp"], format="mixed", utc=True, errors="coerce")
    if timestamps.isna().any():
        return DetectorCompatibility(
            detector="gnn",
            is_compatible=False,
            reason="GNN graph construction requires valid timestamps for every flow.",
            checkpoint_path=checkpoint_path,
            checkpoint_version=checkpoint_version,
            is_legacy_migrated=is_legacy_migrated,
            temporal_isolation_verified=temporal_isolation_verified,
            expected_features=expected_features,
        )

    # 4. Check edge feature presence in flows
    missing_features = [col for col in expected_features if col not in flows.columns]
    if missing_features:
        return DetectorCompatibility(
            detector="gnn",
            is_compatible=False,
            reason=(
                f"Input missing {len(missing_features)} required GNN edge feature(s): "
                f"{sorted(missing_features)[:5]}{'...' if len(missing_features) > 5 else ''}."
            ),
            missing_features=missing_features,
            checkpoint_path=checkpoint_path,
            checkpoint_version=checkpoint_version,
            is_legacy_migrated=is_legacy_migrated,
            temporal_isolation_verified=temporal_isolation_verified,
            expected_features=expected_features,
        )

    # Check numeric validity of required features
    for col in expected_features:
        converted = pd.to_numeric(flows[col], errors="coerce")
        malformed = flows[col].notna() & converted.isna()
        if malformed.any():
            return DetectorCompatibility(
                detector="gnn",
                is_compatible=False,
                reason=f"GNN feature '{col}' contains non-numeric values.",
                checkpoint_path=checkpoint_path,
                checkpoint_version=checkpoint_version,
                is_legacy_migrated=is_legacy_migrated,
                temporal_isolation_verified=temporal_isolation_verified,
                expected_features=expected_features,
            )

    return DetectorCompatibility(
        detector="gnn",
        is_compatible=True,
        reason=(
            f"GraphSAGE GNN compatible ({len(expected_features)} edge features and host graph requirements verified; "
            f"temporal isolation {'verified' if temporal_isolation_verified else 'unverified'})."
        ),
        checkpoint_path=checkpoint_path,
        checkpoint_version=checkpoint_version,
        is_legacy_migrated=is_legacy_migrated,
        temporal_isolation_verified=temporal_isolation_verified,
        expected_features=expected_features,
    )


def select_detector(
    flows: pd.DataFrame,
    metadata: pd.DataFrame,
    requested: str = "auto",
    models_dir: Path = MODELS_DIR,
    baseline_cls: Optional[Type[Any]] = None,
    gnn_cls: Optional[Type[Any]] = None,
) -> SelectionResult:
    """
    Select an appropriate detector (XGBoost or GraphSAGE GNN) based on schema,
    checkpoint compatibility, and user request.
    """
    req = (requested or "auto").strip().lower()
    if req not in {"auto", "xgb", "gnn"}:
        raise ValueError(f"Detector must be 'auto', 'xgb', or 'gnn' (got {requested!r}).")

    xgb_comp = check_xgboost_compatibility(flows, models_dir=models_dir, baseline_cls=baseline_cls)
    gnn_comp = check_gnn_compatibility(flows, metadata, models_dir=models_dir, gnn_cls=gnn_cls)

    if req == "auto":
        # Rule 1: If both are compatible, prefer XGBoost baseline
        if xgb_comp.is_compatible and gnn_comp.is_compatible:
            return SelectionResult(
                requested_detector="auto",
                selected_detector="xgb",
                detector_label="xgb",
                selection_reason="Auto selected XGBoost baseline: preferred production detector when both models are compatible.",
                fallback_reason=None,
                xgb_compatibility=xgb_comp,
                gnn_compatibility=gnn_comp,
            )

        # Rule 2: If only XGBoost is compatible, fall back to XGBoost
        if xgb_comp.is_compatible and not gnn_comp.is_compatible:
            return SelectionResult(
                requested_detector="auto",
                selected_detector="xgb",
                detector_label="xgb",
                selection_reason="Auto selected XGBoost baseline: input satisfies 31-feature schema.",
                fallback_reason=f"GraphSAGE GNN incompatible: {gnn_comp.reason}",
                xgb_compatibility=xgb_comp,
                gnn_compatibility=gnn_comp,
            )

        # Rule 3: If only GraphSAGE GNN is compatible, select GNN
        if gnn_comp.is_compatible and not xgb_comp.is_compatible:
            label = "gnn_legacy_migrated" if gnn_comp.is_legacy_migrated else "gnn"
            return SelectionResult(
                requested_detector="auto",
                selected_detector="gnn",
                detector_label=label,
                selection_reason="Auto selected GraphSAGE GNN: input meets graph and 35-feature schema requirements, while XGBoost baseline is incompatible.",
                fallback_reason=None,
                xgb_compatibility=xgb_comp,
                gnn_compatibility=gnn_comp,
            )

        # Rule 4: Neither is compatible -> clear error
        raise ValueError(
            f"No compatible detector available for this input. "
            f"XGBoost incompatible: {xgb_comp.reason} "
            f"GraphSAGE GNN incompatible: {gnn_comp.reason}"
        )

    if req == "xgb":
        if not xgb_comp.is_compatible:
            raise ValueError(f"Requested detector 'xgb' cannot process input: {xgb_comp.reason}")
        return SelectionResult(
            requested_detector="xgb",
            selected_detector="xgb",
            detector_label="xgb",
            selection_reason="Manual selection: XGBoost baseline classifier requested.",
            fallback_reason=None,
            xgb_compatibility=xgb_comp,
            gnn_compatibility=gnn_comp,
        )

    # req == "gnn"
    if not gnn_comp.is_compatible:
        raise ValueError(f"Requested detector 'gnn' cannot process input: {gnn_comp.reason}")
    label = "gnn_legacy_migrated" if gnn_comp.is_legacy_migrated else "gnn"
    return SelectionResult(
        requested_detector="gnn",
        selected_detector="gnn",
        detector_label=label,
        selection_reason="Manual selection: GraphSAGE GNN requested.",
        fallback_reason=None,
        xgb_compatibility=xgb_comp,
        gnn_compatibility=gnn_comp,
    )
