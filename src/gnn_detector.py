"""
EviGraph GNN Edge Classifier: PyTorch Geometric Edge-GraphSAGE
Adheres to TRD Section 3.3.2 and PRD FR-3.2:
- Network flows represented as directed multigraph edges between host nodes
- Node structural features: in/out degree, fan-out, total byte volume
- Edge features: canonical flow statistical features (anti-leakage: raw IPs/ports excluded)
- 2-layer GraphSAGE message passing over host topology
- Edge MLP classifier predicting anomaly risk probability P(alert | u, v, e)
- Accelerated via NVIDIA CUDA GPU or CPU fallback
"""

import hashlib
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import SAGEConv
from torch_geometric.data import Data
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import precision_recall_fscore_support

from src.config import (
    ALERT_RISK_THRESHOLD,
    GRAPH_TIME_WINDOW_SECS,
    METADATA_COLS,
    MODELS_DIR,
)

CHECKPOINT_VERSION = 2
LEGACY_MIGRATION_KIND = "migrated_legacy_gnn"
NODE_FEATURE_COLUMNS = (
    "log_in_degree",
    "log_out_degree",
    "log_fan_out",
    "log_bytes_sent",
    "log_bytes_received",
)

class EdgeGraphSAGE(nn.Module):
    """2-Layer Edge-GraphSAGE edge anomaly classifier."""
    def __init__(self, node_in_dim: int, edge_in_dim: int, hidden_dim: int = 64, dropout: float = 0.2):
        super().__init__()
        self.conv1 = SAGEConv(node_in_dim, hidden_dim)
        self.conv2 = SAGEConv(hidden_dim, hidden_dim)
        self.dropout = nn.Dropout(dropout)
        
        # Edge classifier head: takes [h_source || h_target || edge_attributes]
        edge_repr_dim = 2 * hidden_dim + edge_in_dim
        self.edge_mlp = nn.Sequential(
            nn.Linear(edge_repr_dim, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, 32),
            nn.ReLU(),
            nn.Linear(32, 1)
        )

    def forward(self, x: torch.Tensor, edge_index: torch.Tensor, edge_attr: torch.Tensor) -> torch.Tensor:
        # 1. Message passing across host communication graph
        h = self.conv1(x, edge_index)
        h = F.relu(h)
        h = self.dropout(h)
        
        h = self.conv2(h, edge_index)
        h = F.relu(h)
        
        # 2. Extract source and target node representations for each flow edge
        src_idx = edge_index[0]
        dst_idx = edge_index[1]
        h_src = h[src_idx]
        h_dst = h[dst_idx]
        
        # 3. Concatenate topology representations with edge telemetry
        edge_repr = torch.cat([h_src, h_dst, edge_attr], dim=-1)
        
        # 4. Predict edge anomaly logits
        logits = self.edge_mlp(edge_repr).squeeze(-1)
        return logits


class GraphDataBuilder:
    """Converts flow tabular DataFrames into PyG Graph Data objects."""
    def __init__(self, window_seconds: int = GRAPH_TIME_WINDOW_SECS):
        if window_seconds <= 0:
            raise ValueError("Graph window must be a positive number of seconds.")
        self.window_seconds = window_seconds
        self.node_to_idx: Dict[str, int] = {}
        self.node_scaler = StandardScaler()
        self.edge_scaler = StandardScaler()
        self.feature_columns: List[str] = []

    def build_graph(
        self, 
        X_df: pd.DataFrame, 
        meta_df: pd.DataFrame, 
        y_series: Optional[pd.Series] = None,
        is_train: bool = True
    ) -> Data:
        if len(X_df) != len(meta_df):
            raise ValueError("Feature and metadata row counts must match.")
        if y_series is not None and len(y_series) != len(meta_df):
            raise ValueError("Label and metadata row counts must match.")
        if len(meta_df) == 0:
            feature_count = len(self.feature_columns) or len(X_df.columns)
            return Data(
                x=torch.zeros((0, len(NODE_FEATURE_COLUMNS)), dtype=torch.float32),
                edge_index=torch.zeros((2, 0), dtype=torch.long),
                edge_attr=torch.zeros((0, feature_count), dtype=torch.float32),
                y=torch.zeros(0, dtype=torch.float32) if y_series is not None else None,
                flow_order=torch.zeros(0, dtype=torch.long),
            )

        missing_metadata = {"src_ip", "dst_ip", "timestamp"} - set(meta_df.columns)
        if missing_metadata:
            raise ValueError(
                "GNN graph construction requires metadata columns: "
                f"{', '.join(sorted(missing_metadata))}."
            )

        leaked_features = sorted(set(X_df.columns) & set(METADATA_COLS))
        if leaked_features:
            raise ValueError(
                "GNN features must exclude identity/label metadata columns: "
                f"{', '.join(leaked_features)}."
            )
        if is_train:
            if not len(X_df.columns):
                raise ValueError("GNN training requires at least one flow feature.")
            self.feature_columns = list(X_df.columns)
        else:
            if not self.feature_columns:
                raise ValueError(
                    "Feature columns are not initialized. Train or load a GNN checkpoint first."
                )
            missing = sorted(set(self.feature_columns) - set(X_df.columns))
            extra = sorted(set(X_df.columns) - set(self.feature_columns))
            if missing or extra:
                raise ValueError(
                    "GNN feature schema mismatch. "
                    f"Missing features: {missing or 'none'}; unexpected features: {extra or 'none'}."
                )

        features = X_df.loc[:, self.feature_columns].replace(
            [np.inf, -np.inf], np.nan
        ).fillna(0.0).to_numpy(dtype=np.float32)
        metadata = meta_df.reset_index(drop=True)
        timestamps = pd.to_datetime(
            metadata["timestamp"], format="mixed", utc=True, errors="coerce"
        )
        if timestamps.isna().any():
            raise ValueError("GNN graph construction requires valid timestamps for every flow.")
        window_ns = self.window_seconds * 1_000_000_000
        timestamp_ns = timestamps.to_numpy(dtype="datetime64[ns]").astype(np.int64)
        window_ids = timestamp_ns // window_ns

        fwd_col = next(
            (c for c in ("totlen_fwd_pkts", "tot_len_fwd_pkts") if c in self.feature_columns),
            None,
        )
        bwd_col = next(
            (c for c in ("totlen_bwd_pkts", "tot_len_bwd_pkts") if c in self.feature_columns),
            None,
        )
        fwd_idx = self.feature_columns.index(fwd_col) if fwd_col else None
        bwd_idx = self.feature_columns.index(bwd_col) if bwd_col else None
        src_ips = metadata["src_ip"].astype(str).to_numpy()
        dst_ips = metadata["dst_ip"].astype(str).to_numpy()

        node_feature_rows = []
        edge_index_rows = [[], []]
        edge_feature_rows = []
        flow_order = []
        self.node_to_idx = {}
        node_offset = 0

        for window_id in np.unique(window_ids):
            positions = np.flatnonzero(window_ids == window_id)
            hosts = sorted(set(src_ips[positions]) | set(dst_ips[positions]))
            local_index = {host: node_offset + i for i, host in enumerate(hosts)}
            stats = {
                host: {
                    "in_degree": 0,
                    "out_degree": 0,
                    "fan_out": set(),
                    "bytes_sent": 0.0,
                    "bytes_received": 0.0,
                }
                for host in hosts
            }

            for position in positions:
                source, target = src_ips[position], dst_ips[position]
                stat = stats[source]
                stat["out_degree"] += 1
                stat["fan_out"].add(target)
                if fwd_idx is not None:
                    stat["bytes_sent"] += float(features[position, fwd_idx])
                target_stat = stats[target]
                target_stat["in_degree"] += 1
                if bwd_idx is not None:
                    target_stat["bytes_received"] += float(features[position, bwd_idx])
                edge_index_rows[0].append(local_index[source])
                edge_index_rows[1].append(local_index[target])
                self.node_to_idx.setdefault(source, local_index[source])
                self.node_to_idx.setdefault(target, local_index[target])

            for host in hosts:
                stat = stats[host]
                node_feature_rows.append([
                    np.log1p(stat["in_degree"]),
                    np.log1p(stat["out_degree"]),
                    np.log1p(len(stat["fan_out"])),
                    np.log1p(max(0.0, stat["bytes_sent"])),
                    np.log1p(max(0.0, stat["bytes_received"])),
                ])

            edge_feature_rows.append(features[positions])
            flow_order.extend(positions.tolist())
            node_offset += len(hosts)

        node_features_raw = np.asarray(node_feature_rows, dtype=np.float32)
        edge_features_raw = np.concatenate(edge_feature_rows, axis=0)
        if is_train:
            node_features = self.node_scaler.fit_transform(node_features_raw)
            edge_features = self.edge_scaler.fit_transform(edge_features_raw)
        else:
            if not hasattr(self.node_scaler, "mean_"):
                raise ValueError(
                    "Node scaler is not fitted. Train or load a GNN checkpoint before inference."
                )
            if not hasattr(self.edge_scaler, "mean_"):
                raise ValueError(
                    "Edge scaler is not fitted. Train or load a GNN checkpoint before inference."
                )
            node_features = self.node_scaler.transform(node_features_raw)
            edge_features = self.edge_scaler.transform(edge_features_raw)

        y_tensor = None
        if y_series is not None:
            labels = y_series.astype(str).to_numpy()
            y_tensor = torch.tensor(
                (labels[np.asarray(flow_order)] != "BENIGN").astype(np.float32)
            )

        return Data(
            x=torch.tensor(node_features, dtype=torch.float32),
            edge_index=torch.tensor(edge_index_rows, dtype=torch.long),
            edge_attr=torch.tensor(edge_features, dtype=torch.float32),
            y=y_tensor,
            flow_order=torch.tensor(flow_order, dtype=torch.long),
        )


class GNNDetector:
    """End-to-End PyG GNN Detector for EviGraph."""
    def __init__(
        self,
        hidden_dim: int = 64,
        lr: float = 0.003,
        model_name: str = "gnn_edge_sage",
        dropout: float = 0.2,
    ):
        self.model_name = model_name
        self.hidden_dim = hidden_dim
        self.lr = lr
        self.dropout = dropout
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.model: Optional[EdgeGraphSAGE] = None
        self.builder = GraphDataBuilder()
        self.optimal_threshold: float = ALERT_RISK_THRESHOLD
        self.training_provenance: Optional[Dict[str, Any]] = None
        self.migration_metadata: Optional[Dict[str, Any]] = None

    def train(
        self,
        X_train: pd.DataFrame,
        y_train: pd.Series,
        meta_train: pd.DataFrame,
        X_val: pd.DataFrame,
        y_val: pd.Series,
        meta_val: pd.DataFrame,
        epochs: int = 40,
        batch_size: int = 4096
    ) -> Dict[str, Any]:
        """Trains Edge-GraphSAGE detector with class reweighting on CUDA or CPU."""
        if len(X_train) == 0 or len(X_val) == 0:
            raise ValueError("GNN training requires non-empty training and validation splits.")
        if "flow_id" not in meta_train or "timestamp" not in meta_train:
            raise ValueError(
                "GNN training metadata must include flow_id and timestamp for provenance."
            )
        train_timestamps = pd.to_datetime(
            meta_train["timestamp"], format="mixed", utc=True, errors="coerce"
        )
        if train_timestamps.isna().any():
            raise ValueError("GNN training metadata contains invalid timestamps.")
        train_ids = meta_train["flow_id"].astype(str)
        if train_ids.duplicated().any():
            raise ValueError("GNN training flow_id values must be unique.")
        if "flow_id" not in meta_val or "timestamp" not in meta_val:
            raise ValueError(
                "GNN validation metadata must include flow_id and timestamp."
            )
        val_timestamps = pd.to_datetime(
            meta_val["timestamp"], format="mixed", utc=True, errors="coerce"
        )
        if val_timestamps.isna().any():
            raise ValueError("GNN validation metadata contains invalid timestamps.")
        val_ids = meta_val["flow_id"].astype(str)
        if set(train_ids) & set(val_ids):
            raise ValueError("GNN training and validation flow_id values must be disjoint.")
        if train_timestamps.max() >= val_timestamps.min():
            raise ValueError(
                "GNN training must end before validation begins to prevent future leakage."
            )
        self.training_provenance = {
            "flow_count": len(train_ids),
            "flow_ids_sha256": hashlib.sha256(
                "\n".join(sorted(train_ids.tolist())).encode("utf-8")
            ).hexdigest(),
            "max_training_timestamp": train_timestamps.max().isoformat(),
        }
        print(f"\n[GNN Detector] Preparing Graph Datasets (Hardware: {str(self.device).upper()})...")
        train_data = self.builder.build_graph(X_train, meta_train, y_train, is_train=True).to(self.device)
        val_data = self.builder.build_graph(X_val, meta_val, y_val, is_train=False).to(self.device)
        if train_data.y is None or val_data.y is None:
            raise ValueError("GNN training requires labels for both training and validation data.")

        node_dim = train_data.x.shape[1]
        edge_dim = train_data.edge_attr.shape[1]
        num_train_edges = train_data.edge_index.shape[1]

        self.model = EdgeGraphSAGE(
            node_in_dim=node_dim,
            edge_in_dim=edge_dim,
            hidden_dim=self.hidden_dim,
            dropout=self.dropout,
        ).to(self.device)

        # Class imbalance weighting
        pos_count = float(train_data.y.sum().item())
        neg_count = float(num_train_edges - pos_count)
        pos_weight = torch.tensor([neg_count / max(1.0, pos_count)], device=self.device)
        criterion = nn.BCEWithLogitsLoss(pos_weight=pos_weight)
        optimizer = torch.optim.AdamW(self.model.parameters(), lr=self.lr, weight_decay=1e-4)

        print(f"[GNN Detector] Training on {train_data.x.shape[0]:,} host nodes and {num_train_edges:,} flow edges...")
        print(f"   * Positive Alert Weight: {pos_weight.item():.2f}")

        best_val_f1 = -1.0
        best_state = None

        self.model.train()
        for epoch in range(1, epochs + 1):
            optimizer.zero_grad()
            logits = self.model(train_data.x, train_data.edge_index, train_data.edge_attr)
            loss = criterion(logits, train_data.y)
            loss.backward()
            optimizer.step()

            # Periodic validation
            if epoch % 5 == 0 or epoch == epochs:
                self.model.eval()
                with torch.no_grad():
                    val_logits = self.model(val_data.x, val_data.edge_index, val_data.edge_attr)
                    val_probs = torch.sigmoid(val_logits).cpu().numpy()
                    y_val_np = val_data.y.cpu().numpy()

                    # Threshold sweep for best F1
                    best_th, ep_f1 = 0.5, 0.0
                    for th in [0.4, 0.5, 0.6, 0.7, 0.8]:
                        preds = (val_probs >= th).astype(int)
                        _, _, f1, _ = precision_recall_fscore_support(y_val_np, preds, average="binary", zero_division=0)
                        if f1 > ep_f1:
                            ep_f1 = f1
                            best_th = th

                    if ep_f1 > best_val_f1:
                        best_val_f1 = ep_f1
                        self.optimal_threshold = best_th
                        best_state = {k: v.cpu().clone() for k, v in self.model.state_dict().items()}

                    print(f"   * Epoch {epoch:>2}/{epochs} | Train Loss: {loss.item():.4f} | Val Best F1: {best_val_f1:.4f} (Th={self.optimal_threshold})")
                self.model.train()

        if best_state is None:
            best_state = {k: v.cpu().clone() for k, v in self.model.state_dict().items()}
        self.model.load_state_dict({k: v.to(self.device) for k, v in best_state.items()})

        print(f"[GNN Detector] Optimization complete! Best Validation F1: {best_val_f1:.4f}")
        return {"best_f1": best_val_f1, "optimal_threshold": self.optimal_threshold}

    def score_flows(self, X_df: pd.DataFrame, meta_df: pd.DataFrame) -> pd.DataFrame:
        """Runs GNN inference over held-out flows, computing topology-aware edge risk scores."""
        if self.model is None:
            raise ValueError("GNN model has not been trained or loaded yet. Call train() or load() before scoring flows.")

        if len(meta_df) == 0:
            scored_df = meta_df.copy()
            scored_df["risk_score"] = pd.Series(dtype=float)
            scored_df["is_alert"] = pd.Series(dtype=bool)
            scored_df["predicted_class"] = pd.Series(dtype=str)
            return scored_df

        self.model.eval()
        data = self.builder.build_graph(X_df, meta_df, is_train=False).to(self.device)
        with torch.no_grad():
            logits = self.model(data.x, data.edge_index, data.edge_attr)
            window_probs = torch.sigmoid(logits).cpu().numpy()
        probs = np.empty(len(meta_df), dtype=np.float32)
        probs[data.flow_order.cpu().numpy()] = window_probs

        scored_df = meta_df.copy()
        scored_df["risk_score"] = np.round(probs.astype(float), 4)
        scored_df["is_alert"] = scored_df["risk_score"] >= self.optimal_threshold
        scored_df["predicted_class"] = np.where(scored_df["is_alert"], "GNN-Anomaly", "BENIGN")
        alerts_count = scored_df["is_alert"].sum()
        print(f"[GNN Detector] Scored {len(scored_df):,} test flows -> {alerts_count:,} ALERTS flagged (Threshold={self.optimal_threshold})")
        return scored_df

    def _resolve_checkpoint_path(self, path: Optional[Union[Path, str]] = None) -> Path:
        if path is None:
            return MODELS_DIR / f"{self.model_name}.pt"
        p = Path(path)
        if p.is_dir() or p.suffix == "":
            return p / f"{self.model_name}.pt"
        return p

    @staticmethod
    def migrate_legacy_checkpoint(
        source: Union[Path, str], destination: Union[Path, str]
    ) -> Path:
        """Wrap a compatible v1 artifact in v2 metadata without claiming unknown history.

        The destination must be new; this method never alters the source checkpoint.
        The 300-second window records the graph window used for future inference by
        the v2 builder. The legacy training graph window remains explicitly unknown.
        """
        source_path, destination_path = Path(source), Path(destination)
        if source_path.resolve() == destination_path.resolve():
            raise ValueError("Migration destination must differ from the source checkpoint.")
        if destination_path.exists():
            raise FileExistsError(f"Migration destination already exists: {destination_path}")
        try:
            legacy = torch.load(source_path, map_location="cpu", weights_only=False)
        except TypeError:
            legacy = torch.load(source_path, map_location="cpu")
        if not isinstance(legacy, dict):
            raise ValueError("Invalid legacy GNN checkpoint: expected a dictionary.")
        required = {
            "model_state", "optimal_threshold", "hidden_dim", "feature_columns",
            "node_scaler", "edge_scaler",
        }
        missing = sorted(required - set(legacy))
        if missing:
            raise ValueError(f"Invalid legacy GNN checkpoint: missing fields {missing}.")
        columns = legacy["feature_columns"]
        node_scaler, edge_scaler = legacy["node_scaler"], legacy["edge_scaler"]
        if not isinstance(columns, list) or not columns or len(columns) != len(set(columns)):
            raise ValueError("Invalid legacy GNN checkpoint: feature columns are empty or duplicated.")
        if getattr(node_scaler, "n_features_in_", None) != len(NODE_FEATURE_COLUMNS):
            raise ValueError("Legacy node scaler is incompatible with the v2 node feature schema.")
        if getattr(edge_scaler, "n_features_in_", None) != len(columns):
            raise ValueError("Legacy edge scaler does not match the stored feature columns.")
        if not hasattr(node_scaler, "mean_") or not hasattr(edge_scaler, "mean_"):
            raise ValueError("Legacy checkpoint scalers are not fitted.")

        hidden_dim = int(legacy["hidden_dim"])
        edge_dim = len(columns)
        threshold = float(legacy["optimal_threshold"])
        if not np.isfinite(threshold) or not 0 <= threshold <= 1:
            raise ValueError("Legacy checkpoint threshold must be in [0, 1].")
        # v1 did not serialize dropout. The repository's training entry point
        # constructs GNNDetector() with its source-defined default of 0.2.
        dropout = 0.2
        model = EdgeGraphSAGE(len(NODE_FEATURE_COLUMNS), edge_dim, hidden_dim, dropout)
        try:
            model.load_state_dict(legacy["model_state"], strict=True)
        except (RuntimeError, TypeError) as exc:
            raise ValueError(f"Legacy model weights are structurally incompatible: {exc}") from exc

        migrated = {
            "checkpoint_version": CHECKPOINT_VERSION,
            "model_state": legacy["model_state"],
            "optimal_threshold": threshold,
            "hidden_dim": hidden_dim,
            "dropout": dropout,
            "graph_window_seconds": GRAPH_TIME_WINDOW_SECS,
            "node_to_idx": legacy.get("node_to_idx", {}),
            "feature_columns": columns,
            "node_scaler": node_scaler,
            "edge_scaler": edge_scaler,
            "training_provenance": None,
            "migration_metadata": {
                "kind": LEGACY_MIGRATION_KIND,
                "source_schema": 1,
                "source_checkpoint": str(source_path),
                "training_graph_window_seconds": None,
                "inference_graph_window_seconds": GRAPH_TIME_WINDOW_SECS,
                "training_provenance_status": "unavailable",
                "dropout_basis": "GNNDetector source default and main.py default construction",
            },
        }
        destination_path.parent.mkdir(parents=True, exist_ok=True)
        torch.save(migrated, destination_path)
        return destination_path

    def save(self, filepath: Optional[Union[Path, str]] = None):
        if self.model is None:
            raise ValueError("Cannot save untrained GNN model. Call train() before save().")
        if self.training_provenance is None:
            raise ValueError(
                "Cannot save a GNN checkpoint without training split provenance. Train the model first."
            )
        target_path = self._resolve_checkpoint_path(filepath)
        target_path.parent.mkdir(parents=True, exist_ok=True)
        torch.save({
            "checkpoint_version": CHECKPOINT_VERSION,
            "model_state": self.model.state_dict(),
            "optimal_threshold": self.optimal_threshold,
            "hidden_dim": self.hidden_dim,
            "dropout": self.dropout,
            "graph_window_seconds": self.builder.window_seconds,
            "node_to_idx": self.builder.node_to_idx,
            "feature_columns": self.builder.feature_columns,
            "node_scaler": self.builder.node_scaler,
            "edge_scaler": self.builder.edge_scaler,
            "training_provenance": self.training_provenance,
        }, target_path)
        print(f"[GNN Detector] Model checkpoint saved to {target_path}")

    def load(self, filepath: Optional[Union[Path, str]] = None):
        target_path = self._resolve_checkpoint_path(filepath)
        if not target_path.exists():
            raise FileNotFoundError(
                f"GNN model checkpoint not found at {target_path}. "
                f"Please train the model first or verify the checkpoint path."
            )
        try:
            checkpoint = torch.load(target_path, map_location=self.device, weights_only=False)
        except TypeError:
            checkpoint = torch.load(target_path, map_location=self.device)
        if not isinstance(checkpoint, dict):
            raise ValueError(f"Invalid GNN checkpoint at {target_path}: expected a dictionary.")
        if checkpoint.get("checkpoint_version") != CHECKPOINT_VERSION:
            raise ValueError(
                f"Incompatible GNN checkpoint at {target_path}: expected version "
                f"{CHECKPOINT_VERSION} with time-windowed graph metadata. Retrain it with "
                "`python main.py --model gnn`."
            )
        required = {
            "model_state", "feature_columns", "node_scaler", "edge_scaler",
            "hidden_dim", "dropout", "graph_window_seconds", "training_provenance",
        }
        missing = sorted(required - set(checkpoint))
        if missing:
            raise ValueError(
                f"Invalid GNN checkpoint at {target_path}: missing fields {missing}."
            )
        feature_columns = checkpoint["feature_columns"]
        node_scaler = checkpoint["node_scaler"]
        edge_scaler = checkpoint["edge_scaler"]
        if not isinstance(feature_columns, list) or not feature_columns:
            raise ValueError(f"Invalid GNN checkpoint at {target_path}: feature schema is empty.")
        if len(feature_columns) != len(set(feature_columns)):
            raise ValueError(f"Invalid GNN checkpoint at {target_path}: duplicate features.")
        if getattr(node_scaler, "n_features_in_", None) != len(NODE_FEATURE_COLUMNS):
            raise ValueError(
                f"Invalid GNN checkpoint at {target_path}: unexpected node feature count."
            )
        if getattr(edge_scaler, "n_features_in_", None) != len(feature_columns):
            raise ValueError(
                f"Invalid GNN checkpoint at {target_path}: edge scaler does not match feature schema."
            )
        if int(checkpoint["graph_window_seconds"]) != GRAPH_TIME_WINDOW_SECS:
            raise ValueError(
                f"Incompatible GNN checkpoint at {target_path}: graph window is "
                f"{checkpoint['graph_window_seconds']} seconds, expected {GRAPH_TIME_WINDOW_SECS}."
            )
        threshold = float(checkpoint.get("optimal_threshold", ALERT_RISK_THRESHOLD))
        if not np.isfinite(threshold) or not 0.0 <= threshold <= 1.0:
            raise ValueError(f"Invalid GNN checkpoint at {target_path}: threshold must be in [0, 1].")

        self.optimal_threshold = threshold
        self.hidden_dim = int(checkpoint["hidden_dim"])
        self.dropout = float(checkpoint["dropout"])
        self.builder = GraphDataBuilder(window_seconds=int(checkpoint["graph_window_seconds"]))
        self.builder.node_to_idx = checkpoint.get("node_to_idx", {})
        self.builder.feature_columns = feature_columns
        self.builder.node_scaler = node_scaler
        self.builder.edge_scaler = edge_scaler
        migration = checkpoint.get("migration_metadata")
        is_legacy_migration = (
            isinstance(migration, dict) and migration.get("kind") == LEGACY_MIGRATION_KIND
        )
        provenance = checkpoint["training_provenance"]
        if provenance is None and not is_legacy_migration:
            raise ValueError("Checkpoint has no training provenance and is not marked as migrated legacy GNN.")
        if provenance is not None and not isinstance(provenance, dict):
            raise ValueError("Invalid GNN checkpoint: training provenance must be a dictionary or null.")
        self.training_provenance = provenance
        self.migration_metadata = migration if is_legacy_migration else None

        node_dim = int(node_scaler.n_features_in_)
        edge_dim = len(feature_columns)
        self.model = EdgeGraphSAGE(
            node_in_dim=node_dim,
            edge_in_dim=edge_dim,
            hidden_dim=self.hidden_dim,
            dropout=self.dropout,
        ).to(self.device)
        self.model.load_state_dict(checkpoint["model_state"])
        self.model.eval()
        label = " (migrated legacy GNN; temporal provenance unavailable)" if is_legacy_migration else ""
        print(f"[GNN Detector] Model checkpoint loaded from {target_path}{label}")

    def validate_inference_split(self, meta_df: pd.DataFrame) -> None:
        """Reject checkpoints whose recorded training horizon reaches the inference split."""
        if self.training_provenance is None:
            raise ValueError(
                "Migrated legacy GNN has no training provenance; temporally isolated evaluation "
                "cannot be claimed or validated."
            )
        if "timestamp" not in meta_df or meta_df.empty:
            raise ValueError("GNN inference split must contain timestamps.")
        test_timestamps = pd.to_datetime(
            meta_df["timestamp"], format="mixed", utc=True, errors="coerce"
        )
        if test_timestamps.isna().any():
            raise ValueError("GNN inference split contains invalid timestamps.")
        trained_through = pd.to_datetime(
            self.training_provenance["max_training_timestamp"], utc=True, errors="raise"
        )
        test_starts = test_timestamps.min()
        if trained_through >= test_starts:
            raise ValueError(
                "GNN checkpoint temporal leakage check failed: training data ends at "
                f"{trained_through.isoformat()}, while inference begins at "
                f"{test_starts.isoformat()}."
            )
