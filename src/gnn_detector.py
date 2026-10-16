"""
EviGraph GNN Edge Classifier: PyTorch Geometric Edge-GraphSAGE
Adheres to TRD Section 3.3.2 and PRD FR-3.2:
- Network flows represented as directed multigraph edges between host nodes
- Node structural features: in/out degree, fan-out, total byte volume
- Edge features: canonical flow statistical features (anti-leakage: raw IPs/ports excluded)
- 2-layer GraphSAGE message passing over host topology
- Edge MLP classifier predicting anomaly risk probability P(alert | u, v, e)
- Accelerated via NVIDIA CUDA GPU
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import SAGEConv
from torch_geometric.data import Data
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import precision_recall_fscore_support, roc_auc_score, average_precision_score
import pandas as pd
import numpy as np
from pathlib import Path
from typing import Dict, Any, Tuple, Optional, List

from src.config import MODELS_DIR, ALERT_RISK_THRESHOLD

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
    def __init__(self):
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
        # 1. Map all unique hosts across dataset to graph node indices
        all_hosts = sorted(list(set(meta_df["src_ip"].astype(str)).union(set(meta_df["dst_ip"].astype(str)))))
        if is_train or not self.node_to_idx:
            self.node_to_idx = {h: i for i, h in enumerate(all_hosts)}
        else:
            # Add any unseen test hosts to index dictionary
            for h in all_hosts:
                if h not in self.node_to_idx:
                    self.node_to_idx[h] = len(self.node_to_idx)

        num_nodes = len(self.node_to_idx)

        # 2. Compute Node Structural Features (degrees, fan-out, volumes)
        node_stats = {h: {"in_deg": 0, "out_deg": 0, "fan_out": set(), "bytes_sent": 0.0, "bytes_recv": 0.0} 
                      for h in self.node_to_idx}
        
        src_ips = meta_df["src_ip"].astype(str).values
        dst_ips = meta_df["dst_ip"].astype(str).values
        bytes_sent = X_df.get("totlen_fwd_pkts", pd.Series(0.0, index=X_df.index)).fillna(0).values
        bytes_recv = X_df.get("totlen_bwd_pkts", pd.Series(0.0, index=X_df.index)).fillna(0).values

        for s, d, bs, br in zip(src_ips, dst_ips, bytes_sent, bytes_recv):
            if s in node_stats:
                node_stats[s]["out_deg"] += 1
                node_stats[s]["fan_out"].add(d)
                node_stats[s]["bytes_sent"] += bs
            if d in node_stats:
                node_stats[d]["in_deg"] += 1
                node_stats[d]["bytes_recv"] += br

        node_feat_rows = []
        for h, idx in sorted(self.node_to_idx.items(), key=lambda x: x[1]):
            st = node_stats.get(h, {"in_deg": 0, "out_deg": 0, "fan_out": set(), "bytes_sent": 0.0, "bytes_recv": 0.0})
            node_feat_rows.append([
                np.log1p(st["in_deg"]),
                np.log1p(st["out_deg"]),
                np.log1p(len(st["fan_out"])),
                np.log1p(max(0.0, float(st["bytes_sent"]))),
                np.log1p(max(0.0, float(st["bytes_recv"])))
            ])

        node_features_raw = np.array(node_feat_rows, dtype=np.float32)
        if is_train:
            node_features = self.node_scaler.fit_transform(node_features_raw)
        else:
            node_features = self.node_scaler.transform(node_features_raw)

        # 3. Build Edge Index
        src_indices = [self.node_to_idx[s] for s in src_ips]
        dst_indices = [self.node_to_idx[d] for d in dst_ips]
        edge_index = torch.tensor([src_indices, dst_indices], dtype=torch.long)

        # 4. Build Edge Attributes (normalized flow features)
        X_clean = X_df.replace([np.inf, -np.inf], np.nan).fillna(0.0).values
        if is_train:
            self.feature_columns = list(X_df.columns)
            edge_attr = self.edge_scaler.fit_transform(X_clean)
        else:
            edge_attr = self.edge_scaler.transform(X_clean)

        # 5. Build Edge Labels
        y_tensor = None
        if y_series is not None:
            y_binary = (y_series != "BENIGN").astype(np.float32).values
            y_tensor = torch.tensor(y_binary, dtype=torch.float32)

        data = Data(
            x=torch.tensor(node_features, dtype=torch.float32),
            edge_index=edge_index,
            edge_attr=torch.tensor(edge_attr, dtype=torch.float32),
            y=y_tensor
        )
        return data


class GNNDetector:
    """End-to-End PyG GNN Detector for EviGraph."""
    def __init__(self, hidden_dim: int = 64, lr: float = 0.003, model_name: str = "gnn_edge_sage"):
        self.model_name = model_name
        self.hidden_dim = hidden_dim
        self.lr = lr
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.model: Optional[EdgeGraphSAGE] = None
        self.builder = GraphDataBuilder()
        self.optimal_threshold: float = ALERT_RISK_THRESHOLD

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
        """Trains Edge-GraphSAGE detector with class reweighting on CUDA."""
        print(f"\n[GNN Detector] Preparing Graph Datasets (Hardware: {str(self.device).upper()})...")
        train_data = self.builder.build_graph(X_train, meta_train, y_train, is_train=True).to(self.device)
        val_data = self.builder.build_graph(X_val, meta_val, y_val, is_train=False).to(self.device)

        node_dim = train_data.x.shape[1]
        edge_dim = train_data.edge_attr.shape[1]
        num_train_edges = train_data.edge_index.shape[1]

        self.model = EdgeGraphSAGE(
            node_in_dim=node_dim,
            edge_in_dim=edge_dim,
            hidden_dim=self.hidden_dim
        ).to(self.device)

        # Class imbalance weighting
        pos_count = float(train_data.y.sum().item())
        neg_count = float(num_train_edges - pos_count)
        pos_weight = torch.tensor([neg_count / max(1.0, pos_count)], device=self.device)
        criterion = nn.BCEWithLogitsLoss(pos_weight=pos_weight)
        optimizer = torch.optim.AdamW(self.model.parameters(), lr=self.lr, weight_decay=1e-4)

        print(f"[GNN Detector] Training on {train_data.x.shape[0]:,} host nodes and {num_train_edges:,} flow edges...")
        print(f"   * Positive Alert Weight: {pos_weight.item():.2f}")

        best_val_f1 = 0.0
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

        if best_state is not None:
            self.model.load_state_dict({k: v.to(self.device) for k, v in best_state.items()})

        print(f"[GNN Detector] Optimization complete! Best Validation F1: {best_val_f1:.4f}")
        return {"best_f1": best_val_f1, "optimal_threshold": self.optimal_threshold}

    def score_flows(self, X_df: pd.DataFrame, meta_df: pd.DataFrame) -> pd.DataFrame:
        """Runs GNN inference over held-out flows, computing topology-aware edge risk scores."""
        self.model.eval()
        data = self.builder.build_graph(X_df, meta_df, is_train=False).to(self.device)
        with torch.no_grad():
            logits = self.model(data.x, data.edge_index, data.edge_attr)
            probs = torch.sigmoid(logits).cpu().numpy()

        scored_df = meta_df.copy()
        scored_df["risk_score"] = probs
        scored_df["is_alert"] = scored_df["risk_score"] >= self.optimal_threshold
        scored_df["predicted_class"] = np.where(scored_df["is_alert"], "GNN-Anomaly", "BENIGN")
        return scored_df

    def save(self, filepath: Optional[Path] = None):
        filepath = filepath or (MODELS_DIR / f"{self.model_name}.pt")
        filepath.parent.mkdir(parents=True, exist_ok=True)
        torch.save({
            "model_state": self.model.state_dict(),
            "optimal_threshold": self.optimal_threshold,
            "node_to_idx": self.builder.node_to_idx,
            "feature_columns": self.builder.feature_columns,
            "node_scaler": self.builder.node_scaler,
            "edge_scaler": self.builder.edge_scaler
        }, filepath)
        print(f"[GNN Detector] Model checkpoint saved to {filepath}")

    def load(self, filepath: Optional[Path] = None):
        filepath = filepath or (MODELS_DIR / f"{self.model_name}.pt")
        checkpoint = torch.load(filepath, map_location=self.device)
        self.optimal_threshold = checkpoint["optimal_threshold"]
        self.builder.node_to_idx = checkpoint["node_to_idx"]
        self.builder.feature_columns = checkpoint["feature_columns"]
        self.builder.node_scaler = checkpoint["node_scaler"]
        self.builder.edge_scaler = checkpoint["edge_scaler"]
        
        node_dim = len(self.builder.node_scaler.mean_)
        edge_dim = len(self.builder.feature_columns)
        self.model = EdgeGraphSAGE(node_in_dim=node_dim, edge_in_dim=edge_dim, hidden_dim=self.hidden_dim).to(self.device)
        self.model.load_state_dict(checkpoint["model_state"])
        self.model.eval()
        print(f"[GNN Detector] Model checkpoint loaded from {filepath}")
