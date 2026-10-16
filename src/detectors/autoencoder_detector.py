"""
EviGraph Unsupervised Zero-Day Anomaly Detector: PyTorch Deep Autoencoder (CUDA-Accelerated)
Trained strictly on BENIGN network flows to learn normal enterprise traffic manifolds.
Detects unseen zero-day attacks and stealthy intrusions via reconstruction loss spikes.
"""

import torch
import torch.nn as nn
from torch.utils.data import TensorDataset, DataLoader
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
import pandas as pd
import numpy as np
from pathlib import Path
from typing import Dict, Any, Optional

from src.config import MODELS_DIR, ALERT_RISK_THRESHOLD

class FlowAutoencoder(nn.Module):
    """Deep Symmetric MLP Autoencoder for Statistical Network Flows."""
    def __init__(self, input_dim: int, hidden_dim1: int = 48, hidden_dim2: int = 24, bottleneck_dim: int = 8):
        super().__init__()
        # Encoder
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, hidden_dim1),
            nn.LayerNorm(hidden_dim1),
            nn.LeakyReLU(0.1),
            nn.Dropout(0.1),
            nn.Linear(hidden_dim1, hidden_dim2),
            nn.LayerNorm(hidden_dim2),
            nn.LeakyReLU(0.1),
            nn.Linear(hidden_dim2, bottleneck_dim)
        )
        # Decoder
        self.decoder = nn.Sequential(
            nn.Linear(bottleneck_dim, hidden_dim2),
            nn.LayerNorm(hidden_dim2),
            nn.LeakyReLU(0.1),
            nn.Dropout(0.1),
            nn.Linear(hidden_dim2, hidden_dim1),
            nn.LayerNorm(hidden_dim1),
            nn.LeakyReLU(0.1),
            nn.Linear(hidden_dim1, input_dim)
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        z = self.encoder(x)
        x_recon = self.decoder(z)
        return x_recon

class AutoencoderDetector:
    def __init__(self, model_name: str = "autoencoder_detector"):
        self.model_name = model_name
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.model: Optional[FlowAutoencoder] = None
        self.scaler = StandardScaler()
        self.calibrator: Optional[LogisticRegression] = None
        self.feature_columns: list = []
        self.baseline_mse_threshold: float = 1.0
        self.optimal_threshold: float = ALERT_RISK_THRESHOLD

    def train(
        self,
        X_train: pd.DataFrame,
        y_train: pd.Series,
        X_val: pd.DataFrame,
        y_val: pd.Series,
        epochs: int = 15,
        batch_size: int = 4096
    ) -> Dict[str, Any]:
        """
        Trains deep autoencoder ONLY on BENIGN enterprise flows.
        """
        print(f"\n[Autoencoder] Initializing Zero-Day Detector (Hardware: {str(self.device).upper()})...")
        
        # 1. Feature filtering
        variances = X_train.var()
        self.feature_columns = variances[variances > 1e-8].index.tolist()
        
        # 2. Filter strictly for BENIGN training flows (Unsupervised Normal Profiling)
        benign_mask = (y_train == "BENIGN")
        X_benign_train = X_train.loc[benign_mask, self.feature_columns].replace([np.inf, -np.inf], np.nan).fillna(0).astype(np.float32)
        print(f"[Autoencoder] Training strictly on {len(X_benign_train):,} BENIGN flows (Unsupervised baseline)...")

        # 3. Standardize features
        X_train_scaled = self.scaler.fit_transform(X_benign_train)
        
        # 4. PyTorch DataLoader
        tensor_x = torch.tensor(X_train_scaled, dtype=torch.float32)
        dataset = TensorDataset(tensor_x)
        loader = DataLoader(dataset, batch_size=batch_size, shuffle=True, drop_last=False)

        # 5. Model instantiation
        input_dim = len(self.feature_columns)
        self.model = FlowAutoencoder(input_dim=input_dim).to(self.device)
        criterion = nn.MSELoss()
        optimizer = torch.optim.AdamW(self.model.parameters(), lr=0.003, weight_decay=1e-5)
        scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=epochs, eta_min=1e-4)

        # 6. Training loop
        self.model.train()
        for epoch in range(1, epochs + 1):
            epoch_loss = 0.0
            for (batch_x,) in loader:
                batch_x = batch_x.to(self.device)
                optimizer.zero_grad()
                recon = self.model(batch_x)
                loss = criterion(recon, batch_x)
                loss.backward()
                optimizer.step()
                epoch_loss += loss.item() * len(batch_x)
            
            scheduler.step()
            avg_loss = epoch_loss / len(X_benign_train)
            if epoch % 5 == 0 or epoch == epochs:
                print(f"   * Epoch {epoch:>2}/{epochs} | Reconstruction MSE Loss: {avg_loss:.5f} | LR: {scheduler.get_last_lr()[0]:.6f}")

        # 7. Calibration on Validation Split
        print("[Autoencoder] Calibrating Anomaly Risk Scores on Validation Flows...")
        X_val_clean = X_val[self.feature_columns].replace([np.inf, -np.inf], np.nan).fillna(0).astype(np.float32)
        X_val_scaled = self.scaler.transform(X_val_clean)
        
        val_losses = self._compute_reconstruction_errors(X_val_scaled)
        y_val_binary = (y_val != "BENIGN").astype(int).values

        # Set 99.5th percentile of benign validation error as sharp baseline cut
        benign_val_mask = (y_val == "BENIGN").values
        if benign_val_mask.any():
            self.baseline_mse_threshold = float(np.percentile(val_losses[benign_val_mask], 99.5))
        else:
            self.baseline_mse_threshold = float(np.median(val_losses))

        # Platt scaling calibrator on log(1 + MSE)
        log_mse = np.log1p(val_losses).reshape(-1, 1)
        if len(np.unique(y_val_binary)) > 1:
            self.calibrator = LogisticRegression(C=1.0, max_iter=200)
            self.calibrator.fit(log_mse, y_val_binary)
            val_risk = self.calibrator.predict_proba(log_mse)[:, 1]
        else:
            self.calibrator = None
            val_risk = np.clip(val_losses / (self.baseline_mse_threshold * 2.0), 0.0, 1.0)

        print(f"[Autoencoder] Baseline Benign 99th-Percentile Cutoff: {self.baseline_mse_threshold:.4f}")
        return {
            "baseline_threshold": self.baseline_mse_threshold,
            "val_mean_loss": float(np.mean(val_losses))
        }

    def _compute_reconstruction_errors(self, X_scaled: np.ndarray, batch_size: int = 8192) -> np.ndarray:
        """Computes MSE reconstruction error vector across samples."""
        self.model.eval()
        tensor_x = torch.tensor(X_scaled, dtype=torch.float32)
        dataset = TensorDataset(tensor_x)
        loader = DataLoader(dataset, batch_size=batch_size, shuffle=False)
        
        all_losses = []
        with torch.no_grad():
            for (batch_x,) in loader:
                batch_x = batch_x.to(self.device)
                recon = self.model(batch_x)
                mse_per_sample = torch.mean((recon - batch_x) ** 2, dim=-1).cpu().numpy()
                all_losses.append(mse_per_sample)
                
        return np.concatenate(all_losses)

    def score_flows(self, X: pd.DataFrame, meta_df: pd.DataFrame) -> pd.DataFrame:
        """Computes per-flow reconstruction anomaly scores and calibrated risk probabilities."""
        if self.model is None:
            raise ValueError("Autoencoder model has not been trained or loaded.")
            
        X_clean = X[self.feature_columns].replace([np.inf, -np.inf], np.nan).fillna(0).astype(np.float32)
        X_scaled = self.scaler.transform(X_clean)
        
        mse_errors = self._compute_reconstruction_errors(X_scaled)
        
        # Calibrated risk
        if self.calibrator is not None:
            log_mse = np.log1p(mse_errors).reshape(-1, 1)
            risk_scores = self.calibrator.predict_proba(log_mse)[:, 1]
        else:
            risk_scores = np.clip(mse_errors / (self.baseline_mse_threshold * 2.0), 0.0, 1.0)
            
        scored_df = meta_df.copy()
        scored_df["autoencoder_raw_mse"] = np.round(mse_errors, 5)
        scored_df["risk_score"] = np.round(risk_scores, 4)
        scored_df["is_alert"] = scored_df["risk_score"] >= self.optimal_threshold
        scored_df["predicted_class"] = np.where(scored_df["is_alert"], "ZeroDay-Anomaly", "BENIGN")
        
        alerts_count = scored_df["is_alert"].sum()
        print(f"[Autoencoder] Scored {len(scored_df):,} flows -> {alerts_count:,} Zero-Day Anomaly ALERTS flagged")
        return scored_df

    def save(self, output_dir: Path = MODELS_DIR):
        output_dir.mkdir(parents=True, exist_ok=True)
        model_path = output_dir / f"{self.model_name}.pt"
        torch.save({
            "model_state": self.model.state_dict(),
            "scaler": self.scaler,
            "calibrator": self.calibrator,
            "feature_columns": self.feature_columns,
            "baseline_threshold": self.baseline_mse_threshold,
            "optimal_threshold": self.optimal_threshold
        }, model_path)
        print(f"[Autoencoder] Saved model checkpoint to {model_path}")

    def load(self, model_dir: Path = MODELS_DIR):
        model_path = model_dir / f"{self.model_name}.pt"
        checkpoint = torch.load(model_path, map_location=self.device)
        self.feature_columns = checkpoint["feature_columns"]
        self.scaler = checkpoint["scaler"]
        self.calibrator = checkpoint["calibrator"]
        self.baseline_mse_threshold = checkpoint["baseline_threshold"]
        self.optimal_threshold = checkpoint["optimal_threshold"]
        
        input_dim = len(self.feature_columns)
        self.model = FlowAutoencoder(input_dim=input_dim).to(self.device)
        self.model.load_state_dict(checkpoint["model_state"])
        self.model.eval()
        print(f"[Autoencoder] Loaded checkpoint from {model_path} with {input_dim} features")
