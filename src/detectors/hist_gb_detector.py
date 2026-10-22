"""
EviGraph Scikit-Learn Native Histogram Gradient Boosting Detector
Zero-dependency high-throughput gradient boosting classifier (LightGBM equivalent in scikit-learn).
Provides complementary multi-class decision trees for dual-tree statistical ensembling.
"""

import os
os.environ["LOKY_MAX_CPU_COUNT"] = str(os.cpu_count() or 4)

import pandas as pd
import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, precision_recall_fscore_support
from sklearn.preprocessing import LabelEncoder
import joblib
from pathlib import Path
from typing import Dict, Any, Optional

from src.config import MODELS_DIR, ALERT_RISK_THRESHOLD

class HistGBDetector:
    def __init__(self, model_name: str = "hist_gb_detector"):
        self.model_name = model_name
        self.label_encoder = LabelEncoder()
        self.base_model: Optional[HistGradientBoostingClassifier] = None
        self.calibrator: Optional[LogisticRegression] = None
        self.feature_columns: list = []
        self.optimal_threshold: float = ALERT_RISK_THRESHOLD
        self.classes_: list = []

    def train(
        self,
        X_train: pd.DataFrame,
        y_train: pd.Series,
        X_val: pd.DataFrame,
        y_val: pd.Series
    ) -> Dict[str, Any]:
        """
        Trains multi-class HistGradientBoosting with balanced sample weighting.
        """
        # 1. Feature selection
        variances = X_train.var()
        self.feature_columns = variances[variances > 1e-8].index.tolist()
        
        X_tr = X_train[self.feature_columns].replace([np.inf, -np.inf], np.nan).fillna(0).astype(np.float32)
        X_v = X_val[self.feature_columns].replace([np.inf, -np.inf], np.nan).fillna(0).astype(np.float32)

        # 2. Exclude ultra-rare classes (< 5 samples in training)
        counts_series = y_train.value_counts()
        rare_classes = counts_series[counts_series < 5].index.tolist()
        if rare_classes:
            keep_mask = ~y_train.isin(rare_classes)
            X_tr = X_tr[keep_mask]
            y_train = y_train[keep_mask]

        # 3. Label encoding
        y_tr_encoded = self.label_encoder.fit_transform(y_train)
        self.classes_ = list(self.label_encoder.classes_)
        num_classes = len(self.classes_)

        val_mask = y_val.isin(self.classes_)
        X_val_clean = X_v[val_mask] if val_mask.any() else X_tr
        y_val_encoded = self.label_encoder.transform(y_val[val_mask]) if val_mask.any() else y_tr_encoded

        # 4. Class weighting
        classes, counts = np.unique(y_tr_encoded, return_counts=True)
        total_samples = len(y_tr_encoded)
        class_weight_dict = {
            cls: float(total_samples / (len(classes) * cnt))
            for cls, cnt in zip(classes, counts)
        }
        sample_weights = np.array([class_weight_dict[y] for y in y_tr_encoded])

        print(f"\n[HistGB Detector] Training Native Histogram Gradient Boosting on {len(X_tr):,} flows...")
        
        # 5. Model configuration
        self.base_model = HistGradientBoostingClassifier(
            max_iter=100,
            max_depth=8,
            learning_rate=0.08,
            min_samples_leaf=25,
            l2_regularization=1.5,
            early_stopping=True,
            validation_fraction=0.1,
            n_iter_no_change=12,
            random_state=42
        )

        # 6. Fit model
        self.base_model.fit(X_tr, y_tr_encoded, sample_weight=sample_weights)
        print(f"[HistGB Detector] Training converged after {self.base_model.n_iter_} iterations")

        # 7. Platt Scaling Calibration
        val_probs_raw = self.base_model.predict_proba(X_val_clean)
        if "BENIGN" in self.classes_:
            benign_idx = self.classes_.index("BENIGN")
            val_raw_risk = 1.0 - val_probs_raw[:, benign_idx]
            y_val_binary = (y_val_encoded != benign_idx).astype(int)
        else:
            val_raw_risk = np.max(val_probs_raw, axis=1)
            y_val_binary = (y_val_encoded > 0).astype(int)

        if len(np.unique(y_val_binary)) > 1:
            self.calibrator = LogisticRegression(C=1.0, max_iter=200)
            self.calibrator.fit(val_raw_risk.reshape(-1, 1), y_val_binary)
            val_calibrated_risk = self.calibrator.predict_proba(val_raw_risk.reshape(-1, 1))[:, 1]
        else:
            self.calibrator = None
            val_calibrated_risk = val_raw_risk

        # 8. Optimal threshold sweep
        if np.sum(y_val_binary) > 0 and np.sum(y_val_binary) < len(y_val_binary):
            best_f1, best_th = 0.0, ALERT_RISK_THRESHOLD
            for th in np.linspace(0.20, 0.85, 27):
                pred_b = (val_calibrated_risk >= th).astype(int)
                _, _, f1, _ = precision_recall_fscore_support(y_val_binary, pred_b, average="binary", zero_division=0)
                if f1 > best_f1:
                    best_f1 = f1
                    best_th = th
            self.optimal_threshold = round(float(best_th), 3)
            print(f"[HistGB Detector] Calibrated Threshold: {self.optimal_threshold} (Val F1={best_f1:.4f})")

        return {"n_iter": self.base_model.n_iter_, "threshold": self.optimal_threshold}

    def score_flows(self, X: pd.DataFrame, meta_df: pd.DataFrame) -> pd.DataFrame:
        """Produces calibrated flow risk scores and predicted attack classes."""
        if self.base_model is None:
            raise ValueError("HistGB Detector has not been trained or loaded.")
            
        X_clean = X[self.feature_columns].replace([np.inf, -np.inf], np.nan).fillna(0).astype(np.float32)
        probs = self.base_model.predict_proba(X_clean)
        pred_idx = np.argmax(probs, axis=1)
        pred_classes = [self.classes_[idx] for idx in pred_idx]

        if "BENIGN" in self.classes_:
            benign_idx = self.classes_.index("BENIGN")
            raw_risk = 1.0 - probs[:, benign_idx]
        else:
            raw_risk = np.max(probs, axis=1)

        if self.calibrator is not None:
            calibrated_risk = self.calibrator.predict_proba(raw_risk.reshape(-1, 1))[:, 1]
        else:
            calibrated_risk = raw_risk

        scored_df = meta_df.copy()
        scored_df["histgb_risk_score"] = np.round(calibrated_risk, 4)
        scored_df["risk_score"] = scored_df["histgb_risk_score"]
        scored_df["predicted_class"] = pred_classes
        scored_df["is_alert"] = scored_df["risk_score"] >= self.optimal_threshold
        return scored_df

    def save(self, output_dir: Path = MODELS_DIR):
        output_dir.mkdir(parents=True, exist_ok=True)
        model_path = output_dir / f"{self.model_name}.joblib"
        meta_path = output_dir / f"{self.model_name}_meta.joblib"
        joblib.dump({"base": self.base_model, "calibrator": self.calibrator}, model_path)
        joblib.dump({
            "classes": self.classes_,
            "features": self.feature_columns,
            "threshold": self.optimal_threshold
        }, meta_path)
        print(f"[HistGB Detector] Saved model to {model_path}")

    def load(self, model_dir: Path = MODELS_DIR):
        model_path = model_dir / f"{self.model_name}.joblib"
        meta_path = model_dir / f"{self.model_name}_meta.joblib"
        models = joblib.load(model_path)
        self.base_model = models["base"]
        self.calibrator = models["calibrator"]
        meta = joblib.load(meta_path)
        self.classes_ = meta["classes"]
        self.feature_columns = meta["features"]
        self.optimal_threshold = meta.get("threshold", ALERT_RISK_THRESHOLD)
        print(f"[HistGB Detector] Loaded model from {model_path}")
