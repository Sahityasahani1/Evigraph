"""
EviGraph Refined Baseline Detector: Finetuned Multi-Class XGBoost with Platt Risk Calibration
Adheres to TRD Section 3.3.1, 3.3.5, and PRD FR-3.1 / FR-3.6:
- Multi-class intrusion detection across all CICIDS2017 attack families
- Balanced sample class weighting for rare attack classes
- L1/L2 regularization and feature bagging
- Early stopping on validation loss
- Platt scaling risk probability calibration (LogisticRegression)
- F1 threshold optimization and comprehensive forensic evaluation
"""

import pandas as pd
import numpy as np
import xgboost as xgb
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    classification_report, 
    precision_recall_fscore_support, 
    roc_auc_score, 
    average_precision_score, 
    confusion_matrix
)
from sklearn.preprocessing import LabelEncoder
import joblib
from pathlib import Path
from typing import Dict, Any, Tuple, Optional
from src.config import MODELS_DIR, ALERT_RISK_THRESHOLD

class BaselineDetector:
    def __init__(self, model_name: str = "xgboost_finetuned"):
        self.model_name = model_name
        self.label_encoder = LabelEncoder()
        self.base_model: Optional[xgb.XGBClassifier] = None
        self.calibrator: Optional[LogisticRegression] = None
        self.feature_columns: list = []
        self.optimal_threshold: float = ALERT_RISK_THRESHOLD
        self.classes_: list = []

    def train(
        self, 
        X_train: pd.DataFrame, 
        y_train: pd.Series, 
        X_val: pd.DataFrame, 
        y_val: pd.Series,
        early_stopping_rounds: int = 20
    ) -> Dict[str, Any]:
        """
        Finetunes multi-class XGBoost with ML fundamentals:
        - Filters ultra-rare training classes (< 5 samples)
        - Computes balanced sample weights
        - Fits regularized XGBoost with early stopping
        - Calibrates risk probability via Platt scaling
        - Tunes threshold for maximum F1
        """
        # 1. Feature selection: drop constant/zero-variance columns in training data
        variances = X_train.var()
        non_constant_cols = variances[variances > 1e-8].index.tolist()
        self.feature_columns = non_constant_cols
        
        X_tr = X_train[self.feature_columns].replace([np.inf, -np.inf], np.nan).fillna(0)
        X_v = X_val[self.feature_columns].replace([np.inf, -np.inf], np.nan).fillna(0)

        # 2. Exclude ultra-rare classes with < 5 samples in training
        counts_series = y_train.value_counts()
        rare_classes = counts_series[counts_series < 5].index.tolist()
        if rare_classes:
            print(f"[Detector] Excluding ultra-rare classes from training (< 5 samples): {rare_classes}")
            keep_mask = ~y_train.isin(rare_classes)
            X_tr = X_tr[keep_mask]
            y_train = y_train[keep_mask]

        # 3. Encode multi-class labels
        y_train_encoded = self.label_encoder.fit_transform(y_train)
        self.classes_ = list(self.label_encoder.classes_)
        num_classes = len(self.classes_)

        # Prepare clean validation split for known training classes
        val_mask = y_val.isin(self.classes_)
        if not val_mask.any():
            X_val_clean = X_tr
            y_val_encoded = y_train_encoded
        else:
            X_val_clean = X_v[val_mask]
            y_val_encoded = self.label_encoder.transform(y_val[val_mask])

        # 4. Balanced sample weights
        classes, counts = np.unique(y_train_encoded, return_counts=True)
        total_samples = len(y_train_encoded)
        class_weight_dict = {
            cls: float(total_samples / (len(classes) * cnt))
            for cls, cnt in zip(classes, counts)
        }
        sample_weights = np.array([class_weight_dict[y] for y in y_train_encoded])

        print(f"[Detector] Training Multi-Class XGBoost on {len(X_tr):,} flows across {num_classes} classes...")
        for cls_name, cls_idx in zip(self.classes_, classes):
            cnt = counts[cls_idx]
            wt = class_weight_dict[cls_idx]
            print(f"   * Class '{cls_name:<26}': {cnt:>7,} flows (weight: {wt:>7.3f})")

        # 5. Hyperparameter configuration with L1/L2 regularization & GPU Acceleration
        import torch
        device = "cuda" if torch.cuda.is_available() else "cpu"
        device_name = torch.cuda.get_device_name(0) if device == "cuda" else "CPU"
        print(f"[Detector] Hardware Accelerator: {device.upper()} ({device_name})")

        eval_metric = "logloss" if num_classes == 2 else "mlogloss"
        self.base_model = xgb.XGBClassifier(
            n_estimators=300,
            max_depth=6,
            learning_rate=0.06,
            subsample=0.8,
            colsample_bytree=0.8,
            reg_alpha=0.1,      # L1 Lasso regularization
            reg_lambda=1.5,     # L2 Ridge regularization
            eval_metric=eval_metric,
            tree_method="hist", # Optimized fast histogram method
            device=device,      # Real NVIDIA GPU acceleration
            random_state=42,
            n_jobs=-1,
            early_stopping_rounds=early_stopping_rounds
        )

        # 6. Fit with early stopping
        self.base_model.fit(
            X_tr, 
            y_train_encoded, 
            sample_weight=sample_weights,
            eval_set=[(X_val_clean, y_val_encoded)],
            verbose=False
        )
        best_iter = getattr(self.base_model, "best_iteration", 300)
        print(f"[Detector] Early stopping triggered at iteration {best_iter}")

        # 7. Platt Scaling Probability Calibration (TRD Sec 3.3.1)
        print("[Detector] Calibrating Risk Scores via Platt Scaling...")
        val_probs_raw = self.base_model.predict_proba(X_val_clean)
        val_preds = np.argmax(val_probs_raw, axis=1)

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

        # 8. Threshold Optimization
        if np.sum(y_val_binary) > 0 and np.sum(y_val_binary) < len(y_val_binary):
            best_f1, best_th = 0.0, ALERT_RISK_THRESHOLD
            for th in np.linspace(0.20, 0.85, 27):
                pred_binary = (val_calibrated_risk >= th).astype(int)
                _, _, f1, _ = precision_recall_fscore_support(
                    y_val_binary, pred_binary, average="binary", zero_division=0
                )
                if f1 > best_f1:
                    best_f1 = f1
                    best_th = th
            self.optimal_threshold = round(float(best_th), 3)
            print(f"[Detector] Optimized Risk Alert Threshold: {self.optimal_threshold} (Validation F1={best_f1:.4f})")
        else:
            self.optimal_threshold = ALERT_RISK_THRESHOLD

        # 9. Performance reporting
        report = classification_report(
            y_val_encoded, 
            val_preds, 
            labels=list(range(num_classes)),
            target_names=self.classes_, 
            output_dict=True,
            zero_division=0
        )
        print("\n[Detector] Multi-Class Validation Report:")
        print(classification_report(
            y_val_encoded, 
            val_preds, 
            labels=list(range(num_classes)),
            target_names=self.classes_, 
            zero_division=0
        ))

        if len(np.unique(y_val_binary)) > 1:
            roc_auc = roc_auc_score(y_val_binary, val_calibrated_risk)
            pr_auc = average_precision_score(y_val_binary, val_calibrated_risk)
            tn, fp, fn, tp = confusion_matrix(y_val_binary, (val_calibrated_risk >= self.optimal_threshold).astype(int)).ravel()
            fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
            print(f"[Detector] Binary Validation Metrics:")
            print(f"   * ROC-AUC : {roc_auc:.4f}")
            print(f"   * PR-AUC  : {pr_auc:.4f}")
            print(f"   * Benign FPR : {fpr * 100:.2f}% (Target: < 1.0%)")

        return report

    def score_flows(self, X: pd.DataFrame, meta_df: pd.DataFrame, threshold: Optional[float] = None) -> pd.DataFrame:
        """
        Produces per-flow calibrated risk scores in [0, 1] and flags alerts.
        """
        if self.base_model is None:
            raise ValueError("Model has not been trained or loaded yet.")
            
        th = threshold or self.optimal_threshold
        X_clean = X[self.feature_columns].replace([np.inf, -np.inf], np.nan).fillna(0)
        
        probs = self.base_model.predict_proba(X_clean)
        pred_idx = np.argmax(probs, axis=1)
        pred_classes = [self.classes_[idx] for idx in pred_idx]
        
        # Raw risk
        if "BENIGN" in self.classes_:
            benign_idx = self.classes_.index("BENIGN")
            raw_risk = 1.0 - probs[:, benign_idx]
        else:
            raw_risk = np.max(probs, axis=1)
            
        # Calibrated risk via Platt scaling
        if self.calibrator is not None:
            calibrated_risk = self.calibrator.predict_proba(raw_risk.reshape(-1, 1))[:, 1]
        else:
            calibrated_risk = raw_risk
            
        scored_df = meta_df.copy()
        scored_df["risk_score"] = np.round(calibrated_risk, 4)
        scored_df["predicted_class"] = pred_classes
        scored_df["is_alert"] = scored_df["risk_score"] >= th
        
        scored_df["class_probabilities"] = [
            {self.classes_[i]: round(float(p), 4) for i, p in enumerate(row_probs)}
            for row_probs in probs
        ]
        
        alerts_count = scored_df["is_alert"].sum()
        print(f"[Detector] Scored {len(scored_df):,} test flows -> {alerts_count:,} ALERTS flagged (Threshold={th})")
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
        print(f"[Detector] Saved model artifacts to {model_path}")

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
        print(f"[Detector] Loaded model from {model_path} with {len(self.feature_columns)} features across {len(self.classes_)} classes")
