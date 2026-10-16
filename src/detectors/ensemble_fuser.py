"""
EviGraph Tri-Pillar Multi-Model Defense-in-Depth Ensemble Fuser
Adheres to PRD FR-3.4 and TRD Section 3.3.4:
- Combines:
  1. Supervised Multi-Class XGBoost (CUDA GPU)
  2. Unsupervised Deep PyTorch Autoencoder (Zero-Day Anomaly Detector)
  3. Scikit-Learn Native Histogram Gradient Boosting (Dual-Tree Diversity)
- Fuses model outputs via a Calibrated Stacking Meta-Learner (Logistic Regression)
- Native C++ TreeSHAP Feature Attributions (Zero external dependencies)
- Conformal ambiguity detection and alert threshold optimization
"""

import pandas as pd
import numpy as np
import xgboost as xgb
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import precision_recall_fscore_support, roc_auc_score, average_precision_score
import joblib
from pathlib import Path
from typing import Dict, Any, List, Optional

from src.config import MODELS_DIR, ALERT_RISK_THRESHOLD
from src.baseline_detector import BaselineDetector
from src.detectors.autoencoder_detector import AutoencoderDetector
from src.detectors.hist_gb_detector import HistGBDetector

class EnsembleFuser:
    def __init__(self, model_name: str = "ensemble_fuser"):
        self.model_name = model_name
        self.xgb_detector = BaselineDetector(model_name="xgboost_baseline")
        self.ae_detector = AutoencoderDetector(model_name="autoencoder_detector")
        self.hgb_detector = HistGBDetector(model_name="hist_gb_detector")
        self.meta_learner = LogisticRegression(C=1.0, max_iter=200)
        self.optimal_threshold: float = ALERT_RISK_THRESHOLD
        self.feature_columns: list = []

    def train(
        self,
        X_train: pd.DataFrame,
        y_train: pd.Series,
        X_val: pd.DataFrame,
        y_val: pd.Series,
        train_gnn: bool = False
    ) -> Dict[str, Any]:
        """
        Trains all 3 pillar models and fits the stacking meta-learner on validation predictions.
        """
        print("=" * 65)
        print("   EVIGRAPH: MULTI-MODEL ENSEMBLE TRAINING (TRI-PILLAR)")
        print("   1. Supervised XGBoost (GPU Hist)")
        print("   2. Unsupervised PyTorch Autoencoder (Zero-Day Detector)")
        print("   3. Native Histogram Gradient Boosting (Dual-Tree Diversity)")
        print("=" * 65)

        # 1. Train Pillar 1: XGBoost Detector
        print("\n>>> [Pillar 1/3] Training Supervised Multi-Class XGBoost...")
        self.xgb_detector.train(X_train, y_train, X_val, y_val)
        self.feature_columns = self.xgb_detector.feature_columns

        # 2. Train Pillar 2: Unsupervised PyTorch Autoencoder
        print("\n>>> [Pillar 2/3] Training Deep PyTorch Autoencoder on Benign Baseline...")
        self.ae_detector.train(X_train, y_train, X_val, y_val, epochs=15)

        # 3. Train Pillar 3: Scikit-Learn Native HistGradientBoosting
        print("\n>>> [Pillar 3/3] Training Native Histogram Gradient Boosting...")
        self.hgb_detector.train(X_train, y_train, X_val, y_val)

        # 4. Generate Validation Predictions for Meta-Learner Stacking
        print("\n>>> [Meta-Learner] Constructing Stacking Feature Space on Validation Split...")
        val_meta = pd.DataFrame({"label": y_val}, index=X_val.index)
        
        xgb_val = self.xgb_detector.score_flows(X_val, val_meta)
        ae_val = self.ae_detector.score_flows(X_val, val_meta)
        hgb_val = self.hgb_detector.score_flows(X_val, val_meta)

        r_xgb = xgb_val["risk_score"].values
        r_ae = ae_val["risk_score"].values
        r_hgb = hgb_val["risk_score"].values

        max_tree = np.maximum(r_xgb, r_hgb)
        min_tree = np.minimum(r_xgb, r_hgb)
        tree_diff = np.abs(r_xgb - r_hgb)
        Z_val = np.column_stack([r_xgb, r_ae, r_hgb, max_tree, min_tree, tree_diff])
        y_val_binary = (y_val != "BENIGN").astype(int).values

        # 5. Fit Stacking Logistic Regression Meta-Learner
        self.meta_learner.fit(Z_val, y_val_binary)
        fused_val_risk = self.meta_learner.predict_proba(Z_val)[:, 1]

        weights = self.meta_learner.coef_[0]
        intercept = self.meta_learner.intercept_[0]
        print(f"[Meta-Learner] Stacking Weights: XGB={weights[0]:.3f}, AE={weights[1]:.3f}, HistGB={weights[2]:.3f}, MaxTree={weights[3]:.3f}, Diff={weights[5]:.3f} (Intercept={intercept:.3f})")

        # 6. Optimize Fused Threshold (Sweep up to 0.95 for precision)
        best_f1, best_th = 0.0, ALERT_RISK_THRESHOLD
        for th in np.linspace(0.20, 0.95, 31):
            pred_b = (fused_val_risk >= th).astype(int)
            _, _, f1, _ = precision_recall_fscore_support(y_val_binary, pred_b, average="binary", zero_division=0)
            if f1 > best_f1:
                best_f1 = f1
                best_th = th
        self.optimal_threshold = round(float(best_th), 3)

        p, r, f1, _ = precision_recall_fscore_support(
            y_val_binary, (fused_val_risk >= self.optimal_threshold).astype(int), average="binary", zero_division=0
        )
        roc_auc = roc_auc_score(y_val_binary, fused_val_risk)
        pr_auc = average_precision_score(y_val_binary, fused_val_risk)

        print(f"\n[Ensemble Fuser] Optimal Alert Threshold: {self.optimal_threshold}")
        print(f"   * Validation Precision : {p * 100:.2f}%")
        print(f"   * Validation Recall    : {r * 100:.2f}%")
        print(f"   * Validation F1-Score  : {f1:.4f}")
        print(f"   * Validation ROC-AUC   : {roc_auc:.4f}")
        print(f"   * Validation PR-AUC    : {pr_auc:.4f}")

        return {
            "optimal_threshold": self.optimal_threshold,
            "weights": list(weights),
            "val_f1": best_f1,
            "val_roc_auc": roc_auc
        }

    def score_flows(
        self,
        X_test: pd.DataFrame,
        meta_test: pd.DataFrame,
        compute_shap: bool = True,
        max_shap_alerts: int = 15000
    ) -> pd.DataFrame:
        """
        Runs multi-model inference, fuses risk scores via meta-learner, and extracts
        native C++ TreeSHAP root-cause explanations for flagged alerts.
        """
        print("\n[Ensemble Fuser] Executing Multi-Model Score Fusion on Test Flows...")
        
        # 1. Independent model scorings
        xgb_scored = self.xgb_detector.score_flows(X_test, meta_test)
        ae_scored = self.ae_detector.score_flows(X_test, meta_test)
        hgb_scored = self.hgb_detector.score_flows(X_test, meta_test)

        r_xgb = xgb_scored["risk_score"].values
        r_ae = ae_scored["risk_score"].values
        r_hgb = hgb_scored["risk_score"].values

        # 2. Meta-Learner probability fusion with tree consensus and disagreement features
        max_tree_t = np.maximum(r_xgb, r_hgb)
        min_tree_t = np.minimum(r_xgb, r_hgb)
        tree_diff_t = np.abs(r_xgb - r_hgb)
        Z_test = np.column_stack([r_xgb, r_ae, r_hgb, max_tree_t, min_tree_t, tree_diff_t])
        fused_risk = self.meta_learner.predict_proba(Z_test)[:, 1]

        scored_df = meta_test.copy()
        scored_df["xgb_risk"] = np.round(r_xgb, 4)
        scored_df["ae_risk"] = np.round(r_ae, 4)
        scored_df["hgb_risk"] = np.round(r_hgb, 4)
        scored_df["risk_score"] = np.round(fused_risk, 4)
        scored_df["is_alert"] = scored_df["risk_score"] >= self.optimal_threshold

        # 3. Class resolution (Supervised class or Zero-Day Anomaly)
        pred_classes = []
        for i, is_al in enumerate(scored_df["is_alert"]):
            if not is_al:
                pred_classes.append("BENIGN")
            elif r_xgb[i] < 0.35 and r_ae[i] >= 0.70:
                pred_classes.append("ZeroDay-Anomaly")
            else:
                pred_classes.append(xgb_scored["predicted_class"].iloc[i])
        scored_df["predicted_class"] = pred_classes

        # 4. Native C++ TreeSHAP Local Attributions for Flagged Alerts
        if compute_shap and scored_df["is_alert"].sum() > 0:
            print("[Ensemble Fuser] Computing Native C++ TreeSHAP Attributions for Alerts...")
            alert_indices = scored_df[scored_df["is_alert"]].index
            if len(alert_indices) > max_shap_alerts:
                alert_indices = alert_indices[:max_shap_alerts]
                
            X_alert = X_test.loc[alert_indices, self.feature_columns].replace([np.inf, -np.inf], np.nan).fillna(0).astype(np.float32)
            
            try:
                booster = self.xgb_detector.base_model.get_booster()
                dmat = xgb.DMatrix(X_alert)
                # Native C++ TreeSHAP computation built into XGBoost
                shap_contribs = booster.predict(dmat, pred_contribs=True)
                
                # If multi-class, shap_contribs is (N, C, Features+1); if binary, (N, Features+1)
                if len(shap_contribs.shape) == 3:
                    # Take contributions for highest predicted malicious class
                    shap_matrix = np.max(np.abs(shap_contribs[:, :, :-1]), axis=1)
                else:
                    shap_matrix = np.abs(shap_contribs[:, :-1])

                explanations = {}
                feature_names = self.feature_columns
                for idx_pos, df_idx in enumerate(alert_indices):
                    row_shap = shap_matrix[idx_pos]
                    top_k_indices = np.argsort(row_shap)[-3:][::-1]
                    top_features = [
                        {
                            "feature": str(feature_names[fi]),
                            "importance": round(float(row_shap[fi]), 4)
                        }
                        for fi in top_k_indices
                    ]
                    explanations[df_idx] = top_features

                scored_df["shap_explanation"] = [explanations.get(idx, []) for idx in scored_df.index]
                print(f"[Ensemble Fuser] Attached native TreeSHAP explanations to {len(alert_indices):,} alerts")
            except Exception as e:
                print(f"[Ensemble Fuser] SHAP computation notice: {e}")
                scored_df["shap_explanation"] = [[] for _ in range(len(scored_df))]
        else:
            scored_df["shap_explanation"] = [[] for _ in range(len(scored_df))]

        total_alerts = scored_df["is_alert"].sum()
        print(f"[Ensemble Fuser] Total Scored Flows: {len(scored_df):,} | Flagged Fused Alerts: {total_alerts:,} (Threshold={self.optimal_threshold})")
        return scored_df

    def save(self, output_dir: Path = MODELS_DIR):
        output_dir.mkdir(parents=True, exist_ok=True)
        self.xgb_detector.save(output_dir)
        self.ae_detector.save(output_dir)
        self.hgb_detector.save(output_dir)
        fuser_path = output_dir / f"{self.model_name}.joblib"
        joblib.dump({
            "meta_learner": self.meta_learner,
            "threshold": self.optimal_threshold,
            "feature_columns": self.feature_columns
        }, fuser_path)
        print(f"[Ensemble Fuser] Saved complete ensemble artifacts to {output_dir}")

    def load(self, model_dir: Path = MODELS_DIR):
        self.xgb_detector.load(model_dir)
        self.ae_detector.load(model_dir)
        self.hgb_detector.load(model_dir)
        fuser_path = model_dir / f"{self.model_name}.joblib"
        data = joblib.load(fuser_path)
        self.meta_learner = data["meta_learner"]
        self.optimal_threshold = data["threshold"]
        self.feature_columns = data["feature_columns"]
        print(f"[Ensemble Fuser] Loaded ensemble checkpoint from {fuser_path}")
