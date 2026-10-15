"""
EviGraph Baseline Detector: XGBoost Classifier with Calibrated Risk Scoring
Adheres to TRD Section 3.3.1 and FR-3.1:
- XGBoost multiclass classifier with class weighting
- Probability calibration (Platt/sigmoid or isotonic scaling)
- Computes calibrated risk scores in [0, 1] and flags flow-level alerts
"""

import pandas as pd
import numpy as np
import xgboost as xgb
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.preprocessing import LabelEncoder
import joblib
from pathlib import Path
from typing import Dict, Any, Tuple
from src.config import MODELS_DIR, ALERT_RISK_THRESHOLD

class BaselineDetector:
    def __init__(self, model_name: str = "xgboost_baseline"):
        self.model_name = model_name
        self.label_encoder = LabelEncoder()
        self.model: Optional[CalibratedClassifierCV] = None
        self.feature_columns: list = []

    def train(
        self, 
        X_train: pd.DataFrame, 
        y_train: pd.Series, 
        X_val: pd.DataFrame, 
        y_val: pd.Series
    ) -> Dict[str, Any]:
        """Trains XGBoost and calibrates output probabilities on validation data."""
        self.feature_columns = list(X_train.columns)
        
        # Encode labels
        y_train_encoded = self.label_encoder.fit_transform(y_train)
        
        # Filter validation set to known classes so calibration doesn't fail on novel zero-day attacks
        val_mask = y_val.isin(self.label_encoder.classes_)
        if not val_mask.any():
            X_val_clean, y_val_encoded = X_train, y_train_encoded
        else:
            X_val_clean = X_val[val_mask]
            y_val_encoded = self.label_encoder.transform(y_val[val_mask])
        
        # Calculate sample weights for class imbalance
        classes, counts = np.unique(y_train_encoded, return_counts=True)
        class_weights = {cls: float(len(y_train_encoded) / (len(classes) * cnt)) for cls, cnt in zip(classes, counts)}
        sample_weights = np.array([class_weights[y] for y in y_train_encoded])
        
        print(f"[Detector] Training XGBoost on {len(X_train)} samples across {len(classes)} classes...")
        base_xgb = xgb.XGBClassifier(
            n_estimators=100,
            max_depth=5,
            learning_rate=0.08,
            subsample=0.8,
            colsample_bytree=0.8,
            eval_metric="mlogloss",
            random_state=42,
            n_jobs=-1
        )
        base_xgb.fit(X_train, y_train_encoded, sample_weight=sample_weights)
        
        # Probability Calibration (TRD Sec 3.3.1)
        print("[Detector] Calibrating probabilities with CalibratedClassifierCV (isotonic/sigmoid)...")
        method = "sigmoid" if len(X_val_clean) < 1000 else "isotonic"
        try:
            from sklearn.frozen import FrozenEstimator
            self.model = CalibratedClassifierCV(estimator=FrozenEstimator(base_xgb), method=method)
            self.model.fit(X_val_clean, y_val_encoded)
        except Exception:
            # Fallback for older scikit-learn or cross-validation
            self.model = CalibratedClassifierCV(estimator=base_xgb, method=method, cv=3)
            self.model.fit(X_train, y_train_encoded)
        
        # Evaluation on known validation classes
        val_preds = self.model.predict(X_val_clean)
        val_probs = self.model.predict_proba(X_val_clean)
        
        report = classification_report(
            y_val_encoded, 
            val_preds, 
            labels=list(range(len(self.label_encoder.classes_))),
            target_names=self.label_encoder.classes_, 
            output_dict=True,
            zero_division=0
        )
        print("[Detector] Validation Results:")
        print(classification_report(
            y_val_encoded, 
            val_preds, 
            labels=list(range(len(self.label_encoder.classes_))),
            target_names=self.label_encoder.classes_, 
            zero_division=0
        ))
        
        return report

    def score_flows(self, X: pd.DataFrame, meta_df: pd.DataFrame) -> pd.DataFrame:
        """
        Produces per-flow calibrated risk score in [0, 1] and flags alerts.
        Risk score is defined as P(malicious) = 1.0 - P(BENIGN).
        """
        if self.model is None:
            raise ValueError("Model is not trained or loaded yet.")
            
        probs = self.model.predict_proba(X[self.feature_columns])
        pred_idx = np.argmax(probs, axis=1)
        pred_classes = self.label_encoder.inverse_transform(pred_idx)
        
        # Find index of BENIGN
        if "BENIGN" in self.label_encoder.classes_:
            benign_idx = list(self.label_encoder.classes_).index("BENIGN")
            risk_scores = 1.0 - probs[:, benign_idx]
        else:
            # If binary or no benign label, max non-benign prob
            risk_scores = np.max(probs, axis=1)
            
        scored_df = meta_df.copy()
        scored_df["risk_score"] = np.round(risk_scores, 4)
        scored_df["predicted_class"] = pred_classes
        scored_df["is_alert"] = scored_df["risk_score"] >= ALERT_RISK_THRESHOLD
        
        # Attach full probability vector as dict for forensic explainability
        class_names = list(self.label_encoder.classes_)
        scored_df["class_probabilities"] = [
            {class_names[i]: round(float(p), 4) for i, p in enumerate(row_probs)}
            for row_probs in probs
        ]
        
        print(f"[Detector] Scored {len(scored_df)} flows -> {scored_df['is_alert'].sum()} ALERTS flagged (Threshold={ALERT_RISK_THRESHOLD})")
        return scored_df

    def save(self, output_dir: Path = MODELS_DIR):
        output_dir.mkdir(parents=True, exist_ok=True)
        model_path = output_dir / f"{self.model_name}.joblib"
        meta_path = output_dir / f"{self.model_name}_meta.joblib"
        joblib.dump(self.model, model_path)
        joblib.dump({"classes": self.label_encoder.classes_, "features": self.feature_columns}, meta_path)
        print(f"[Detector] Saved model artifacts to {model_path}")

    def load(self, model_dir: Path = MODELS_DIR):
        model_path = model_dir / f"{self.model_name}.joblib"
        meta_path = model_dir / f"{self.model_name}_meta.joblib"
        self.model = joblib.load(model_path)
        meta = joblib.load(meta_path)
        self.label_encoder.classes_ = meta["classes"]
        self.feature_columns = meta["features"]
        print(f"[Detector] Loaded model from {model_path}")
