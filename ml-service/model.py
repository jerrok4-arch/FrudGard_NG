"""ML model training and inference for fraud detection."""
import json
import logging
import os
from datetime import datetime, timedelta
from typing import List, Optional, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier

from config import ModelConfig
from features import FeatureEngineer, RawLoginEvent

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class FraudDetectionModel:
    """Ensemble model: XGBoost + Isolation Forest for fraud detection."""

    def __init__(self, config: ModelConfig):
        self.config = config
        self.feature_engineer = FeatureEngineer(config)
        self.scaler: Optional[StandardScaler] = None
        self.xgb_model: Optional[XGBClassifier] = None
        self.iso_model: Optional[IsolationForest] = None
        self._load_models()

    def _load_models(self):
        """Load pre-trained models from disk."""
        try:
            if os.path.exists(self.config.scaler_path):
                self.scaler = joblib.load(self.config.scaler_path)
                logger.info("Loaded scaler from %s", self.config.scaler_path)
        except Exception as e:
            logger.warning("Failed to load scaler: %s", e)

        try:
            if os.path.exists(self.config.xgboost_model_path):
                self.xgb_model = XGBClassifier()
                self.xgb_model.load_model(self.config.xgboost_model_path)
                logger.info("Loaded XGBoost model from %s", self.config.xgboost_model_path)
        except Exception as e:
            logger.warning("Failed to load XGBoost model: %s", e)

        try:
            if os.path.exists(self.config.isolation_model_path):
                self.iso_model = joblib.load(self.config.isolation_model_path)
                logger.info("Loaded Isolation Forest from %s", self.config.isolation_model_path)
        except Exception as e:
            logger.warning("Failed to load Isolation Forest: %s", e)

    def predict(self, event: RawLoginEvent) -> dict:
        """Run inference on a single login event.

        Returns dict with:
            - fraud_probability: float (0-1)
            - anomaly_score: float (negative = anomaly)
            - ensemble_score: float (0-1, combined)
            - is_fraud: bool
            - confidence: float
            - model_version: str
        """
        df = self.feature_engineer.engineer_features(event)

        # Drop non-numeric columns for model input
        X = df.select_dtypes(include=[np.number]).values

        # Scale features
        if self.scaler is not None:
            X_scaled = self.scaler.transform(X)
        else:
            X_scaled = X

        # XGBoost prediction (supervised)
        xgb_prob = 0.5
        if self.xgb_model is not None:
            xgb_prob = float(self.xgb_model.predict_proba(X_scaled)[0][1])

        # Isolation Forest prediction (unsupervised anomaly)
        iso_score = 0.0
        if self.iso_model is not None:
            # IsolationForest returns -1 for anomaly, 1 for normal
            iso_pred = self.iso_model.predict(X_scaled)[0]
            iso_raw = self.iso_model.score_samples(X_scaled)[0]
            # Normalize to 0-1 (lower raw score = more anomalous)
            iso_score = 1.0 - (iso_raw + 0.5)  # Approximate normalization
            iso_score = max(0.0, min(1.0, iso_score))
            if iso_pred == -1:
                iso_score = max(iso_score, 0.7)

        # Ensemble: weighted combination
        # XGBoost gets higher weight when we have labeled data
        # Isolation Forest gets higher weight for novel attack patterns
        ensemble_score = 0.6 * xgb_prob + 0.4 * iso_score

        # Confidence based on agreement between models
        confidence = 1.0 - abs(xgb_prob - iso_score)

        # Decision threshold
        is_fraud = ensemble_score > 0.7

        return {
            "fraud_probability": round(xgb_prob, 4),
            "anomaly_score": round(iso_score, 4),
            "ensemble_score": round(ensemble_score, 4),
            "is_fraud": is_fraud,
            "confidence": round(confidence, 4),
            "model_version": "fraudguard-v2.1",
            "timestamp": datetime.utcnow().isoformat(),
        }

    def train(self, events: List[RawLoginEvent]) -> dict:
        """Train models on labeled dataset.

        Args:
            events: List of login events with is_fraud labels (0=legit, 1=fraud)

        Returns:
            Training metrics dict
        """
        logger.info("Starting model training with %d events", len(events))

        # Feature engineering
        df = self.feature_engineer.engineer_batch(events)

        # Separate features and labels
        y = np.array([e.is_fraud for e in events])
        X = df.select_dtypes(include=[np.number]).values

        # Handle class imbalance
        fraud_count = np.sum(y)
        legit_count = len(y) - fraud_count
        scale_pos_weight = legit_count / max(fraud_count, 1)
        logger.info("Class distribution: %d fraud, %d legit (scale_pos_weight=%.2f)", 
                   fraud_count, legit_count, scale_pos_weight)

        # Scale features
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)

        # Train XGBoost
        logger.info("Training XGBoost classifier...")
        self.xgb_model = XGBClassifier(
            n_estimators=200,
            max_depth=6,
            learning_rate=0.1,
            subsample=0.8,
            colsample_bytree=0.8,
            scale_pos_weight=scale_pos_weight,
            eval_metric="logloss",
            random_state=42,
            n_jobs=-1,
        )
        self.xgb_model.fit(X_scaled, y)

        # Train Isolation Forest (on ALL data, unsupervised)
        logger.info("Training Isolation Forest...")
        self.iso_model = IsolationForest(
            n_estimators=200,
            contamination=0.1,  # Assume 10% anomalies
            random_state=42,
            n_jobs=-1,
        )
        self.iso_model.fit(X_scaled)

        # Save models
        self._save_models()

        # Feature importance from XGBoost
        feature_names = df.select_dtypes(include=[np.number]).columns.tolist()
        importance = self.xgb_model.feature_importances_
        feature_importance = dict(sorted(
            zip(feature_names, importance),
            key=lambda x: x[1],
            reverse=True
        )[:10])

        metrics = {
            "training_samples": len(events),
            "fraud_samples": int(fraud_count),
            "legit_samples": int(legit_count),
            "scale_pos_weight": round(scale_pos_weight, 2),
            "top_features": feature_importance,
            "timestamp": datetime.utcnow().isoformat(),
        }

        logger.info("Training complete. Top features: %s", 
                   list(feature_importance.keys())[:5])
        return metrics

    def _save_models(self):
        """Persist trained models to disk."""
        os.makedirs(self.config.model_dir, exist_ok=True)

        if self.scaler:
            joblib.dump(self.scaler, self.config.scaler_path)
        if self.xgb_model:
            self.xgb_model.save_model(self.config.xgboost_model_path)
        if self.iso_model:
            joblib.dump(self.iso_model, self.config.isolation_model_path)

        logger.info("Models saved to %s", self.config.model_dir)

    def explain_prediction(self, event: RawLoginEvent) -> List[dict]:
        """Generate SHAP-like feature contribution explanation."""
        df = self.feature_engineer.engineer_features(event)
        X = df.select_dtypes(include=[np.number]).values

        if self.scaler:
            X_scaled = self.scaler.transform(X)
        else:
            X_scaled = X

        # Get feature importance from XGBoost
        if self.xgb_model is None:
            return []

        feature_names = df.select_dtypes(include=[np.number]).columns.tolist()
        importance = self.xgb_model.feature_importances_
        values = X_scaled[0]

        explanations = []
        for name, imp, val in zip(feature_names, importance, values):
            # High value + high importance = major contributor
            contribution = abs(val) * imp
            if contribution > 0.01:  # Only significant contributions
                explanations.append({
                    "feature": name,
                    "value": round(float(val), 4),
                    "importance": round(float(imp), 4),
                    "contribution": round(float(contribution), 4),
                })

        # Sort by contribution
        explanations.sort(key=lambda x: x["contribution"], reverse=True)
        return explanations[:10]
