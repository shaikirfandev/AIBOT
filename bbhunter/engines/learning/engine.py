"""
Learning Module
================

Continuously improves the suite by learning from:
- Past vulnerability scan results (true/false positives)
- Researcher feedback
- Payload effectiveness
- WAF bypass success rates

Uses scikit-learn for lightweight ML models to:
- Improve false positive detection
- Prioritize scan targets
- Suggest effective payloads
"""

from __future__ import annotations

import json
import pickle
from datetime import datetime
from pathlib import Path
from typing import Any

import numpy as np

from bbhunter.config import get_config
from bbhunter.logger import get_logger
from bbhunter.models import Severity, Vulnerability, VulnCategory

logger = get_logger()


class LearningEngine:
    """
    Machine learning engine for continuous improvement.
    
    Trains on historical scan data to improve:
    - False positive detection accuracy
    - Vulnerability severity prediction
    - Payload effectiveness ranking
    """

    def __init__(self):
        self.config = get_config()
        self.model_dir = Path("./data/models")
        self.model_dir.mkdir(parents=True, exist_ok=True)
        self.fp_model = None
        self.training_data: list[dict] = []
        self._load_training_data()

    def _load_training_data(self):
        """Load historical training data."""
        data_file = self.model_dir / "training_data.json"
        if data_file.exists():
            try:
                with open(data_file) as f:
                    self.training_data = json.load(f)
                logger.info(f"📚 Loaded {len(self.training_data)} training samples")
            except Exception as e:
                logger.warning(f"Could not load training data: {e}")

    def _save_training_data(self):
        """Persist training data."""
        data_file = self.model_dir / "training_data.json"
        with open(data_file, "w") as f:
            json.dump(self.training_data, f)

    def record_feedback(
        self,
        vulnerability: Vulnerability,
        is_true_positive: bool,
        researcher_notes: str = "",
    ):
        """
        Record researcher feedback on a finding.
        
        This is the primary way the system learns and improves.
        """
        features = self._extract_features(vulnerability)
        features["is_true_positive"] = is_true_positive
        features["researcher_notes"] = researcher_notes
        features["timestamp"] = datetime.utcnow().isoformat()

        self.training_data.append(features)
        self._save_training_data()

        logger.info(
            f"📝 Feedback recorded: {vulnerability.title} → "
            f"{'TRUE POSITIVE' if is_true_positive else 'FALSE POSITIVE'}"
        )

        # Retrain if we have enough data
        if len(self.training_data) >= self.config.learning.min_samples:
            self.train_fp_model()

    def _extract_features(self, vuln: Vulnerability) -> dict[str, Any]:
        """Extract feature vector from a vulnerability for ML."""
        return {
            "category": vuln.category.value,
            "severity": vuln.severity.value,
            "confidence": vuln.confidence,
            "has_evidence": bool(vuln.evidence),
            "evidence_length": len(vuln.evidence) if vuln.evidence else 0,
            "has_payload": bool(vuln.payload),
            "has_request": bool(vuln.request),
            "has_response": bool(vuln.response),
            "response_length": len(vuln.response) if vuln.response else 0,
            "url_depth": vuln.url.count("/") if vuln.url else 0,
            "has_parameter": bool(vuln.parameter),
            "steps_count": len(vuln.steps_to_reproduce),
        }

    def _features_to_vector(self, features: dict) -> np.ndarray:
        """Convert feature dict to numeric vector."""
        category_map = {c.value: i for i, c in enumerate(VulnCategory)}
        severity_map = {s.value: i for i, s in enumerate(Severity)}

        return np.array([
            category_map.get(features.get("category", ""), 0),
            severity_map.get(features.get("severity", ""), 0),
            features.get("confidence", 0.5),
            int(features.get("has_evidence", False)),
            min(features.get("evidence_length", 0) / 1000, 10),
            int(features.get("has_payload", False)),
            int(features.get("has_request", False)),
            int(features.get("has_response", False)),
            min(features.get("response_length", 0) / 10000, 10),
            min(features.get("url_depth", 0) / 10, 1),
            int(features.get("has_parameter", False)),
            min(features.get("steps_count", 0) / 10, 1),
        ])

    def train_fp_model(self):
        """Train the false positive detection model."""
        try:
            from sklearn.ensemble import RandomForestClassifier
            from sklearn.model_selection import cross_val_score

            labeled = [d for d in self.training_data if "is_true_positive" in d]
            if len(labeled) < self.config.learning.min_samples:
                logger.info(f"Not enough labeled data ({len(labeled)}/{self.config.learning.min_samples})")
                return

            X = np.array([self._features_to_vector(d) for d in labeled])
            y = np.array([int(d["is_true_positive"]) for d in labeled])

            model = RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                random_state=42,
            )

            # Cross-validate
            scores = cross_val_score(model, X, y, cv=5, scoring="accuracy")
            logger.info(f"🤖 FP model accuracy: {scores.mean():.3f} (+/- {scores.std():.3f})")

            # Train final model
            model.fit(X, y)
            self.fp_model = model

            # Save model
            model_path = self.model_dir / "fp_model.pkl"
            with open(model_path, "wb") as f:
                pickle.dump(model, f)

            logger.info(f"🤖 FP model trained and saved ({len(labeled)} samples)")

        except ImportError:
            logger.warning("scikit-learn not installed, skipping model training")
        except Exception as e:
            logger.error(f"Model training error: {e}")

    def predict_false_positive(self, vuln: Vulnerability) -> float:
        """
        Predict the probability that a finding is a false positive.
        
        Returns:
            Float 0.0-1.0 (probability of being TRUE positive)
        """
        if self.fp_model is None:
            # Load saved model
            model_path = self.model_dir / "fp_model.pkl"
            if model_path.exists():
                try:
                    with open(model_path, "rb") as f:
                        self.fp_model = pickle.load(f)
                except Exception:
                    pass

        if self.fp_model is None:
            return vuln.confidence

        features = self._extract_features(vuln)
        vector = self._features_to_vector(features).reshape(1, -1)
        
        try:
            probability = self.fp_model.predict_proba(vector)[0][1]  # P(true positive)
            return float(probability)
        except Exception:
            return vuln.confidence

    def get_payload_effectiveness(self, category: VulnCategory) -> list[dict[str, Any]]:
        """Get payload effectiveness rankings from historical data."""
        category_data = [
            d for d in self.training_data
            if d.get("category") == category.value and d.get("is_true_positive")
        ]

        # Count payload success rates (if we tracked payloads)
        payload_stats: dict[str, int] = {}
        for d in category_data:
            payload = d.get("payload", "")
            if payload:
                payload_stats[payload] = payload_stats.get(payload, 0) + 1

        ranked = sorted(payload_stats.items(), key=lambda x: x[1], reverse=True)
        return [{"payload": p, "success_count": c} for p, c in ranked[:20]]

    def get_statistics(self) -> dict[str, Any]:
        """Get learning module statistics."""
        labeled = [d for d in self.training_data if "is_true_positive" in d]
        tp = sum(1 for d in labeled if d.get("is_true_positive"))
        fp = len(labeled) - tp

        return {
            "total_samples": len(self.training_data),
            "labeled_samples": len(labeled),
            "true_positives": tp,
            "false_positives": fp,
            "model_trained": self.fp_model is not None,
            "min_samples_needed": self.config.learning.min_samples,
        }
