"""
Learning Module
=================

Continuously improves the system by learning from:
- Past vulnerability findings (true/false positives)
- Researcher feedback
- Pattern recognition
- Historical scan data
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

import numpy as np

from bbhunter.config import get_config
from bbhunter.logger import get_logger
from bbhunter.models import Severity, Vulnerability, VulnCategory

logger = get_logger()


class LearningModule:
    """
    Machine learning module that improves detection accuracy over time.
    
    Learns from:
    - Researcher feedback on true/false positives
    - Patterns in successful vs unsuccessful detections
    - Endpoint characteristics correlated with vulnerabilities
    """

    def __init__(self):
        self.config = get_config()
        self.data_dir = Path(self.config.app.data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.feedback_file = self.data_dir / "feedback.json"
        self.model_file = self.data_dir / "learning_model.json"
        self.feedback_data: list[dict] = []
        self.model: dict[str, Any] = self._load_model()
        self._load_feedback()

    def _load_feedback(self):
        """Load historical feedback data."""
        if self.feedback_file.exists():
            try:
                self.feedback_data = json.loads(self.feedback_file.read_text())
            except Exception:
                self.feedback_data = []

    def _save_feedback(self):
        """Persist feedback data."""
        self.feedback_file.write_text(json.dumps(self.feedback_data, indent=2, default=str))

    def _load_model(self) -> dict[str, Any]:
        """Load the learned model parameters."""
        if self.model_file.exists():
            try:
                return json.loads(self.model_file.read_text())
            except Exception:
                pass
        return self._default_model()

    def _save_model(self):
        """Persist the learned model."""
        self.model_file.write_text(json.dumps(self.model, indent=2))

    def _default_model(self) -> dict[str, Any]:
        """Return default model parameters."""
        return {
            "confidence_adjustments": {},
            "parameter_risk_scores": {},
            "url_pattern_risk": {},
            "fp_patterns": [],
            "tp_patterns": [],
            "total_feedback": 0,
            "true_positive_rate": 0.5,
            "last_trained": None,
        }

    def record_feedback(
        self,
        vulnerability_id: str,
        is_true_positive: bool,
        category: str,
        parameter: str = "",
        url_pattern: str = "",
        confidence: float = 0.0,
        notes: str = "",
    ):
        """Record researcher feedback on a finding."""
        feedback = {
            "vulnerability_id": vulnerability_id,
            "is_true_positive": is_true_positive,
            "category": category,
            "parameter": parameter,
            "url_pattern": url_pattern,
            "confidence": confidence,
            "notes": notes,
            "timestamp": datetime.utcnow().isoformat(),
        }
        self.feedback_data.append(feedback)
        self._save_feedback()
        self._update_model_incremental(feedback)
        logger.info(
            f"📚 Feedback recorded: {'✅ TP' if is_true_positive else '❌ FP'} "
            f"for {category}"
        )

    def _update_model_incremental(self, feedback: dict):
        """Update model parameters based on new feedback."""
        category = feedback["category"]
        is_tp = feedback["is_true_positive"]
        param = feedback["parameter"]

        if category not in self.model["confidence_adjustments"]:
            self.model["confidence_adjustments"][category] = {"tp": 0, "fp": 0, "adjustment": 0.0}

        adj = self.model["confidence_adjustments"][category]
        if is_tp:
            adj["tp"] += 1
        else:
            adj["fp"] += 1

        total = adj["tp"] + adj["fp"]
        if total > 0:
            tp_rate = adj["tp"] / total
            adj["adjustment"] = (tp_rate - 0.5) * 0.2

        if param:
            if param not in self.model["parameter_risk_scores"]:
                self.model["parameter_risk_scores"][param] = {"tp": 0, "fp": 0, "risk": 0.5}
            p_score = self.model["parameter_risk_scores"][param]
            if is_tp:
                p_score["tp"] += 1
            else:
                p_score["fp"] += 1
            p_total = p_score["tp"] + p_score["fp"]
            if p_total > 0:
                p_score["risk"] = p_score["tp"] / p_total

        self.model["total_feedback"] += 1
        self._save_model()

    def retrain(self):
        """Full model retraining from all historical feedback."""
        if len(self.feedback_data) < self.config.learning.min_samples:
            logger.info(f"📚 Not enough samples for retraining ({len(self.feedback_data)}/{self.config.learning.min_samples})")
            return

        logger.info(f"🔄 Retraining model with {len(self.feedback_data)} samples...")
        self.model = self._default_model()
        for feedback in self.feedback_data:
            self._update_model_incremental(feedback)

        tp_count = sum(1 for f in self.feedback_data if f["is_true_positive"])
        total = len(self.feedback_data)
        self.model["true_positive_rate"] = tp_count / total if total > 0 else 0.5
        self._extract_patterns()
        self.model["last_trained"] = datetime.utcnow().isoformat()
        self._save_model()
        logger.info(f"✅ Model retrained. TP rate: {self.model['true_positive_rate']:.2%}")

    def _extract_patterns(self):
        """Extract common patterns from true/false positives."""
        fp_categories = Counter()
        tp_categories = Counter()
        for f in self.feedback_data:
            if f["is_true_positive"]:
                tp_categories[f["category"]] += 1
            else:
                fp_categories[f["category"]] += 1
        self.model["fp_patterns"] = [{"category": c, "count": n} for c, n in fp_categories.most_common(10)]
        self.model["tp_patterns"] = [{"category": c, "count": n} for c, n in tp_categories.most_common(10)]

    def adjust_confidence(self, vuln: Vulnerability) -> float:
        """Adjust vulnerability confidence score based on learned patterns."""
        confidence = vuln.confidence
        cat_adj = self.model["confidence_adjustments"].get(vuln.category.value, {})
        if cat_adj:
            confidence += cat_adj.get("adjustment", 0.0)
        if vuln.parameter:
            param_data = self.model["parameter_risk_scores"].get(vuln.parameter, {})
            if param_data:
                param_risk = param_data.get("risk", 0.5)
                confidence = 0.7 * confidence + 0.3 * param_risk
        return max(0.0, min(1.0, confidence))

    def get_statistics(self) -> dict[str, Any]:
        """Get learning module statistics."""
        return {
            "total_feedback": self.model["total_feedback"],
            "true_positive_rate": self.model["true_positive_rate"],
            "categories_tracked": len(self.model["confidence_adjustments"]),
            "parameters_tracked": len(self.model["parameter_risk_scores"]),
            "last_trained": self.model["last_trained"],
            "feedback_samples": len(self.feedback_data),
        }
