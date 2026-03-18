"""
Learning Engine (v2 – Intelligence Upgrade)
=============================================

Continuously improves the suite by learning from:
- Past vulnerability scan results (true/false positives)
- Researcher feedback
- Payload effectiveness per WAF / technology
- URL pattern features & NLP features from evidence text
- Trend detection across scan runs

Uses scikit-learn for lightweight ML models:
- GradientBoosting (primary) + RandomForest (fallback) for FP detection
- 25+ engineered features  (up from 12)
- Auto-retrain on new feedback with cross-validation reporting
"""

from __future__ import annotations

import json
import math
import pickle
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np

from bbhunter.config import get_config
from bbhunter.logger import get_logger
from bbhunter.models import Severity, Vulnerability, VulnCategory

logger = get_logger()


# ───────────────────────────────────────────────────────────
#  Feature extraction helpers (NLP / URL patterns)
# ───────────────────────────────────────────────────────────

# Tokens often found in true-positive evidence
_TP_KEYWORDS = {
    "alert", "script", "onerror", "onload", "eval", "document.cookie",
    "syntax", "error", "sql", "union", "select", "sleep", "waitfor",
    "root:", "/etc/passwd", "internal", "metadata", "127.0.0.1",
    "localhost", "token", "secret", "password", "aws_access_key",
    "api_key",
}

# Common false-positive noise phrases
_FP_KEYWORDS = {
    "not found", "404", "forbidden", "rate limit", "captcha",
    "cloudflare", "access denied", "bad request", "400",
}

_URL_SENSITIVE_PATTERNS = re.compile(
    r"(admin|api|internal|debug|staging|dev|login|auth|graphql|swagger|config|"
    r"backup|upload|download|export|import|token|secret|private|manage)",
    re.IGNORECASE,
)


def _text_features(text: str | None) -> dict[str, float]:
    """Extract NLP-like features from evidence / response text."""
    if not text:
        return {"tp_keyword_hits": 0, "fp_keyword_hits": 0, "entropy": 0.0, "digit_ratio": 0.0}
    lower = text.lower()
    tp_hits = sum(1 for kw in _TP_KEYWORDS if kw in lower)
    fp_hits = sum(1 for kw in _FP_KEYWORDS if kw in lower)
    # Shannon entropy (indicator of randomness, e.g. real tokens vs. static pages)
    freq = Counter(lower)
    length = len(lower) or 1
    entropy = -sum((c / length) * math.log2(c / length) for c in freq.values() if c > 0)
    digit_ratio = sum(1 for ch in text if ch.isdigit()) / max(len(text), 1)
    return {
        "tp_keyword_hits": tp_hits,
        "fp_keyword_hits": fp_hits,
        "entropy": round(entropy, 3),
        "digit_ratio": round(digit_ratio, 3),
    }


def _url_features(url: str | None) -> dict[str, float]:
    """Extract URL pattern features."""
    if not url:
        return {"url_depth": 0, "has_param": 0, "sensitive_path": 0,
                "is_api": 0, "path_length": 0, "param_count": 0}
    from urllib.parse import urlparse, parse_qs
    parsed = urlparse(url)
    path = parsed.path.strip("/")
    params = parse_qs(parsed.query)
    return {
        "url_depth": path.count("/") + 1 if path else 0,
        "has_param": 1 if params else 0,
        "sensitive_path": 1 if _URL_SENSITIVE_PATTERNS.search(path) else 0,
        "is_api": 1 if "/api" in url.lower() else 0,
        "path_length": len(path),
        "param_count": len(params),
    }


class LearningEngine:
    """
    Machine learning engine for continuous improvement.

    Trains on historical scan data to improve:
    - False positive detection accuracy (25+ features)
    - Vulnerability severity prediction
    - Payload effectiveness ranking per WAF / technology
    - Trend analysis across scan runs
    """

    def __init__(self):
        self.config = get_config()
        self.model_dir = Path("./data/models")
        self.model_dir.mkdir(parents=True, exist_ok=True)
        self.fp_model: Any = None
        self.training_data: list[dict] = []
        self._payload_tracker: dict[str, dict[str, int]] = {}  # category→{payload→successes}
        self._waf_payload_tracker: dict[str, dict[str, int]] = {}  # waf→{payload→successes}
        self._load_training_data()
        self._load_payload_tracker()

    # ───────────────────────────────────────────────────────
    #  Persistence
    # ───────────────────────────────────────────────────────

    def _load_training_data(self):
        data_file = self.model_dir / "training_data.json"
        if data_file.exists():
            try:
                with open(data_file) as f:
                    self.training_data = json.load(f)
                logger.info(f"📚 Loaded {len(self.training_data)} training samples")
            except Exception as e:
                logger.warning(f"Could not load training data: {e}")

    def _save_training_data(self):
        data_file = self.model_dir / "training_data.json"
        with open(data_file, "w") as f:
            json.dump(self.training_data, f)

    def _load_payload_tracker(self):
        tracker_file = self.model_dir / "payload_tracker.json"
        if tracker_file.exists():
            try:
                with open(tracker_file) as f:
                    data = json.load(f)
                self._payload_tracker = data.get("by_category", {})
                self._waf_payload_tracker = data.get("by_waf", {})
            except Exception as exc:
                logger.debug(f"Failed to load payload tracker: {exc}")

    def _save_payload_tracker(self):
        tracker_file = self.model_dir / "payload_tracker.json"
        with open(tracker_file, "w") as f:
            json.dump({
                "by_category": self._payload_tracker,
                "by_waf": self._waf_payload_tracker,
            }, f)

    # ───────────────────────────────────────────────────────
    #  Feedback Recording
    # ───────────────────────────────────────────────────────

    def record_feedback(
        self,
        vulnerability: Vulnerability,
        is_true_positive: bool,
        researcher_notes: str = "",
    ):
        """Primary way the system learns."""
        features = self._extract_features(vulnerability)
        features["is_true_positive"] = is_true_positive
        features["researcher_notes"] = researcher_notes
        features["timestamp"] = datetime.now(timezone.utc).isoformat()

        self.training_data.append(features)
        self._save_training_data()

        # Track payload effectiveness
        if is_true_positive and vulnerability.payload:
            cat = vulnerability.category.value
            self._payload_tracker.setdefault(cat, {})
            self._payload_tracker[cat][vulnerability.payload] = (
                self._payload_tracker[cat].get(vulnerability.payload, 0) + 1
            )
            self._save_payload_tracker()

        logger.info(
            f"📝 Feedback recorded: {vulnerability.title} → "
            f"{'TRUE POSITIVE' if is_true_positive else 'FALSE POSITIVE'}"
        )

        if len(self.training_data) >= self.config.learning.min_samples:
            self.train_fp_model()

    def record_payload_result(
        self,
        payload: str,
        category: str,
        success: bool,
        waf: str | None = None,
    ):
        """Record whether a specific payload succeeded, optionally per WAF."""
        if success:
            self._payload_tracker.setdefault(category, {})
            self._payload_tracker[category][payload] = (
                self._payload_tracker[category].get(payload, 0) + 1
            )
            if waf:
                key = f"{waf}:{category}"
                self._waf_payload_tracker.setdefault(key, {})
                self._waf_payload_tracker[key][payload] = (
                    self._waf_payload_tracker[key].get(payload, 0) + 1
                )
            self._save_payload_tracker()

    # ───────────────────────────────────────────────────────
    #  Feature Extraction (25+ features)
    # ───────────────────────────────────────────────────────

    def _extract_features(self, vuln: Vulnerability) -> dict[str, Any]:
        """Extract feature vector from a vulnerability for ML (25+ features)."""
        base = {
            # Original 12
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

        # NLP features from evidence
        nlp = _text_features(vuln.evidence)
        base["tp_keyword_hits"] = nlp["tp_keyword_hits"]
        base["fp_keyword_hits"] = nlp["fp_keyword_hits"]
        base["evidence_entropy"] = nlp["entropy"]
        base["evidence_digit_ratio"] = nlp["digit_ratio"]

        # NLP features from response
        resp_nlp = _text_features(vuln.response[:2000] if vuln.response else None)
        base["response_tp_keywords"] = resp_nlp["tp_keyword_hits"]
        base["response_fp_keywords"] = resp_nlp["fp_keyword_hits"]

        # URL pattern features
        url_feats = _url_features(vuln.url)
        base["url_sensitive_path"] = url_feats["sensitive_path"]
        base["url_is_api"] = url_feats["is_api"]
        base["url_path_length"] = url_feats["path_length"]
        base["url_param_count"] = url_feats["param_count"]

        # Payload complexity features
        if vuln.payload:
            base["payload_length"] = len(vuln.payload)
            base["payload_has_encoding"] = 1 if any(c in vuln.payload for c in ["%", "\\u", "\\x", "&#"]) else 0
            base["payload_has_tags"] = 1 if "<" in vuln.payload and ">" in vuln.payload else 0
        else:
            base["payload_length"] = 0
            base["payload_has_encoding"] = 0
            base["payload_has_tags"] = 0

        # CVSS score if computed
        base["cvss_score"] = vuln.cvss_score

        return base

    # Feature names in order (must match _features_to_vector)
    _FEATURE_NAMES = [
        "category", "severity", "confidence",
        "has_evidence", "evidence_length", "has_payload",
        "has_request", "has_response", "response_length",
        "url_depth", "has_parameter", "steps_count",
        "tp_keyword_hits", "fp_keyword_hits",
        "evidence_entropy", "evidence_digit_ratio",
        "response_tp_keywords", "response_fp_keywords",
        "url_sensitive_path", "url_is_api", "url_path_length", "url_param_count",
        "payload_length", "payload_has_encoding", "payload_has_tags",
        "cvss_score",
    ]

    def _features_to_vector(self, features: dict) -> np.ndarray:
        """Convert feature dict to numeric vector (26 dimensions)."""
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
            # New NLP features
            min(features.get("tp_keyword_hits", 0) / 10, 1),
            min(features.get("fp_keyword_hits", 0) / 5, 1),
            min(features.get("evidence_entropy", 0) / 8, 1),
            features.get("evidence_digit_ratio", 0),
            min(features.get("response_tp_keywords", 0) / 10, 1),
            min(features.get("response_fp_keywords", 0) / 5, 1),
            # URL features
            int(features.get("url_sensitive_path", 0)),
            int(features.get("url_is_api", 0)),
            min(features.get("url_path_length", 0) / 100, 1),
            min(features.get("url_param_count", 0) / 10, 1),
            # Payload features
            min(features.get("payload_length", 0) / 200, 1),
            int(features.get("payload_has_encoding", 0)),
            int(features.get("payload_has_tags", 0)),
            # CVSS
            features.get("cvss_score", 0) / 10,
        ])

    # ───────────────────────────────────────────────────────
    #  Model Training
    # ───────────────────────────────────────────────────────

    def train_fp_model(self):
        """Train the false positive detection model (GradientBoosting primary, RF fallback)."""
        try:
            from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
            from sklearn.model_selection import cross_val_score

            labeled = [d for d in self.training_data if "is_true_positive" in d]
            if len(labeled) < self.config.learning.min_samples:
                logger.info(f"Not enough labeled data ({len(labeled)}/{self.config.learning.min_samples})")
                return

            X = np.array([self._features_to_vector(d) for d in labeled])
            y = np.array([int(d["is_true_positive"]) for d in labeled])

            # Try GradientBoosting first (generally better than RF)
            gb = GradientBoostingClassifier(
                n_estimators=150, max_depth=5, learning_rate=0.1,
                subsample=0.8, random_state=42,
            )
            rf = RandomForestClassifier(
                n_estimators=100, max_depth=10, random_state=42,
            )

            gb_scores = cross_val_score(gb, X, y, cv=min(5, len(labeled)), scoring="accuracy")
            rf_scores = cross_val_score(rf, X, y, cv=min(5, len(labeled)), scoring="accuracy")

            logger.info(
                f"🤖 GradientBoosting: {gb_scores.mean():.3f} (±{gb_scores.std():.3f}) | "
                f"RandomForest: {rf_scores.mean():.3f} (±{rf_scores.std():.3f})"
            )

            # Use whichever performs better
            if gb_scores.mean() >= rf_scores.mean():
                best = gb
                model_name = "GradientBoosting"
            else:
                best = rf
                model_name = "RandomForest"

            best.fit(X, y)
            self.fp_model = best

            # Save model + metadata
            model_path = self.model_dir / "fp_model.pkl"
            with open(model_path, "wb") as f:
                pickle.dump({"model": best, "name": model_name, "n_features": X.shape[1]}, f)

            # Feature importance report
            importances = best.feature_importances_
            top_features = sorted(
                zip(self._FEATURE_NAMES[:len(importances)], importances),
                key=lambda x: x[1], reverse=True,
            )[:5]
            logger.info(
                f"🤖 {model_name} trained ({len(labeled)} samples). "
                f"Top features: {', '.join(f'{n}={v:.2f}' for n, v in top_features)}"
            )

        except ImportError:
            logger.warning("scikit-learn not installed, skipping model training")
        except Exception as e:
            logger.error(f"Model training error: {e}")

    def predict_false_positive(self, vuln: Vulnerability) -> float:
        """
        Predict probability that a finding is a TRUE positive.
        Returns float 0.0-1.0.
        """
        if self.fp_model is None:
            model_path = self.model_dir / "fp_model.pkl"
            if model_path.exists():
                try:
                    with open(model_path, "rb") as f:
                        data = pickle.load(f)
                    if isinstance(data, dict):
                        self.fp_model = data["model"]
                    else:
                        self.fp_model = data  # backward compat
                except Exception as exc:
                    logger.debug(f"Failed to load FP model: {exc}")

        if self.fp_model is None:
            return vuln.confidence

        features = self._extract_features(vuln)
        vector = self._features_to_vector(features).reshape(1, -1)
        try:
            probability = self.fp_model.predict_proba(vector)[0][1]  # P(true positive)
            return float(probability)
        except Exception as exc:
            logger.debug(f"FP model prediction failed: {exc}")
            return vuln.confidence

    # ───────────────────────────────────────────────────────
    #  Payload Effectiveness
    # ───────────────────────────────────────────────────────

    def get_payload_effectiveness(
        self, category: VulnCategory, waf: str | None = None,
    ) -> list[dict[str, Any]]:
        """Get payload effectiveness rankings from tracking data."""
        if waf:
            key = f"{waf}:{category.value}"
            stats = self._waf_payload_tracker.get(key, {})
        else:
            stats = self._payload_tracker.get(category.value, {})

        # Also include payloads from training data (backward compat)
        category_data = [
            d for d in self.training_data
            if d.get("category") == category.value and d.get("is_true_positive")
        ]
        for d in category_data:
            payload = d.get("payload", "")
            if payload:
                stats[payload] = stats.get(payload, 0) + 1

        ranked = sorted(stats.items(), key=lambda x: x[1], reverse=True)
        return [{"payload": p, "success_count": c} for p, c in ranked[:30]]

    def get_waf_bypasses(self, waf: str) -> dict[str, list[dict[str, Any]]]:
        """Get which payloads work best against a specific WAF, grouped by category."""
        result: dict[str, list[dict[str, Any]]] = {}
        for key, stats in self._waf_payload_tracker.items():
            if key.startswith(f"{waf}:"):
                category = key.split(":", 1)[1]
                ranked = sorted(stats.items(), key=lambda x: x[1], reverse=True)
                result[category] = [{"payload": p, "success_count": c} for p, c in ranked[:10]]
        return result

    # ───────────────────────────────────────────────────────
    #  Trend Analysis
    # ───────────────────────────────────────────────────────

    def get_trends(self, window_days: int = 30) -> dict[str, Any]:
        """Analyze trends in recent feedback data."""
        from datetime import timedelta
        cutoff = datetime.now(timezone.utc) - timedelta(days=window_days)

        recent = []
        for d in self.training_data:
            try:
                ts = datetime.fromisoformat(d.get("timestamp", ""))
                if ts > cutoff:
                    recent.append(d)
            except (ValueError, TypeError):
                pass

        if not recent:
            return {"window_days": window_days, "samples": 0, "message": "No recent data"}

        # FP rate trend
        labeled = [d for d in recent if "is_true_positive" in d]
        tp_count = sum(1 for d in labeled if d.get("is_true_positive"))
        fp_count = len(labeled) - tp_count
        fp_rate = fp_count / max(len(labeled), 1)

        # Category distribution
        cat_counts: dict[str, int] = Counter(d.get("category", "unknown") for d in recent)

        # Top payloads
        payload_counts: dict[str, int] = {}
        for d in recent:
            p = d.get("payload", "")
            if p and d.get("is_true_positive"):
                payload_counts[p] = payload_counts.get(p, 0) + 1

        return {
            "window_days": window_days,
            "samples": len(recent),
            "fp_rate": round(fp_rate, 3),
            "tp_count": tp_count,
            "fp_count": fp_count,
            "category_distribution": dict(cat_counts.most_common(10)),
            "top_payloads": dict(sorted(payload_counts.items(), key=lambda x: -x[1])[:5]),
        }

    # ───────────────────────────────────────────────────────
    #  Statistics
    # ───────────────────────────────────────────────────────

    def get_statistics(self) -> dict[str, Any]:
        labeled = [d for d in self.training_data if "is_true_positive" in d]
        tp = sum(1 for d in labeled if d.get("is_true_positive"))
        fp = len(labeled) - tp

        # Model info
        model_info = "none"
        if self.fp_model is not None:
            model_info = getattr(self.fp_model, "__class__", type(self.fp_model)).__name__

        return {
            "total_samples": len(self.training_data),
            "labeled_samples": len(labeled),
            "true_positives": tp,
            "false_positives": fp,
            "model_trained": self.fp_model is not None,
            "model_type": model_info,
            "min_samples_needed": self.config.learning.min_samples,
            "payload_categories_tracked": len(self._payload_tracker),
            "waf_profiles_tracked": len(self._waf_payload_tracker),
        }
