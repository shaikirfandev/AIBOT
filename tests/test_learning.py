"""Tests for bbhunter.engines.learning.engine (LearningEngine)."""

from __future__ import annotations

from pathlib import Path

import pytest

from bbhunter.models import Vulnerability, VulnCategory, Severity


class TestLearningEngine:
    @pytest.fixture(autouse=True)
    def _setup_config(self, config_file: Path):
        from bbhunter.config import load_config
        import bbhunter.config as mod
        mod._config = load_config(config_file)

    def test_initializes(self):
        from bbhunter.engines.learning.engine import LearningEngine
        engine = LearningEngine()
        assert engine is not None

    def test_get_statistics(self):
        from bbhunter.engines.learning.engine import LearningEngine
        engine = LearningEngine()
        stats = engine.get_statistics()
        assert isinstance(stats, dict)

    def test_record_feedback(self, make_vulnerability):
        from bbhunter.engines.learning.engine import LearningEngine
        engine = LearningEngine()
        vuln = make_vulnerability()
        # Should not raise
        engine.record_feedback(vuln, is_true_positive=True, researcher_notes="confirmed")

    def test_predict_false_positive(self, make_vulnerability):
        from bbhunter.engines.learning.engine import LearningEngine
        engine = LearningEngine()
        vuln = make_vulnerability()
        # Should return a float probability
        score = engine.predict_false_positive(vuln)
        assert isinstance(score, (int, float))
        assert 0.0 <= score <= 1.0
