"""Tests for bbhunter.engines.assistant.engine (ManualTestingAssistant)."""

from __future__ import annotations

from pathlib import Path

import pytest

from bbhunter.models import Endpoint


class TestManualTestingAssistant:
    @pytest.fixture(autouse=True)
    def _setup_config(self, config_file: Path):
        from bbhunter.config import load_config
        import bbhunter.config as mod
        mod._config = load_config(config_file)

    def test_suggest_attack_vectors(self, make_endpoint):
        from bbhunter.engines.assistant.engine import ManualTestingAssistant
        assistant = ManualTestingAssistant()
        ep = make_endpoint(url="https://example.com/api/graphql", method="POST")
        result = assistant.suggest_attack_vectors(ep)
        assert isinstance(result, (dict, list))
        if isinstance(result, list):
            assert len(result) > 0

    def test_decode_base64(self):
        from bbhunter.engines.assistant.engine import ManualTestingAssistant
        assistant = ManualTestingAssistant()
        result = assistant.decode_data("aGVsbG8gd29ybGQ=")
        assert isinstance(result, dict)

    def test_decode_jwt(self):
        from bbhunter.engines.assistant.engine import ManualTestingAssistant
        assistant = ManualTestingAssistant()
        # A minimal JWT (header.payload.signature)
        jwt_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        result = assistant.decode_data(jwt_token)
        assert isinstance(result, dict)
