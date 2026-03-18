"""Tests for bbhunter.logger module."""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest

from bbhunter.logger import ActionLogger, setup_logging, get_logger, get_action_logger


class TestActionLogger:
    def test_log_creates_file(self, tmp_path: Path):
        log_file = tmp_path / "actions.log"
        al = ActionLogger(str(log_file))
        al.log("test_action", "example.com", {"key": "value"})
        assert log_file.exists()

    def test_log_entry_is_valid_json(self, tmp_path: Path):
        log_file = tmp_path / "actions.log"
        al = ActionLogger(str(log_file))
        al.log("scan_start", "example.com")
        line = log_file.read_text().strip()
        entry = json.loads(line)
        assert entry["action"] == "scan_start"
        assert entry["target"] == "example.com"
        assert "timestamp" in entry

    def test_log_timestamp_is_utc(self, tmp_path: Path):
        log_file = tmp_path / "actions.log"
        al = ActionLogger(str(log_file))
        al.log("test", "example.com")
        entry = json.loads(log_file.read_text().strip())
        ts = entry["timestamp"]
        # Should end with +00:00 (timezone-aware UTC)
        assert "+00:00" in ts or "Z" in ts

    def test_log_request(self, tmp_path: Path):
        log_file = tmp_path / "actions.log"
        al = ActionLogger(str(log_file))
        al.log_request("GET", "https://example.com", 200)
        entry = json.loads(log_file.read_text().strip())
        assert entry["action"] == "http_request"
        assert entry["details"]["method"] == "GET"
        assert entry["details"]["status_code"] == 200

    def test_log_vulnerability(self, tmp_path: Path):
        log_file = tmp_path / "actions.log"
        al = ActionLogger(str(log_file))
        al.log_vulnerability("XSS in search", "example.com", "high")
        entry = json.loads(log_file.read_text().strip())
        assert entry["level"] == "WARNING"
        assert entry["details"]["severity"] == "high"

    def test_thread_safety(self, tmp_path: Path):
        """ActionLogger should have a threading lock."""
        log_file = tmp_path / "actions.log"
        al = ActionLogger(str(log_file))
        assert hasattr(al, "_lock")


class TestSetupLogging:
    def test_returns_logger(self):
        logger = setup_logging("DEBUG")
        assert isinstance(logger, logging.Logger)
        assert logger.name == "bbhunter"

    def test_no_duplicate_handlers(self):
        l1 = setup_logging("INFO")
        h_count = len(l1.handlers)
        l2 = setup_logging("INFO")
        assert len(l2.handlers) == h_count  # should not double


class TestSingletons:
    def test_get_logger_returns_logger(self):
        logger = get_logger()
        assert isinstance(logger, logging.Logger)

    def test_get_action_logger_returns_instance(self):
        al = get_action_logger()
        assert isinstance(al, ActionLogger)
