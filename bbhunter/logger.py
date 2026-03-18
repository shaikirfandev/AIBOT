"""
Logging and action audit system.
Every action is logged for safety compliance and forensics.

Features:
- RotatingFileHandler (10 MB × 5 backups) for the main app log
- Thread-safe ActionLogger with a lock around file writes
- All timestamps use timezone-aware UTC (datetime.now(timezone.utc))
"""

from __future__ import annotations

import json
import logging
import os
import threading
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.logging import RichHandler

console = Console()

# ---------------------------------------------------------------------------
# Action Logger - logs every scanning action to file for audit
# ---------------------------------------------------------------------------

class ActionLogger:
    """Logs all security testing actions for audit trail compliance."""

    def __init__(self, log_file: str = "./logs/actions.log"):
        self.log_file = Path(log_file)
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def log(
        self,
        action: str,
        target: str,
        details: dict[str, Any] | None = None,
        level: str = "INFO",
    ):
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": level,
            "action": action,
            "target": target,
            "details": details or {},
        }
        with self._lock:
            with open(self.log_file, "a") as f:
                f.write(json.dumps(entry) + "\n")

    def log_request(self, method: str, url: str, status: int = 0):
        self.log("http_request", url, {"method": method, "status_code": status})

    def log_scan_start(self, scan_type: str, target: str):
        self.log("scan_start", target, {"scan_type": scan_type})

    def log_scan_end(self, scan_type: str, target: str, findings: int = 0):
        self.log("scan_end", target, {"scan_type": scan_type, "findings": findings})

    def log_vulnerability(self, vuln_title: str, target: str, severity: str):
        self.log("vulnerability_found", target, {"title": vuln_title, "severity": severity}, level="WARNING")


# ---------------------------------------------------------------------------
# App Logger
# ---------------------------------------------------------------------------

def setup_logging(level: str = "INFO") -> logging.Logger:
    """Configure rich console + rotating file logging for the application."""
    log_dir = Path("./logs")
    log_dir.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger("bbhunter")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Prevent duplicate handlers when setup_logging is called multiple times
    if logger.handlers:
        return logger

    # Rich console handler
    console_handler = RichHandler(rich_tracebacks=True, console=console)
    console_handler.setLevel(logging.DEBUG)
    logger.addHandler(console_handler)

    # Rotating file handler — 10 MB per file, keep 5 backups
    file_handler = RotatingFileHandler(
        log_dir / "bbhunter.log",
        maxBytes=10 * 1024 * 1024,
        backupCount=5,
        encoding="utf-8",
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(
        logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    )
    logger.addHandler(file_handler)

    return logger


# Singleton instances
_logger: logging.Logger | None = None
_action_logger: ActionLogger | None = None


def get_logger() -> logging.Logger:
    global _logger
    if _logger is None:
        _logger = setup_logging()
    return _logger


def get_action_logger() -> ActionLogger:
    global _action_logger
    if _action_logger is None:
        _action_logger = ActionLogger()
    return _action_logger
