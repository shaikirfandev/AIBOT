"""
Logging and action audit system.
Every action is logged for safety compliance and forensics.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime
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

    def log(
        self,
        action: str,
        target: str,
        details: dict[str, Any] | None = None,
        level: str = "INFO",
    ):
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": level,
            "action": action,
            "target": target,
            "details": details or {},
        }
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
    """Configure rich logging for the application."""
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(rich_tracebacks=True, console=console)],
    )
    logger = logging.getLogger("bbhunter")
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
