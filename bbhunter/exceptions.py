"""
Typed Exception Hierarchy for BBHunter
=======================================

Centralised exceptions used across all engines and scripts.
Every module should import from here instead of raising bare
``Exception`` or ``KeyError`` etc.
"""

from __future__ import annotations


class BBHunterError(Exception):
    """Base exception for all BBHunter errors."""


# ── Authorization / Safety ──────────────────────────────────────────────

class AuthorizationError(BBHunterError):
    """Raised when an operation targets an unauthorized asset."""


class ScopeError(BBHunterError):
    """Raised when a URL/domain is outside the defined scope."""


# ── Configuration ───────────────────────────────────────────────────────

class ConfigError(BBHunterError):
    """Raised for invalid or missing configuration."""


# ── Pipeline / Orchestration ────────────────────────────────────────────

class PipelineError(BBHunterError):
    """Raised when a pipeline step fails fatally."""


class StepTimeoutError(PipelineError):
    """Raised when an individual pipeline step exceeds its timeout."""


# ── External Tool Errors ───────────────────────────────────────────────

class ToolNotFoundError(BBHunterError):
    """Raised when a required external CLI tool is not installed."""


class ToolExecutionError(BBHunterError):
    """Raised when an external tool returns a non-zero exit code."""

    def __init__(self, tool: str, returncode: int, stderr: str = ""):
        self.tool = tool
        self.returncode = returncode
        self.stderr = stderr
        super().__init__(f"{tool} exited with code {returncode}: {stderr[:300]}")


# ── Network / HTTP ──────────────────────────────────────────────────────

class NetworkError(BBHunterError):
    """Raised for HTTP/DNS/connection failures."""


class RateLimitError(NetworkError):
    """Raised when a target returns HTTP 429."""


# ── LLM / AI ───────────────────────────────────────────────────────────

class LLMError(BBHunterError):
    """Raised when the LLM backend fails."""


class LLMConnectionError(LLMError):
    """Raised when the LLM backend is unreachable."""


class LLMTimeoutError(LLMError):
    """Raised when an LLM request exceeds its timeout."""


# ── Scanner ─────────────────────────────────────────────────────────────

class ScannerError(BBHunterError):
    """Raised when an individual scanner module fails."""


class ScannerTimeoutError(ScannerError):
    """Raised when a scanner module exceeds its timeout."""


# ── Database ────────────────────────────────────────────────────────────

class DatabaseError(BBHunterError):
    """Raised for database connection or query failures."""


# ── Reporting ───────────────────────────────────────────────────────────

class ReportError(BBHunterError):
    """Raised when report generation fails."""
