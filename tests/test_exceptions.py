"""Tests for bbhunter.exceptions module."""

from bbhunter.exceptions import (
    BBHunterError,
    AuthorizationError,
    ScopeError,
    ConfigError,
    PipelineError,
    StepTimeoutError,
    ToolNotFoundError,
    ToolExecutionError,
    NetworkError,
    RateLimitError,
    LLMError,
    LLMConnectionError,
    LLMTimeoutError,
    ScannerError,
    ScannerTimeoutError,
    DatabaseError,
    ReportError,
)


class TestExceptionHierarchy:
    """Verify the exception inheritance chain."""

    def test_all_inherit_from_base(self):
        for exc_cls in [
            AuthorizationError, ScopeError, ConfigError, PipelineError,
            ToolNotFoundError, ToolExecutionError, NetworkError, LLMError,
            ScannerError, DatabaseError, ReportError,
        ]:
            assert issubclass(exc_cls, BBHunterError)

    def test_step_timeout_is_pipeline_error(self):
        assert issubclass(StepTimeoutError, PipelineError)

    def test_rate_limit_is_network_error(self):
        assert issubclass(RateLimitError, NetworkError)

    def test_llm_subtypes(self):
        assert issubclass(LLMConnectionError, LLMError)
        assert issubclass(LLMTimeoutError, LLMError)

    def test_scanner_timeout_is_scanner_error(self):
        assert issubclass(ScannerTimeoutError, ScannerError)

    def test_tool_execution_error_message(self):
        err = ToolExecutionError("subfinder", 1, "some stderr output")
        assert err.tool == "subfinder"
        assert err.returncode == 1
        assert "subfinder" in str(err)
        assert "1" in str(err)

    def test_base_is_catchable(self):
        try:
            raise AuthorizationError("test")
        except BBHunterError as e:
            assert str(e) == "test"
