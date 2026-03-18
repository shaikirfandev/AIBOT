"""Tests for bbhunter.safety module."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from bbhunter.exceptions import AuthorizationError


class TestSafetyGate:
    """Test the SafetyGate authorization enforcement."""

    def test_bypass_when_auth_disabled(self, config_file: Path, tmp_path: Path):
        """When require_authorization=false, check() returns permissive target."""
        from bbhunter.config import load_config
        import bbhunter.config as mod
        mod._config = load_config(config_file)

        from bbhunter.safety import SafetyGate
        gate = SafetyGate()
        target = gate.check("anything.com")
        assert target.domain == "anything.com"

    def test_authorized_target_passes(self, config_file: Path, auth_file: Path):
        """Authorized domain passes the check."""
        from bbhunter.config import load_config
        import bbhunter.config as mod
        cfg = load_config(config_file)
        # Enable auth and point to our auth file
        cfg.safety.require_authorization = True
        cfg.safety.authorization_file = str(auth_file)
        mod._config = cfg

        from bbhunter.safety import SafetyGate
        gate = SafetyGate()
        target = gate.check("example.com")
        assert target.domain == "example.com"

    def test_wildcard_scope_passes(self, config_file: Path, auth_file: Path):
        """Subdomain matching *.example.com passes."""
        from bbhunter.config import load_config
        import bbhunter.config as mod
        cfg = load_config(config_file)
        cfg.safety.require_authorization = True
        cfg.safety.authorization_file = str(auth_file)
        mod._config = cfg

        from bbhunter.safety import SafetyGate
        gate = SafetyGate()
        target = gate.check("sub.example.com")
        assert target is not None

    def test_excluded_subdomain_fails(self, config_file: Path, auth_file: Path):
        """internal.example.com is in the exclude list."""
        from bbhunter.config import load_config
        import bbhunter.config as mod
        cfg = load_config(config_file)
        cfg.safety.require_authorization = True
        cfg.safety.authorization_file = str(auth_file)
        mod._config = cfg

        from bbhunter.safety import SafetyGate
        gate = SafetyGate()
        with pytest.raises(AuthorizationError):
            gate.check("internal.example.com")

    def test_unauthorized_domain_raises(self, config_file: Path, auth_file: Path):
        """Completely unauthorized domain raises AuthorizationError."""
        from bbhunter.config import load_config
        import bbhunter.config as mod
        cfg = load_config(config_file)
        cfg.safety.require_authorization = True
        cfg.safety.authorization_file = str(auth_file)
        mod._config = cfg

        from bbhunter.safety import SafetyGate
        gate = SafetyGate()
        with pytest.raises(AuthorizationError, match="NOT authorized"):
            gate.check("evil.com")

    def test_is_method_banned(self, config_file: Path):
        from bbhunter.config import load_config
        import bbhunter.config as mod
        mod._config = load_config(config_file)

        from bbhunter.safety import SafetyGate
        gate = SafetyGate()
        assert gate.is_method_banned("dos") is True
        assert gate.is_method_banned("passive_scan") is False

    def test_is_in_scope_url(self, config_file: Path, auth_file: Path):
        from bbhunter.config import load_config
        import bbhunter.config as mod
        cfg = load_config(config_file)
        cfg.safety.require_authorization = True
        cfg.safety.authorization_file = str(auth_file)
        mod._config = cfg

        from bbhunter.safety import SafetyGate
        gate = SafetyGate()
        assert gate.is_in_scope("https://sub.example.com/path") is True
        assert gate.is_in_scope("https://evil.com/") is False

    def test_expired_authorization_raises(self, config_file: Path, tmp_path: Path):
        """Expired authorization date should raise."""
        from bbhunter.config import load_config
        import bbhunter.config as mod
        cfg = load_config(config_file)
        cfg.safety.require_authorization = True

        auth_yaml = tmp_path / "expired.yaml"
        auth_yaml.write_text("""\
targets:
  - domain: "expired.com"
    scope:
      include: ["*.expired.com"]
      exclude: []
    authorization:
      type: "bug_bounty"
      platform: "Test"
      expiry_date: "2020-01-01"
    rules: {}
""")
        cfg.safety.authorization_file = str(auth_yaml)
        mod._config = cfg

        from bbhunter.safety import SafetyGate
        gate = SafetyGate()
        with pytest.raises(AuthorizationError, match="expired"):
            gate.check("expired.com")
