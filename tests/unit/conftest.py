"""Shared pytest configuration for new platform tests."""
import sys
from pathlib import Path

# Add packages to path
_root = Path(__file__).resolve().parent.parent.parent
for pkg_dir in (_root / "packages").iterdir():
    if pkg_dir.is_dir():
        sys.path.insert(0, str(pkg_dir))

# LLM gateway
sys.path.insert(0, str(_root / "services" / "llm-gateway"))

# Alias module name for import
import importlib
gateway_module = importlib.import_module("gateway")
sys.modules["services_llm_gateway"] = gateway_module
