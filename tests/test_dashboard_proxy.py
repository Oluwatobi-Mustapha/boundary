import importlib.util
import os
import pathlib
import pytest


ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "dashboard_proxy.py"

spec = importlib.util.spec_from_file_location("dashboard_proxy", MODULE_PATH)
assert spec is not None, f"Could not find module at {MODULE_PATH}"
assert spec.loader is not None, f"Module spec at {MODULE_PATH} has no loader"
dashboard_proxy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dashboard_proxy)


def test_parse_dashboard_url_valid():
    api_root, default_path, region = dashboard_proxy._parse_dashboard_url(
        "https://abc123.execute-api.us-east-1.amazonaws.com/dashboard"
    )
    assert api_root == "https://abc123.execute-api.us-east-1.amazonaws.com"
    assert default_path == "/dashboard"
    assert region == "us-east-1"


def test_parse_dashboard_url_rejects_invalid():
    with pytest.raises(ValueError):
        dashboard_proxy._parse_dashboard_url("http://example.com/dashboard")
    with pytest.raises(ValueError):
        dashboard_proxy._parse_dashboard_url("https://example.com/dashboard")
