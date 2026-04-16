"""Resilience tests for fallback and baseline security behavior."""

import tempfile

from core.context import Endpoint, Evidence, ScanContext, VulnType
from core.orchestrator import Orchestrator
from core.scope import ScopeValidator
from modules.auth.session_audit import SessionAuditor
from utils.tool_wrapper import ToolWrapper


def test_toolwrapper_missing_tool_returns_false_without_crash():
    wrapper = ToolWrapper("tool_that_definitely_does_not_exist_anonmusk")
    assert wrapper.is_available is False


def test_orchestrator_default_attack_plan_includes_core_modules():
    with tempfile.TemporaryDirectory() as tmpdir:
        orch = Orchestrator(
            target="example.com",
            config_path=f"{tmpdir}/mock_config_for_test.yaml",
            output_dir=tmpdir,
            api_key="",
        )
        orch.ctx.endpoints = [
            Endpoint(
                url="https://example.com/api/users?id=1&q=test",
                params=["id", "q"],
                interesting=True,
            ),
            Endpoint(
                url="https://example.com/login",
                params=[],
                interesting=False,
            ),
        ]

        plan = orch._default_attack_plan()
        modules = {item["module"] for item in plan}

        assert "session_audit" in modules
        assert "xss" in modules
        assert "sqli" in modules
        assert "api_bola" in modules
        assert "rate_limit" in modules


def test_session_audit_reports_missing_security_headers():
    ctx = ScanContext(target="example.com")
    scope = ScopeValidator.from_target("example.com")
    module = SessionAuditor(ctx, scope, config={})

    module._check_security_headers(
        host="https://example.com",
        headers={"Server": "nginx"},
        evidence=Evidence(request_url="https://example.com"),
    )

    assert len(ctx.findings) == 1
    assert ctx.findings[0].vuln_type == VulnType.MISCONFIG
    assert "Missing Security Headers" in ctx.findings[0].title
