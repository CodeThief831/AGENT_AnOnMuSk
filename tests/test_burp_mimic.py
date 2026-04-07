"""Tests for burp_mimic.generator module."""

import tempfile
from pathlib import Path

from core.context import Evidence, Finding, Severity, VulnType
from burp_mimic.generator import BurpMimicGenerator


class TestBurpMimicGenerator:
    """Test PoC script generation."""

    def test_generate_repeater_script(self):
        """Test that a valid Python script is generated."""
        with tempfile.TemporaryDirectory() as tmpdir:
            gen = BurpMimicGenerator(output_dir=tmpdir)

            finding = Finding(
                title="Test SQLi",
                vuln_type=VulnType.SQLI,
                severity=Severity.CRITICAL,
                cvss_score=9.8,
                target_url="https://example.com/api/users?id=1",
                parameter="id",
                payload="' OR 1=1--",
                evidence=[Evidence(
                    request_method="GET",
                    request_url="https://example.com/api/users?id=' OR 1=1--",
                    request_headers={"User-Agent": "Test"},
                    response_status=200,
                    response_body="admin data leaked",
                )],
            )

            script_path = gen.generate(finding)
            assert script_path
            assert Path(script_path).exists()

            content = Path(script_path).read_text(encoding="utf-8")
            assert "import requests" in content
            assert "AGENT ANONMUSK" in content
            assert "example.com" in content
            assert "--proxy" in content

    def test_generate_without_evidence(self):
        """Test graceful handling when no evidence exists."""
        with tempfile.TemporaryDirectory() as tmpdir:
            gen = BurpMimicGenerator(output_dir=tmpdir)

            finding = Finding(
                title="Test",
                vuln_type=VulnType.XSS,
                severity=Severity.LOW,
            )

            path = gen.generate(finding)
            assert path == ""

    def test_script_is_valid_python(self):
        """Verify generated script has valid Python syntax."""
        with tempfile.TemporaryDirectory() as tmpdir:
            gen = BurpMimicGenerator(output_dir=tmpdir)

            finding = Finding(
                title="XSS PoC",
                vuln_type=VulnType.XSS,
                severity=Severity.MEDIUM,
                payload='<script>alert(1)</script>',
                evidence=[Evidence(
                    request_method="GET",
                    request_url="https://example.com/?q=test",
                    response_status=200,
                )],
            )

            script_path = gen.generate(finding)
            content = Path(script_path).read_text(encoding="utf-8")

            # Compile check — should not raise SyntaxError
            compile(content, script_path, "exec")
