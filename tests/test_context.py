"""Tests for core.context module."""

import json
import tempfile
from pathlib import Path

import pytest
from core.context import (
    ScanContext, Finding, Evidence, Endpoint,
    TechStack, Severity, VulnType,
)


class TestScanContext:
    """Test ScanContext data model."""

    def test_create_default(self):
        ctx = ScanContext(target="example.com")
        assert ctx.target == "example.com"
        assert ctx.scan_id
        assert ctx.subdomains == []
        assert ctx.findings == []

    def test_add_finding(self):
        ctx = ScanContext(target="example.com")
        finding = Finding(
            title="Test XSS",
            vuln_type=VulnType.XSS,
            severity=Severity.MEDIUM,
            cvss_score=6.1,
        )
        ctx.add_finding(finding)
        assert len(ctx.findings) == 1
        assert len(ctx.events) == 1
        assert ctx.events[0].event_type == "finding"

    def test_add_event(self):
        ctx = ScanContext(target="example.com")
        ctx.add_event("test", "module", "Test message", {"key": "val"})
        assert len(ctx.events) == 1
        assert ctx.events[0].module == "module"

    def test_stats(self):
        ctx = ScanContext(target="example.com")
        ctx.subdomains = ["a.example.com", "b.example.com"]
        ctx.live_hosts = ["https://a.example.com"]

        finding = Finding(
            title="Test",
            vuln_type=VulnType.XSS,
            severity=Severity.HIGH,
        )
        ctx.add_finding(finding)

        stats = ctx.stats
        assert stats["subdomains"] == 2
        assert stats["live_hosts"] == 1
        assert stats["findings"] == 1
        assert stats["severity"]["high"] == 1

    def test_save_and_load(self):
        ctx = ScanContext(target="example.com")
        ctx.subdomains = ["sub.example.com"]
        finding = Finding(
            title="Test SQLi",
            vuln_type=VulnType.SQLI,
            severity=Severity.CRITICAL,
            cvss_score=9.8,
        )
        ctx.add_finding(finding)

        with tempfile.TemporaryDirectory() as tmpdir:
            save_path = ctx.save(tmpdir)
            assert Path(save_path).exists()

            loaded = ScanContext.load(save_path)
            assert loaded.target == "example.com"
            assert len(loaded.findings) == 1
            assert loaded.findings[0].title == "Test SQLi"
            assert loaded.findings[0].cvss_score == 9.8


class TestFinding:
    """Test Finding model."""

    def test_finding_defaults(self):
        f = Finding(
            title="Test",
            vuln_type=VulnType.XSS,
            severity=Severity.LOW,
        )
        assert f.id
        assert f.confidence == 0.0
        assert f.validated is False
        assert f.discovered_at

    def test_finding_with_evidence(self):
        evidence = Evidence(
            request_method="GET",
            request_url="https://example.com/test?q=<script>",
            response_status=200,
            response_time_ms=42.0,
        )
        f = Finding(
            title="XSS",
            vuln_type=VulnType.XSS,
            severity=Severity.MEDIUM,
            evidence=[evidence],
        )
        assert len(f.evidence) == 1
        assert f.evidence[0].response_status == 200


class TestEndpoint:
    """Test Endpoint model."""

    def test_endpoint_defaults(self):
        ep = Endpoint(url="https://example.com/api/users?id=1")
        assert ep.method == "GET"
        assert ep.params == []
        assert ep.interesting is False
