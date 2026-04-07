"""
AGENT ANONMUSK — Report Generator
==================================
Generates Markdown and JSON reports from scan findings.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.context import ScanContext, Finding
from reporting.cvss import CVSSCalculator, severity_from_score
from reporting.remediation import get_remediation

logger = logging.getLogger("AGENT ANONMUSK.reporting")


class ReportGenerator:
    """
    Generates comprehensive security assessment reports.

    Output formats:
    - Markdown (.md) — Human-readable with severity badges
    - JSON (.json) — Machine-readable for integrations
    """

    def __init__(self, output_dir: str = "./output", config: dict | None = None):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.config = config or {}

    def generate(self, ctx: ScanContext) -> str:
        """Generate the full Markdown report. Returns file path."""

        # Auto-score findings that don't have CVSS yet
        for finding in ctx.findings:
            if finding.cvss_score == 0:
                score, vector = CVSSCalculator.auto_score(finding.vuln_type)
                finding.cvss_score = score
                finding.cvss_vector = vector

        # Sort findings by severity (critical first)
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        findings = sorted(
            ctx.findings,
            key=lambda f: severity_order.get(f.severity.value, 5),
        )

        # Build report sections
        sections = [
            self._header(ctx),
            self._executive_summary(ctx, findings),
            self._severity_breakdown(findings),
            self._findings_detail(findings),
            self._tech_stack_summary(ctx),
            self._methodology(ctx),
            self._appendix(ctx),
        ]

        report = "\n\n".join(sections)

        # Save
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M")
        filename = f"AGENT ANONMUSK_report_{ctx.scan_id[:8]}_{timestamp}.md"
        filepath = self.output_dir / filename
        filepath.write_text(report, encoding="utf-8")

        logger.info("Report generated: %s", filepath)
        return str(filepath)

    def export_json(self, ctx: ScanContext) -> str:
        """Export scan data as JSON. Returns file path."""
        data = {
            "scan_id": ctx.scan_id,
            "target": ctx.target,
            "started_at": ctx.started_at,
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "stats": ctx.stats,
            "findings": [f.model_dump() for f in ctx.findings],
            "tech_stack": ctx.tech_stack.model_dump(),
            "subdomains": ctx.subdomains,
            "live_hosts": ctx.live_hosts,
            "events": [e.model_dump() for e in ctx.events],
        }

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M")
        filename = f"AGENT ANONMUSK_scan_{ctx.scan_id[:8]}_{timestamp}.json"
        filepath = self.output_dir / filename
        filepath.write_text(
            json.dumps(data, indent=2, default=str),
            encoding="utf-8",
        )

        return str(filepath)

    # ── Report Sections ──────────────────────────────────

    def _header(self, ctx: ScanContext) -> str:
        return f"""# ⚡ AGENT ANONMUSK — Security Assessment Report

| Field | Value |
|-------|-------|
| **Target** | `{ctx.target}` |
| **Scan ID** | `{ctx.scan_id[:8]}` |
| **Date** | {datetime.now(timezone.utc).strftime("%B %d, %Y")} |
| **Subdomains** | {len(ctx.subdomains)} discovered |
| **Live Hosts** | {len(ctx.live_hosts)} active |
| **Endpoints** | {len(ctx.endpoints)} enumerated |
| **Findings** | {len(ctx.findings)} total |

---

> ⚠️ **CONFIDENTIAL** — This report contains sensitive security information.
> Distribute only to authorized personnel."""

    def _executive_summary(self, ctx: ScanContext, findings: list[Finding]) -> str:
        critical = sum(1 for f in findings if f.severity.value == "critical")
        high = sum(1 for f in findings if f.severity.value == "high")
        medium = sum(1 for f in findings if f.severity.value == "medium")
        low = sum(1 for f in findings if f.severity.value == "low")
        info = sum(1 for f in findings if f.severity.value == "info")

        risk_level = "CRITICAL" if critical > 0 else (
            "HIGH" if high > 0 else (
                "MEDIUM" if medium > 0 else "LOW"
            )
        )

        return f"""## 📋 Executive Summary

**Overall Risk Level: {risk_level}**

The AGENT ANONMUSK autonomous security agent performed a comprehensive assessment
of `{ctx.target}`, discovering **{len(findings)} findings** across
{len(ctx.live_hosts)} live hosts.

### Severity Distribution

| Severity | Count |
|----------|-------|
| 🔴 Critical | {critical} |
| 🟠 High | {high} |
| 🟡 Medium | {medium} |
| 🔵 Low | {low} |
| ⚪ Info | {info} |"""

    def _severity_breakdown(self, findings: list[Finding]) -> str:
        if not findings:
            return "## Findings\n\nNo vulnerabilities detected."

        lines = ["## 📊 Severity Breakdown\n"]
        lines.append("| # | Severity | CVSS | Title | URL |")
        lines.append("|---|----------|------|-------|-----|")

        for i, f in enumerate(findings, 1):
            sev_icon = {
                "critical": "🔴",
                "high": "🟠",
                "medium": "🟡",
                "low": "🔵",
                "info": "⚪",
            }.get(f.severity.value, "⚪")

            title = f.title[:60]
            url = f.target_url[:50] if f.target_url else "—"
            lines.append(
                f"| {i} | {sev_icon} {f.severity.value.upper()} | "
                f"{f.cvss_score:.1f} | {title} | `{url}` |"
            )

        return "\n".join(lines)

    def _findings_detail(self, findings: list[Finding]) -> str:
        if not findings:
            return ""

        sections = ["## 🔍 Detailed Findings\n"]

        for i, f in enumerate(findings, 1):
            remediation = get_remediation(f.vuln_type)

            section = f"""### {i}. {f.title}

| Property | Value |
|----------|-------|
| **Severity** | {f.severity.value.upper()} |
| **CVSS Score** | {f.cvss_score:.1f} |
| **CVSS Vector** | `{f.cvss_vector}` |
| **Type** | {f.vuln_type.value} |
| **URL** | `{f.target_url}` |
| **Parameter** | `{f.parameter or '—'}` |
| **Confidence** | {f.confidence * 100:.0f}% |

**Description:**
{f.description}

"""
            if f.payload:
                section += f"**Payload:**\n```\n{f.payload}\n```\n\n"

            if f.poc_script_path:
                section += f"**PoC Script:** `{f.poc_script_path}`\n\n"

            # Evidence
            if f.evidence:
                ev = f.evidence[0]
                section += f"""**Evidence:**
- Request: `{ev.request_method} {ev.request_url}`
- Status: `{ev.response_status}`
- Response Time: `{ev.response_time_ms:.0f}ms`
"""
                if ev.notes:
                    section += f"- Notes: {ev.notes}\n"

            # Remediation
            section += f"""
**Remediation:**
{remediation.get('summary', f.remediation or 'See OWASP guidelines.')}

---
"""
            sections.append(section)

        return "\n".join(sections)

    def _tech_stack_summary(self, ctx: ScanContext) -> str:
        tech = ctx.tech_stack
        return f"""## 🔧 Technology Stack

| Component | Value |
|-----------|-------|
| **Server** | {tech.server or 'Unknown'} |
| **Framework** | {tech.framework or 'Unknown'} |
| **Language** | {tech.language or 'Unknown'} |
| **WAF** | {tech.waf or 'None detected'} |
| **Cookies** | {', '.join(tech.cookies[:5]) or 'None'} |"""

    def _methodology(self, ctx: ScanContext) -> str:
        return """## 📖 Methodology

This assessment was performed by the **AGENT ANONMUSK** autonomous agent using
the following methodology:

1. **Reconnaissance** — Subdomain enumeration, endpoint discovery, JS analysis
2. **Fingerprinting** — Technology stack and WAF identification
3. **LLM Analysis** — AI-driven attack vector selection
4. **Active Testing** — Automated vulnerability testing with WAF-evasion
5. **Validation** — PoC script generation and replay verification
6. **Reporting** — Automated CVSS scoring and remediation advice

Tools utilized: subfinder, amass, httpx, nuclei, custom engines."""

    def _appendix(self, ctx: ScanContext) -> str:
        sections = ["## 📎 Appendix\n"]

        if ctx.js_secrets:
            sections.append("### Exposed Secrets in JavaScript\n")
            sections.append("| Type | Source |")
            sections.append("|------|--------|")
            for secret in ctx.js_secrets[:10]:
                sections.append(
                    f"| {secret['type']} | `{secret['source'][:60]}` |"
                )

        sections.append(f"\n### Scan Timeline\n")
        sections.append(f"Total events recorded: **{len(ctx.events)}**\n")

        return "\n".join(sections)
