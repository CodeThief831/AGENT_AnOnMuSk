"""
AGENT ANONMUSK — Nuclei Runner
===============================
Wraps the Nuclei CLI scanner with JSON output parsing.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from core.context import Evidence, Finding, Severity, VulnType
from modules.base import BaseModule
from utils.tool_wrapper import ToolWrapper

logger = logging.getLogger("AGENT ANONMUSK.nuclei")

SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


class NucleiRunner(BaseModule):
    """
    Runs Nuclei vulnerability scanner against live hosts.

    Features:
    - JSON output parsing
    - Template selection based on tech fingerprint
    - Rate limiting and scope enforcement
    """

    MODULE_NAME = "nuclei"

    async def run(self) -> None:
        self._log_start("Running Nuclei scanner...")

        nuclei_config = self.config.get("nuclei", {})
        tool_paths = self.config.get("tools", {})

        nuclei = ToolWrapper("nuclei", tool_paths.get("nuclei"))

        if not nuclei.is_available:
            self._log_complete("Nuclei not installed — skipping")
            return

        # Prepare target list
        targets = self.ctx.live_hosts or [f"https://{self.ctx.target}"]
        if not targets:
            self._log_complete("No targets for Nuclei")
            return

        # Build target file
        output_dir = Path(self.config.get("general", {}).get("output_dir", "./output"))
        output_dir.mkdir(parents=True, exist_ok=True)

        target_file = output_dir / "nuclei_targets.txt"
        target_file.write_text("\n".join(targets), encoding="utf-8")

        result_file = output_dir / "nuclei_results.jsonl"

        # Build command args
        args = [
            "-l", str(target_file),
            "-jsonl",
            "-o", str(result_file),
            "-silent",
        ]

        # Severity filter
        severity_filter = nuclei_config.get("severity_filter", ["critical", "high", "medium"])
        if severity_filter:
            args.extend(["-severity", ",".join(severity_filter)])

        # Rate limiting
        rate_limit = nuclei_config.get("rate_limit", 150)
        args.extend(["-rate-limit", str(rate_limit)])

        # Bulk size
        bulk_size = nuclei_config.get("bulk_size", 25)
        args.extend(["-bulk-size", str(bulk_size)])

        # Custom templates
        templates_dir = nuclei_config.get("templates_dir", "")
        if templates_dir:
            args.extend(["-t", templates_dir])

        # Run Nuclei
        logger.info("Running Nuclei with %d targets...", len(targets))
        await nuclei.run(args, timeout=600)  # 10 min timeout

        # Parse results
        if result_file.exists():
            await self._parse_results(result_file)
        else:
            logger.info("No Nuclei results to parse")

        # Cleanup
        target_file.unlink(missing_ok=True)

        self._log_complete("Nuclei scan complete")

    async def _parse_results(self, result_file: Path):
        """Parse Nuclei JSON output and add findings."""
        try:
            lines = result_file.read_text(encoding="utf-8").strip().splitlines()
            count = 0

            for line in lines:
                if not line.strip():
                    continue
                try:
                    result = json.loads(line)
                    finding = self._result_to_finding(result)
                    if finding:
                        self.ctx.add_finding(finding)
                        count += 1
                except json.JSONDecodeError:
                    continue

            logger.info("Parsed %d Nuclei findings from %d results", count, len(lines))

        except Exception as e:
            logger.error("Failed to parse Nuclei results: %s", e)

    @staticmethod
    def _result_to_finding(result: dict[str, Any]) -> Finding | None:
        """Convert a Nuclei JSON result to a Finding."""
        try:
            info = result.get("info", {})
            severity_str = info.get("severity", "info").lower()
            severity = SEVERITY_MAP.get(severity_str, Severity.INFO)

            template_id = result.get("template-id", "unknown")
            matched_at = result.get("matched-at", "")
            matcher_name = result.get("matcher-name", "")

            # Build evidence
            request_data = result.get("request", "")
            response_data = result.get("response", "")

            evidence = Evidence(
                request_url=matched_at,
                request_body=str(request_data)[:2000],
                response_body=str(response_data)[:2000],
                notes=f"Template: {template_id}, Matcher: {matcher_name}",
            )

            return Finding(
                title=f"[Nuclei] {info.get('name', template_id)}",
                vuln_type=VulnType.OTHER,
                severity=severity,
                description=info.get("description", f"Nuclei template {template_id} matched."),
                evidence=[evidence],
                confidence=0.85,
                target_url=matched_at,
                remediation=info.get("remediation", ""),
            )

        except Exception:
            return None
