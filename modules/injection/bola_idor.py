"""
AGENT ANONMUSK — BOLA/IDOR Detector
====================================
Identifies Broken Object-Level Authorization by testing cross-account access.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from core.context import Evidence, Finding, Severity, VulnType
from modules.base import BaseModule
from utils.http_client import HTTPClient

logger = logging.getLogger("AGENT ANONMUSK.injection.bola")

# Patterns indicating object IDs in URLs
ID_PATTERNS = [
    re.compile(r"/(?:user|account|org|profile|order|invoice|document|file|report|project|team|api/v\d+/\w+)/(\d+)", re.IGNORECASE),
    re.compile(r"(?:user_id|account_id|org_id|id|uid|profile_id)=(\d+)", re.IGNORECASE),
    re.compile(r"/(?:user|account|org|profile)/([a-f0-9-]{36})", re.IGNORECASE),  # UUID
]


class BOLADetector(BaseModule):
    """
    Detects Broken Object-Level Authorization (IDOR):
    1. Identifies endpoints with object ID patterns
    2. Fetches the original resource (baseline)
    3. Modifies the ID (increment/decrement) and compares responses
    4. If different valid data returns → BOLA confirmed
    """

    MODULE_NAME = "bola_idor"

    async def run(self) -> None:
        self._log_start("Testing for BOLA/IDOR vulnerabilities...")

        target_urls = self._attack_params.get("target_urls", [])
        if not target_urls:
            target_urls = self._find_id_endpoints()

        if not target_urls:
            self._log_complete("No endpoints with object IDs found")
            return

        scan_config = self.config.get("scanning", {})
        async with HTTPClient(
            scope=self.scope,
            rate_limit=scan_config.get("rate_limit", 5),
            timeout=scan_config.get("request_timeout", 15),
        ) as client:
            for url in target_urls[:20]:
                await self._test_idor(client, url)

        self._log_complete("BOLA/IDOR testing complete")

    def _find_id_endpoints(self) -> list[str]:
        """Find endpoints that contain object IDs."""
        urls = []
        for ep in self.ctx.endpoints:
            for pattern in ID_PATTERNS:
                if pattern.search(ep.url):
                    urls.append(ep.url)
                    break
        return urls

    async def _test_idor(self, client: HTTPClient, url: str):
        """Test a single endpoint for IDOR."""
        for pattern in ID_PATTERNS:
            match = pattern.search(url)
            if not match:
                continue

            original_id = match.group(1)

            # Generate test IDs
            test_ids = self._generate_test_ids(original_id)

            try:
                # Get baseline response
                baseline_resp, baseline_evidence = await client.get(url)
                baseline_status = baseline_resp.status_code
                baseline_length = len(baseline_resp.text)

                if baseline_status >= 400:
                    continue  # Skip if original request fails

                # Try each test ID
                for test_id in test_ids:
                    test_url = url.replace(original_id, str(test_id))

                    if test_url == url:
                        continue

                    try:
                        test_resp, test_evidence = await client.get(test_url)
                        test_status = test_resp.status_code
                        test_length = len(test_resp.text)

                        # Analyze: if we get a 200 with different content → IDOR
                        if (
                            test_status == 200
                            and test_length > 50
                            and abs(test_length - baseline_length) > 10
                            and test_resp.text != baseline_resp.text
                        ):
                            finding = Finding(
                                title=f"BOLA/IDOR at {url}",
                                vuln_type=VulnType.BOLA,
                                severity=Severity.HIGH,
                                description=(
                                    f"Broken Object-Level Authorization detected. "
                                    f"Changing object ID from '{original_id}' to "
                                    f"'{test_id}' returned different valid data "
                                    f"(status {test_status}, {test_length} bytes) "
                                    f"without proper authorization checks."
                                ),
                                evidence=[
                                    baseline_evidence,
                                    test_evidence,
                                ],
                                confidence=0.85,
                                target_url=url,
                                parameter="id",
                                payload=str(test_id),
                                remediation=(
                                    "Implement proper authorization checks:\n"
                                    "1. Verify the authenticated user owns the requested resource\n"
                                    "2. Use indirect object references (map user-facing IDs to internal IDs)\n"
                                    "3. Implement access control middleware"
                                ),
                            )
                            self.ctx.add_finding(finding)
                            logger.warning(
                                "🔓 BOLA/IDOR found: %s (id: %s → %s)",
                                url, original_id, test_id,
                            )
                            return  # One finding per endpoint

                    except Exception as e:
                        logger.debug("IDOR test failed: %s", e)

            except Exception as e:
                logger.debug("Baseline fetch failed for %s: %s", url, e)

    @staticmethod
    def _generate_test_ids(original_id: str) -> list[str]:
        """Generate test IDs from the original."""
        test_ids = []

        # Numeric IDs: try adjacent values
        try:
            num = int(original_id)
            test_ids.extend([
                str(num - 1), str(num + 1), str(num - 2),
                str(num + 2), str(num * 2), "1", "0",
            ])
        except ValueError:
            # UUID or string ID: try common IDs
            test_ids.extend([
                "1", "0", "admin", "test",
                "00000000-0000-0000-0000-000000000000",
                "00000000-0000-0000-0000-000000000001",
            ])

        return test_ids
