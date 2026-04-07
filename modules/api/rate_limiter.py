"""
AGENT ANONMUSK — Rate Limit Tester
==================================
"Turbo Intruder" style rate escalation to find API rate-limit breaking points.
"""

from __future__ import annotations

import asyncio
import logging
import time

from core.context import Evidence, Finding, Severity, VulnType
from modules.base import BaseModule
from utils.http_client import HTTPClient

logger = logging.getLogger("AGENT ANONMUSK.api.rate_limit")


class RateLimitTester(BaseModule):
    """
    Progressive rate escalation to find API rate-limit thresholds.

    Method:
    1. Send N requests at increasing speeds
    2. Measure when rate limiting kicks in (429, captcha, block)
    3. Report the threshold and bypass potential
    """

    MODULE_NAME = "rate_limit"

    async def run(self) -> None:
        self._log_start("Testing API rate limits...")

        target_urls = self._attack_params.get("target_urls", [])
        if not target_urls:
            # Find API endpoints likely to have rate limits
            target_urls = [
                ep.url for ep in self.ctx.endpoints
                if any(kw in ep.url.lower() for kw in [
                    "login", "auth", "reset", "api/", "register",
                    "password", "verify", "otp", "token",
                ])
            ]

        if not target_urls:
            self._log_complete("No rate-limitable endpoints found")
            return

        for url in target_urls[:5]:
            await self._test_rate_limit(url)

        self._log_complete("Rate limit testing complete")

    async def _test_rate_limit(self, url: str):
        """Test rate limiting on a single endpoint."""
        logger.info("Rate testing: %s", url)

        # Escalating burst sizes
        burst_sizes = [5, 10, 25, 50, 100]
        results = []

        scan_config = self.config.get("scanning", {})

        async with HTTPClient(
            scope=self.scope,
            rate_limit=0,  # No rate limiting for this test
            timeout=scan_config.get("request_timeout", 15),
        ) as client:
            for burst in burst_sizes:
                result = await self._send_burst(client, url, burst)
                results.append(result)

                # If we got rate limited, record the threshold
                if result["rate_limited"]:
                    finding = Finding(
                        title=f"Rate Limit Threshold Discovered at {url}",
                        vuln_type=VulnType.RATE_LIMIT,
                        severity=Severity.INFO,
                        description=(
                            f"Rate limiting activates after ~{result['threshold']} "
                            f"requests at {result['rps']:.1f} req/s.\n\n"
                            f"This is informational — rate limiting IS working.\n"
                            f"Burst sizes tested: {burst_sizes}"
                        ),
                        evidence=[Evidence(
                            request_url=url,
                            notes=(
                                f"Threshold: {result['threshold']} requests\n"
                                f"Rate: {result['rps']:.1f} req/s\n"
                                f"Status codes: {result['status_codes']}"
                            ),
                        )],
                        confidence=0.9,
                        target_url=url,
                    )
                    self.ctx.add_finding(finding)
                    logger.info(
                        "📊 Rate limit threshold: %d req at %.1f/s for %s",
                        result["threshold"], result["rps"], url,
                    )
                    return

            # No rate limiting detected at any burst size
            finding = Finding(
                title=f"Missing Rate Limiting at {url}",
                vuln_type=VulnType.RATE_LIMIT,
                severity=Severity.MEDIUM,
                description=(
                    f"No rate limiting detected after {max(burst_sizes)} "
                    f"rapid requests. This endpoint may be vulnerable to:\n"
                    f"- Brute force attacks\n"
                    f"- Credential stuffing\n"
                    f"- Resource exhaustion (DoS)"
                ),
                evidence=[Evidence(
                    request_url=url,
                    notes=f"All {max(burst_sizes)} requests returned 200 OK",
                )],
                confidence=0.8,
                target_url=url,
                remediation=(
                    "Implement rate limiting:\n"
                    "1. Use token bucket or sliding window algorithm\n"
                    "2. Limit by IP + User-Agent + session\n"
                    "3. Return 429 Too Many Requests with Retry-After header\n"
                    "4. Consider CAPTCHA after threshold"
                ),
            )
            self.ctx.add_finding(finding)
            logger.warning("⚡ No rate limit on %s", url)

    async def _send_burst(
        self,
        client: HTTPClient,
        url: str,
        count: int,
    ) -> dict:
        """Send a burst of requests and analyze responses."""
        status_codes: list[int] = []
        rate_limited = False
        threshold = count

        start = time.monotonic()

        tasks = []
        for i in range(count):
            tasks.append(self._single_request(client, url))

        responses = await asyncio.gather(*tasks, return_exceptions=True)
        elapsed = time.monotonic() - start

        for i, resp in enumerate(responses):
            if isinstance(resp, Exception):
                continue
            status_codes.append(resp)
            if resp in (429, 503) or resp >= 500:
                rate_limited = True
                threshold = i + 1

        rps = count / elapsed if elapsed > 0 else 0

        return {
            "burst_size": count,
            "rate_limited": rate_limited,
            "threshold": threshold,
            "rps": rps,
            "elapsed": elapsed,
            "status_codes": dict(
                (code, status_codes.count(code))
                for code in set(status_codes)
            ),
        }

    async def _single_request(self, client: HTTPClient, url: str) -> int:
        """Send a single request and return status code."""
        try:
            resp, _ = await client.get(url, check_scope=True)
            return resp.status_code
        except Exception:
            return 0
