"""
AGENT ANONMUSK — Username Enumerator
====================================
Tests login/register/password-reset endpoints for verbose error differential.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

from core.context import Evidence, Finding, Severity, VulnType
from modules.base import BaseModule
from utils.http_client import HTTPClient

logger = logging.getLogger("AGENT ANONMUSK.auth.username_enum")

# ── Test usernames ───────────────────────────────────────────
EXISTING_USER_CANDIDATES = [
    "admin", "administrator", "root", "test", "user",
    "info", "support", "contact", "demo", "guest",
]

NONEXISTENT_USERS = [
    "xq7z9rk2m4", "notarealuser_8392", "fakeaccount_test_zz",
]


class UsernameEnumerator(BaseModule):
    """
    Detects username enumeration via:
    1. Error message differential (different error for valid vs invalid users)
    2. Timing differential (valid users take longer to process)
    """

    MODULE_NAME = "username_enum"

    async def run(self) -> None:
        self._log_start("Testing for username enumeration...")

        target_urls = self._attack_params.get("target_urls", [])

        if not target_urls:
            # Auto-discover auth endpoints from existing endpoints
            target_urls = self._find_auth_endpoints()

        if not target_urls:
            self._log_complete("No auth endpoints found to test")
            return

        scan_config = self.config.get("scanning", {})
        async with HTTPClient(
            scope=self.scope,
            rate_limit=scan_config.get("rate_limit", 5),
            timeout=scan_config.get("request_timeout", 15),
        ) as client:
            for url in target_urls:
                await self._test_endpoint(client, url)

        self._log_complete("Username enumeration testing complete")

    def _find_auth_endpoints(self) -> list[str]:
        """Find login/register/reset endpoints from recon data."""
        auth_keywords = ["login", "signin", "sign-in", "auth", "register",
                         "signup", "sign-up", "forgot", "reset", "password"]
        urls = []
        for ep in self.ctx.endpoints:
            lower_url = ep.url.lower()
            if any(kw in lower_url for kw in auth_keywords):
                urls.append(ep.url)
        return urls[:5]  # Limit to 5

    async def _test_endpoint(self, client: HTTPClient, url: str):
        """Test a single endpoint for username enumeration."""
        logger.info("Testing: %s", url)

        # ── Phase 1: Collect baseline responses ──────────
        responses: dict[str, dict[str, Any]] = {}

        # Try with known-bad username first
        for username in NONEXISTENT_USERS[:2]:
            resp_data = await self._attempt_login(client, url, username)
            if resp_data:
                responses[f"invalid_{username}"] = resp_data

        # Try with common usernames
        for username in EXISTING_USER_CANDIDATES[:5]:
            resp_data = await self._attempt_login(client, url, username)
            if resp_data:
                responses[f"candidate_{username}"] = resp_data

        # ── Phase 2: Analyze differential ────────────────
        if len(responses) < 3:
            logger.debug("Not enough responses to analyze for %s", url)
            return

        invalid_responses = {
            k: v for k, v in responses.items() if k.startswith("invalid_")
        }
        candidate_responses = {
            k: v for k, v in responses.items() if k.startswith("candidate_")
        }

        for name, candidate in candidate_responses.items():
            username = name.replace("candidate_", "")

            # Check error message differential
            for inv_name, invalid in invalid_responses.items():
                msg_diff = self._check_message_diff(invalid, candidate)
                time_diff = self._check_timing_diff(invalid, candidate)

                if msg_diff or time_diff:
                    evidence = Evidence(
                        request_method="POST",
                        request_url=url,
                        request_body=f"username={username}",
                        response_status=candidate.get("status", 0),
                        response_body=candidate.get("body", "")[:2000],
                        response_time_ms=candidate.get("time_ms", 0),
                        notes=(
                            f"Message diff: {msg_diff}\n"
                            f"Timing diff: {time_diff}"
                        ),
                    )

                    finding = Finding(
                        title=f"Username Enumeration at {url}",
                        vuln_type=VulnType.USERNAME_ENUM,
                        severity=Severity.LOW,
                        description=(
                            f"The endpoint responds differently for valid vs "
                            f"invalid usernames. Username '{username}' appears "
                            f"to exist based on response differential."
                        ),
                        evidence=[evidence],
                        confidence=0.7 if msg_diff else 0.5,
                        target_url=url,
                        parameter="username",
                        payload=username,
                    )

                    self.ctx.add_finding(finding)
                    logger.warning(
                        "🔓 Username enumeration found at %s (user: %s)",
                        url, username,
                    )
                    return  # One finding per endpoint is enough

    async def _attempt_login(
        self, client: HTTPClient, url: str, username: str
    ) -> dict[str, Any] | None:
        """Attempt a login and capture response details."""
        try:
            start = time.monotonic()
            resp, evidence = await client.post(
                url,
                data=f"username={username}&password=wrongpassword123!",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            elapsed = (time.monotonic() - start) * 1000

            return {
                "status": resp.status_code,
                "body": resp.text[:3000],
                "length": len(resp.text),
                "time_ms": elapsed,
                "headers": dict(resp.headers),
            }
        except Exception as e:
            logger.debug("Login attempt failed for %s: %s", username, e)
            return None

    @staticmethod
    def _check_message_diff(
        invalid: dict[str, Any], candidate: dict[str, Any]
    ) -> str:
        """Check if error messages differ (indicates enumeration)."""
        inv_body = invalid.get("body", "").lower()
        cand_body = candidate.get("body", "").lower()

        if inv_body == cand_body:
            return ""

        # Check for common differential patterns
        inv_len = invalid.get("length", 0)
        cand_len = candidate.get("length", 0)
        if abs(inv_len - cand_len) > 20:
            return f"Response length differs: {inv_len} vs {cand_len}"

        # Check status code diff
        if invalid.get("status") != candidate.get("status"):
            return (
                f"Status code differs: "
                f"{invalid.get('status')} vs {candidate.get('status')}"
            )

        return ""

    @staticmethod
    def _check_timing_diff(
        invalid: dict[str, Any], candidate: dict[str, Any]
    ) -> str:
        """Check timing differential (>200ms difference is suspicious)."""
        inv_time = invalid.get("time_ms", 0)
        cand_time = candidate.get("time_ms", 0)

        diff = abs(cand_time - inv_time)
        if diff > 200:
            return f"Response time differs by {diff:.0f}ms ({inv_time:.0f} vs {cand_time:.0f})"
        return ""
