"""
AGENT ANONMUSK — Session Fixation Tester
========================================
Tests if session identity persists across login state changes.
"""

from __future__ import annotations

import logging

from core.context import Evidence, Finding, Severity, VulnType
from modules.base import BaseModule
from utils.http_client import HTTPClient

logger = logging.getLogger("AGENT ANONMUSK.auth.fixation")


class SessionFixationTester(BaseModule):
    """
    Tests for session fixation:
    1. Get a session token (pre-login)
    2. Authenticate
    3. Check if the same session token persists (BAD)
    """

    MODULE_NAME = "session_fixation"

    async def run(self) -> None:
        self._log_start("Testing for session fixation...")

        target_urls = self._attack_params.get("target_urls", [])
        if not target_urls:
            target_urls = self._find_login_endpoints()

        if not target_urls:
            self._log_complete("No login endpoints found")
            return

        scan_config = self.config.get("scanning", {})
        async with HTTPClient(
            scope=self.scope,
            rate_limit=scan_config.get("rate_limit", 5),
            timeout=scan_config.get("request_timeout", 15),
        ) as client:
            for url in target_urls:
                await self._test_fixation(client, url)

        self._log_complete("Session fixation testing complete")

    def _find_login_endpoints(self) -> list[str]:
        """Find login endpoints from recon."""
        login_kw = ["login", "signin", "sign-in", "auth/login"]
        urls = []
        for ep in self.ctx.endpoints:
            if any(kw in ep.url.lower() for kw in login_kw):
                urls.append(ep.url)
        return urls[:3]

    async def _test_fixation(self, client: HTTPClient, url: str):
        """Test session fixation on a login endpoint."""
        try:
            # Step 1: Get pre-login session
            resp1, _ = await client.get(url)
            pre_cookies = self._extract_session_cookies(resp1)

            if not pre_cookies:
                logger.debug("No session cookies from %s", url)
                return

            # Step 2: Attempt login with the pre-login cookies
            resp2, evidence = await client.post(
                url,
                data="username=test&password=test123",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                cookies=pre_cookies,
            )

            post_cookies = self._extract_session_cookies(resp2)

            # Step 3: Check if session tokens changed
            if pre_cookies and post_cookies:
                unchanged = {
                    k: v for k, v in pre_cookies.items()
                    if k in post_cookies and post_cookies[k] == v
                }

                if unchanged:
                    finding = Finding(
                        title=f"Session Fixation at {url}",
                        vuln_type=VulnType.SESSION_FIXATION,
                        severity=Severity.HIGH,
                        description=(
                            f"Session token(s) persist across login state change: "
                            f"{', '.join(unchanged.keys())}. An attacker could "
                            f"fixate a session and hijack authenticated access."
                        ),
                        evidence=[Evidence(
                            request_method="POST",
                            request_url=url,
                            notes=(
                                f"Pre-login cookies: {pre_cookies}\n"
                                f"Post-login cookies: {post_cookies}\n"
                                f"Unchanged: {unchanged}"
                            ),
                        )],
                        confidence=0.75,
                        target_url=url,
                        remediation=(
                            "Regenerate the session ID after any authentication "
                            "state change (login, logout, privilege escalation)."
                        ),
                    )
                    self.ctx.add_finding(finding)
                    logger.warning("🔒 Session fixation at %s", url)

        except Exception as e:
            logger.debug("Fixation test failed for %s: %s", url, e)

    @staticmethod
    def _extract_session_cookies(resp) -> dict[str, str]:
        """Extract session-like cookies from response."""
        session_indicators = [
            "session", "sid", "token", "auth", "ssid",
            "connect.sid", "phpsessid", "jsessionid",
        ]
        cookies = {}
        for name, value in resp.cookies.items():
            if any(ind in name.lower() for ind in session_indicators):
                cookies[name] = value
        return cookies
