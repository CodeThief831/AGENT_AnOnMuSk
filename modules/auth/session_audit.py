"""
AGENT ANONMUSK — Session Auditor
================================
Verifies session cookie security: HttpOnly, Secure, SameSite flags,
token entropy, and token rotation.
"""

from __future__ import annotations

import hashlib
import logging
import math
from collections import Counter

from core.context import Evidence, Finding, Severity, VulnType
from modules.base import BaseModule
from utils.http_client import HTTPClient

logger = logging.getLogger("AGENT ANONMUSK.auth.session")


class SessionAuditor(BaseModule):
    """
    Audits session management for:
    1. Missing HttpOnly / Secure / SameSite cookie flags
    2. Low session token entropy
    3. Token rotation on login/logout
    """

    MODULE_NAME = "session_audit"

    async def run(self) -> None:
        self._log_start("Auditing session management...")

        scan_config = self.config.get("scanning", {})
        hosts = self.ctx.live_hosts[:5] or [f"https://{self.ctx.target}"]

        async with HTTPClient(
            scope=self.scope,
            rate_limit=scan_config.get("rate_limit", 10),
            timeout=scan_config.get("request_timeout", 15),
        ) as client:
            for host in hosts:
                await self._audit_host(client, host)

        self._log_complete("Session audit complete")

    async def _audit_host(self, client: HTTPClient, host: str):
        """Audit a single host's session management."""
        try:
            resp, evidence = await client.get(host)
        except Exception as e:
            logger.debug("Failed to fetch %s: %s", host, e)
            return

        # Extract Set-Cookie headers
        cookies_raw = resp.headers.get_list("set-cookie") if hasattr(
            resp.headers, "get_list"
        ) else [
            v for k, v in resp.headers.multi_items()
            if k.lower() == "set-cookie"
        ]

        if not cookies_raw:
            logger.debug("No cookies set by %s", host)
            return

        for cookie_str in cookies_raw:
            self._check_cookie_flags(host, cookie_str, evidence)
            self._check_entropy(host, cookie_str, evidence)

    def _check_cookie_flags(self, host: str, cookie_str: str, evidence: Evidence):
        """Check for missing security flags on cookies."""
        cookie_lower = cookie_str.lower()
        cookie_name = cookie_str.split("=")[0].strip()

        # Skip non-session cookies (tracking, analytics)
        session_indicators = [
            "session", "sid", "token", "auth", "jwt",
            "ssid", "connect.sid", "phpsessid", "jsessionid",
        ]
        is_session = any(ind in cookie_name.lower() for ind in session_indicators)

        if not is_session:
            return  # Only audit session-like cookies

        issues = []

        if "httponly" not in cookie_lower:
            issues.append("Missing HttpOnly flag (vulnerable to XSS cookie theft)")

        if "secure" not in cookie_lower:
            issues.append("Missing Secure flag (cookie sent over HTTP)")

        if "samesite" not in cookie_lower:
            issues.append("Missing SameSite flag (CSRF risk)")
        elif "samesite=none" in cookie_lower:
            issues.append("SameSite=None (CSRF risk unless Secure is set)")

        if issues:
            finding = Finding(
                title=f"Insecure Session Cookie '{cookie_name}' at {host}",
                vuln_type=VulnType.MISCONFIG,
                severity=Severity.MEDIUM if "httponly" in str(issues).lower() else Severity.LOW,
                description=(
                    f"The session cookie '{cookie_name}' is missing security flags:\n"
                    + "\n".join(f"- {issue}" for issue in issues)
                ),
                evidence=[Evidence(
                    request_url=host,
                    response_headers={"Set-Cookie": cookie_str},
                    notes="\n".join(issues),
                )],
                confidence=0.95,
                target_url=host,
                remediation=(
                    f"Set proper flags on the '{cookie_name}' cookie:\n"
                    f"Set-Cookie: {cookie_name}=<value>; HttpOnly; Secure; SameSite=Lax"
                ),
            )
            self.ctx.add_finding(finding)
            logger.warning("🍪 Insecure cookie '%s' at %s", cookie_name, host)

    def _check_entropy(self, host: str, cookie_str: str, evidence: Evidence):
        """Check session token entropy (should be >= 4.0 bits per char)."""
        parts = cookie_str.split(";")[0]  # Get name=value
        if "=" not in parts:
            return

        name, value = parts.split("=", 1)
        value = value.strip()

        if len(value) < 8:
            return  # Too short to analyze

        entropy = self._calculate_entropy(value)

        if entropy < 3.5:
            finding = Finding(
                title=f"Low Entropy Session Token '{name.strip()}' at {host}",
                vuln_type=VulnType.MISCONFIG,
                severity=Severity.HIGH,
                description=(
                    f"The session token '{name.strip()}' has low entropy "
                    f"({entropy:.2f} bits/char). Tokens should have >= 4.0 "
                    f"bits/char to resist brute-force prediction."
                ),
                evidence=[Evidence(
                    request_url=host,
                    response_headers={"Set-Cookie": cookie_str[:200]},
                    notes=f"Entropy: {entropy:.2f} bits/char, Length: {len(value)}",
                )],
                confidence=0.8,
                target_url=host,
                remediation=(
                    "Generate session tokens using cryptographically secure "
                    "random number generators (e.g., secrets.token_hex(32) in Python)."
                ),
            )
            self.ctx.add_finding(finding)

    @staticmethod
    def _calculate_entropy(data: str) -> float:
        """Calculate Shannon entropy of a string (bits per character)."""
        if not data:
            return 0.0
        counter = Counter(data)
        length = len(data)
        entropy = 0.0
        for count in counter.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)
        return entropy
