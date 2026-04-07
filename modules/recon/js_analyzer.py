"""
AGENT ANONMUSK — JavaScript Analyzer
====================================
Scrapes JS files for hidden endpoints, API keys, secrets, and internal URLs.
"""

from __future__ import annotations

import logging
import re
from typing import Any

import httpx
from bs4 import BeautifulSoup

from modules.base import BaseModule

logger = logging.getLogger("anonmusk_agent.recon.js")

# ── Regex patterns for secret detection ──────────────────────

SECRET_PATTERNS = {
    "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "aws_secret_key": re.compile(r"(?:aws_secret_access_key|AWS_SECRET)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"),
    "google_api_key": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "github_token": re.compile(r"gh[ps]_[A-Za-z0-9_]{36,}"),
    "slack_token": re.compile(r"xox[bpsa]-[0-9]{10,13}-[0-9A-Za-z-]+"),
    "jwt_token": re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
    "private_key": re.compile(r"-----BEGIN (?:RSA|EC|DSA|OPENSSH) PRIVATE KEY-----"),
    "generic_secret": re.compile(
        r"(?:api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token|"
        r"secret[_-]?key|private[_-]?key|password|passwd|credentials)"
        r"\s*[:=]\s*['\"]([A-Za-z0-9/+=_\-]{8,})['\"]",
        re.IGNORECASE,
    ),
    "bearer_token": re.compile(r"['\"]Bearer\s+[A-Za-z0-9._\-]+['\"]"),
}

# Endpoint patterns in JS
ENDPOINT_PATTERNS = [
    re.compile(r'["\'](/api/[a-zA-Z0-9_/\-{}]+)["\']'),
    re.compile(r'["\'](/v[0-9]+/[a-zA-Z0-9_/\-{}]+)["\']'),
    re.compile(r'fetch\(["\']([^"\']+)["\']'),
    re.compile(r'axios\.[a-z]+\(["\']([^"\']+)["\']'),
    re.compile(r'\.(?:get|post|put|delete|patch)\(["\']([^"\']+)["\']'),
    re.compile(r'endpoint\s*[:=]\s*["\']([^"\']+)["\']'),
    re.compile(r'url\s*[:=]\s*["\']([^"\']+)["\']'),
    re.compile(r'href\s*[:=]\s*["\'](/[^"\']+)["\']'),
]


class JSAnalyzer(BaseModule):
    """
    Analyzes JavaScript files for hidden endpoints and secrets.

    Steps:
    1. Find <script src="..."> tags from live hosts
    2. Download each JS file
    3. Extract endpoints, secrets, and internal URLs
    """

    MODULE_NAME = "js_analyzer"

    async def run(self) -> None:
        if not self.config.get("recon", {}).get("enable_js_analysis", True):
            self._log_complete("JS analysis disabled in config")
            return

        self._log_start("Analyzing JavaScript files...")

        scan_config = self.config.get("scanning", {})
        timeout = scan_config.get("request_timeout", 15)

        js_urls: set[str] = set()
        all_endpoints: set[str] = set()
        all_secrets: list[dict[str, str]] = []

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(timeout),
            follow_redirects=True,
            verify=False,
            headers={
                "User-Agent": scan_config.get(
                    "user_agent",
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/125.0.0.0"
                ),
            },
        ) as client:
            # Step 1: Extract JS URLs from live hosts
            for host in self.ctx.live_hosts[:10]:  # Top 10 hosts
                try:
                    resp = await client.get(host)
                    soup = BeautifulSoup(resp.text, "lxml")

                    for script in soup.find_all("script", src=True):
                        src = script["src"]
                        if src.startswith("//"):
                            src = f"https:{src}"
                        elif src.startswith("/"):
                            src = f"{host.rstrip('/')}{src}"
                        elif not src.startswith("http"):
                            src = f"{host.rstrip('/')}/{src}"
                        js_urls.add(src)

                except Exception as e:
                    logger.debug("Failed to fetch %s: %s", host, e)

            self.ctx.js_files = list(js_urls)
            logger.info("Found %d JavaScript files", len(js_urls))

            # Step 2: Analyze each JS file
            for js_url in js_urls:
                try:
                    resp = await client.get(js_url)
                    if resp.status_code != 200:
                        continue

                    content = resp.text

                    # Extract endpoints
                    for pattern in ENDPOINT_PATTERNS:
                        for match in pattern.finditer(content):
                            endpoint = match.group(1)
                            if len(endpoint) > 5 and not endpoint.endswith(
                                (".js", ".css", ".png", ".jpg", ".svg", ".ico")
                            ):
                                all_endpoints.add(endpoint)

                    # Extract secrets
                    for secret_type, pattern in SECRET_PATTERNS.items():
                        for match in pattern.finditer(content):
                            secret_val = match.group(0)[:100]  # truncate
                            all_secrets.append({
                                "type": secret_type,
                                "value": secret_val,
                                "source": js_url,
                            })
                            logger.warning(
                                "🔑 Secret found [%s] in %s",
                                secret_type, js_url,
                            )

                except Exception as e:
                    logger.debug("Failed to analyze %s: %s", js_url, e)

        # Update context
        self.ctx.js_secrets = all_secrets

        # Add JS-discovered endpoints to the main endpoint list
        from core.context import Endpoint
        for ep in all_endpoints:
            self.ctx.endpoints.append(Endpoint(
                url=ep,
                source="js_analysis",
                interesting=True,
            ))

        self._log_complete(
            f"Extracted {len(all_endpoints)} endpoints and "
            f"{len(all_secrets)} secrets from {len(js_urls)} JS files",
        )
