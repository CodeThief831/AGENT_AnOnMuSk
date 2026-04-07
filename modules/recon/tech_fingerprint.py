"""
AGENT ANONMUSK — Technology Fingerprinter
========================================
Identifies the tech stack (server, framework, WAF) to tailor attacks.
"""

from __future__ import annotations

import logging
import re

import httpx

from core.context import TechStack
from modules.base import BaseModule

logger = logging.getLogger("AGENT ANONMUSK.recon.fingerprint")

# ── Signature Database ───────────────────────────────────────

FRAMEWORK_SIGNATURES = {
    # HTML body markers
    "react": [
        re.compile(r'id="(?:root|app|__next)"'),
        re.compile(r"_react"),
        re.compile(r"__NEXT_DATA__"),
        re.compile(r"data-reactroot"),
    ],
    "angular": [
        re.compile(r"ng-version"),
        re.compile(r"ng-app"),
        re.compile(r"\bng-\w+\b"),
    ],
    "vue": [
        re.compile(r"__vue__"),
        re.compile(r'id="app".*data-v-'),
        re.compile(r"vue\.js|vue\.min\.js"),
    ],
    "jquery": [
        re.compile(r"jquery[.\-]?\d"),
    ],
    "rails": [
        re.compile(r"csrf-token"),
        re.compile(r"authenticity_token"),
        re.compile(r"rails-ujs"),
    ],
    "django": [
        re.compile(r"csrfmiddlewaretoken"),
        re.compile(r"__admin/"),
    ],
    "laravel": [
        re.compile(r"laravel_session"),
        re.compile(r"XSRF-TOKEN"),
    ],
    "wordpress": [
        re.compile(r"wp-content|wp-includes"),
        re.compile(r"wordpress"),
    ],
    "spring": [
        re.compile(r"JSESSIONID"),
        re.compile(r"spring"),
    ],
}

SERVER_SIGNATURES = {
    "nginx": re.compile(r"nginx", re.IGNORECASE),
    "apache": re.compile(r"apache", re.IGNORECASE),
    "iis": re.compile(r"IIS|Microsoft", re.IGNORECASE),
    "cloudflare": re.compile(r"cloudflare", re.IGNORECASE),
    "gunicorn": re.compile(r"gunicorn", re.IGNORECASE),
    "express": re.compile(r"express", re.IGNORECASE),
}

WAF_SIGNATURES = {
    "cloudflare": [
        re.compile(r"cf-ray", re.IGNORECASE),
        re.compile(r"cloudflare", re.IGNORECASE),
    ],
    "akamai": [
        re.compile(r"akamai", re.IGNORECASE),
        re.compile(r"x-akamai", re.IGNORECASE),
    ],
    "aws_waf": [
        re.compile(r"x-amzn-requestid", re.IGNORECASE),
        re.compile(r"awselb", re.IGNORECASE),
    ],
    "imperva": [
        re.compile(r"incap_ses", re.IGNORECASE),
        re.compile(r"visid_incap", re.IGNORECASE),
    ],
    "sucuri": [
        re.compile(r"x-sucuri", re.IGNORECASE),
    ],
    "f5_bigip": [
        re.compile(r"bigip", re.IGNORECASE),
        re.compile(r"x-wa-info", re.IGNORECASE),
    ],
}

LANGUAGE_SIGNATURES = {
    "php": [
        re.compile(r"x-powered-by.*php", re.IGNORECASE),
        re.compile(r"\.php"),
        re.compile(r"PHPSESSID"),
    ],
    "python": [
        re.compile(r"x-powered-by.*python", re.IGNORECASE),
        re.compile(r"wsgi"),
    ],
    "java": [
        re.compile(r"JSESSIONID"),
        re.compile(r"x-powered-by.*servlet", re.IGNORECASE),
    ],
    "node": [
        re.compile(r"x-powered-by.*express", re.IGNORECASE),
        re.compile(r"connect\.sid"),
    ],
    "ruby": [
        re.compile(r"x-powered-by.*phusion|puma", re.IGNORECASE),
        re.compile(r"_session_id"),
    ],
    "asp.net": [
        re.compile(r"x-aspnet-version", re.IGNORECASE),
        re.compile(r"asp\.net", re.IGNORECASE),
        re.compile(r"__viewstate", re.IGNORECASE),
    ],
}


class TechFingerprinter(BaseModule):
    """
    Fingerprints the target's technology stack.

    Checks:
    - HTTP headers (Server, X-Powered-By, Set-Cookie)
    - HTML body markers (framework JS, meta tags)
    - Cookie names
    """

    MODULE_NAME = "tech_fingerprint"

    async def run(self) -> None:
        if not self.config.get("recon", {}).get("enable_tech_fingerprint", True):
            self._log_complete("Fingerprinting disabled in config")
            return

        self._log_start("Fingerprinting technology stack...")

        tech = TechStack()
        scan_config = self.config.get("scanning", {})

        hosts_to_check = self.ctx.live_hosts[:5] or [f"https://{self.ctx.target}"]

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(scan_config.get("request_timeout", 15)),
            follow_redirects=True,
            verify=False,
        ) as client:
            for host in hosts_to_check:
                try:
                    resp = await client.get(host)

                    headers_str = str(dict(resp.headers))
                    body = resp.text[:50000]  # First 50KB
                    cookies = str(resp.cookies)
                    combined = f"{headers_str}\n{body}\n{cookies}"

                    # Detect server
                    server_header = resp.headers.get("server", "")
                    if server_header and not tech.server:
                        tech.server = server_header

                    for name, pattern in SERVER_SIGNATURES.items():
                        if pattern.search(server_header):
                            tech.server = name
                            break

                    # Detect WAF
                    for waf_name, patterns in WAF_SIGNATURES.items():
                        if any(p.search(headers_str) for p in patterns):
                            tech.waf = waf_name
                            tech.raw_signatures.append(f"waf:{waf_name}")
                            break

                    # Detect framework
                    for fw_name, patterns in FRAMEWORK_SIGNATURES.items():
                        if any(p.search(combined) for p in patterns):
                            if not tech.framework:
                                tech.framework = fw_name
                            tech.raw_signatures.append(f"framework:{fw_name}")

                    # Detect language
                    for lang_name, patterns in LANGUAGE_SIGNATURES.items():
                        if any(p.search(combined) for p in patterns):
                            if not tech.language:
                                tech.language = lang_name
                            tech.raw_signatures.append(f"language:{lang_name}")

                    # Capture interesting headers
                    for header in [
                        "x-powered-by", "server", "x-aspnet-version",
                        "x-generator", "x-drupal-cache", "x-varnish",
                    ]:
                        val = resp.headers.get(header)
                        if val:
                            tech.headers[header] = val

                    # Capture cookies
                    for cookie in resp.cookies.jar:
                        tech.cookies.append(cookie.name)

                except Exception as e:
                    logger.debug("Failed to fingerprint %s: %s", host, e)

        # Deduplicate
        tech.raw_signatures = list(set(tech.raw_signatures))
        tech.cookies = list(set(tech.cookies))

        self.ctx.tech_stack = tech

        summary_parts = []
        if tech.server:
            summary_parts.append(f"Server: {tech.server}")
        if tech.framework:
            summary_parts.append(f"Framework: {tech.framework}")
        if tech.language:
            summary_parts.append(f"Language: {tech.language}")
        if tech.waf:
            summary_parts.append(f"WAF: {tech.waf}")

        self._log_complete(
            f"Fingerprint: {' │ '.join(summary_parts) or 'Unknown'}",
            data=tech.model_dump(),
        )
