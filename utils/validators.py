"""
AGENT ANONMUSK — Input Validators
================================
Domain/URL validation, scope file parsing, input sanitization.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse


# ── Regex Patterns ───────────────────────────────────────────

DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,}$"
)

WILDCARD_DOMAIN_RE = re.compile(
    r"^\*\.(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,}$"
)

URL_RE = re.compile(
    r"^https?://[^\s/$.?#].[^\s]*$",
    re.IGNORECASE,
)


def is_valid_domain(domain: str) -> bool:
    """Check if a string is a valid domain name."""
    return bool(DOMAIN_RE.match(domain.strip()))


def is_valid_wildcard(pattern: str) -> bool:
    """Check if a string is a valid wildcard domain (*.example.com)."""
    return bool(WILDCARD_DOMAIN_RE.match(pattern.strip()))


def is_valid_url(url: str) -> bool:
    """Check if a string is a valid HTTP/HTTPS URL."""
    if not URL_RE.match(url.strip()):
        return False
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False


def normalize_url(url: str) -> str:
    """Normalize a URL (lowercase scheme/host, strip trailing slash)."""
    parsed = urlparse(url.strip())
    scheme = parsed.scheme.lower() or "https"
    host = (parsed.hostname or "").lower()
    port = f":{parsed.port}" if parsed.port and parsed.port not in (80, 443) else ""
    path = parsed.path.rstrip("/") or ""
    query = f"?{parsed.query}" if parsed.query else ""
    return f"{scheme}://{host}{port}{path}{query}"


def extract_domain(url: str) -> str:
    """Extract the domain from a URL or domain string."""
    if "://" in url:
        parsed = urlparse(url)
        return (parsed.hostname or url).lower()
    return url.split(":")[0].strip().lower()


def extract_params(url: str) -> list[str]:
    """Extract query parameter names from a URL."""
    parsed = urlparse(url)
    if not parsed.query:
        return []
    params = []
    for pair in parsed.query.split("&"):
        if "=" in pair:
            params.append(pair.split("=")[0])
        else:
            params.append(pair)
    return params


def sanitize_filename(name: str) -> str:
    """Sanitize a string for use as a filename."""
    return re.sub(r'[<>:"/\\|?*\x00-\x1f]', '_', name)[:200]
