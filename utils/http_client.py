"""
AGENT ANONMUSK — HTTP Client
===========================
Shared async HTTP client with scope checking, rate limiting,
proxy support, and automatic evidence collection.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Optional

import httpx

from core.context import Evidence
from core.scope import ScopeValidator

logger = logging.getLogger("AGENT ANONMUSK.http")


class HTTPClient:
    """
    Scope-aware async HTTP client.

    Every request is automatically:
    1. Checked against scope
    2. Rate-limited
    3. Logged with full request/response for evidence
    """

    def __init__(
        self,
        scope: ScopeValidator,
        rate_limit: int = 10,
        timeout: int = 30,
        max_redirects: int = 5,
        user_agent: str = "",
        proxy: Optional[str] = None,
        verify_ssl: bool = True,
    ):
        self.scope = scope
        self.rate_limit = rate_limit
        self._interval = 1.0 / rate_limit if rate_limit > 0 else 0
        self._last_request_time = 0.0
        self._lock = asyncio.Lock()

        transport_kwargs: dict[str, Any] = {}
        if proxy:
            transport_kwargs["proxy"] = proxy

        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(timeout),
            follow_redirects=True,
            max_redirects=max_redirects,
            verify=verify_ssl,
            headers={
                "User-Agent": user_agent or (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/125.0.0.0 Safari/537.36"
                ),
            },
            **transport_kwargs,
        )

    async def _rate_limit_wait(self):
        """Enforce rate limiting between requests."""
        async with self._lock:
            elapsed = time.monotonic() - self._last_request_time
            if elapsed < self._interval:
                await asyncio.sleep(self._interval - elapsed)
            self._last_request_time = time.monotonic()

    async def request(
        self,
        method: str,
        url: str,
        headers: Optional[dict] = None,
        data: Optional[str] = None,
        json_data: Optional[dict] = None,
        cookies: Optional[dict] = None,
        params: Optional[dict] = None,
        check_scope: bool = True,
    ) -> tuple[httpx.Response, Evidence]:
        """
        Send an HTTP request with scope check and evidence capture.

        Returns:
            (response, evidence) tuple
        """
        # Scope enforcement
        if check_scope:
            self.scope.validate_or_raise(url)

        await self._rate_limit_wait()

        start_time = time.monotonic()

        request_kwargs: dict[str, Any] = {"headers": headers or {}}
        if data:
            request_kwargs["content"] = data
        if json_data:
            request_kwargs["json"] = json_data
        if cookies:
            request_kwargs["cookies"] = cookies
        if params:
            request_kwargs["params"] = params

        response = await self._client.request(method, url, **request_kwargs)
        elapsed_ms = (time.monotonic() - start_time) * 1000

        # Build evidence
        evidence = Evidence(
            request_method=method,
            request_url=url,
            request_headers=dict(headers or {}),
            request_body=data or "",
            response_status=response.status_code,
            response_headers=dict(response.headers),
            response_body=response.text[:5000],  # cap at 5KB
            response_time_ms=round(elapsed_ms, 2),
        )

        logger.debug(
            "%s %s → %d (%.0fms)",
            method, url, response.status_code, elapsed_ms,
        )

        return response, evidence

    async def get(self, url: str, **kwargs) -> tuple[httpx.Response, Evidence]:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> tuple[httpx.Response, Evidence]:
        return await self.request("POST", url, **kwargs)

    async def put(self, url: str, **kwargs) -> tuple[httpx.Response, Evidence]:
        return await self.request("PUT", url, **kwargs)

    async def delete(self, url: str, **kwargs) -> tuple[httpx.Response, Evidence]:
        return await self.request("DELETE", url, **kwargs)

    async def close(self):
        """Close the underlying HTTP client."""
        await self._client.aclose()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.close()
