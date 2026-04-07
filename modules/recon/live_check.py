"""
AGENT ANONMUSK — Live Host Checker
==================================
Filters subdomains to only live HTTP/HTTPS hosts.
"""

from __future__ import annotations

import logging

import httpx

from modules.base import BaseModule
from utils.tool_wrapper import ToolWrapper

logger = logging.getLogger("AGENT ANONMUSK.recon.live_check")


class LiveChecker(BaseModule):
    """
    Probes discovered subdomains for live HTTP/HTTPS services.

    Uses httpx CLI if available, falls back to Python httpx library.
    """

    MODULE_NAME = "live_check"

    async def run(self) -> None:
        self._log_start(f"Checking {len(self.ctx.subdomains)} subdomains for live hosts...")

        if not self.ctx.subdomains:
            self._log_complete("No subdomains to check")
            return

        tool_paths = self.config.get("tools", {})
        httpx_tool = ToolWrapper("httpx", tool_paths.get("httpx_cli"))

        if httpx_tool.is_available:
            await self._check_with_cli(httpx_tool)
        else:
            logger.info("httpx CLI not available — using Python fallback")
            await self._check_with_python()

        self._log_complete(
            f"Found {len(self.ctx.live_hosts)} live hosts "
            f"out of {len(self.ctx.subdomains)} subdomains",
        )

    async def _check_with_cli(self, tool: ToolWrapper):
        """Use httpx CLI for fast live checking."""
        results = await tool.run_with_pipe(
            args=["-silent", "-no-color"],
            pipe_input=self.ctx.subdomains,
            timeout=180,
        )
        self.ctx.live_hosts = sorted(set(results))

    async def _check_with_python(self):
        """Fallback: Use Python httpx to check each subdomain."""
        live: list[str] = []
        scan_config = self.config.get("scanning", {})
        timeout = scan_config.get("request_timeout", 10)

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(timeout),
            follow_redirects=True,
            verify=False,
        ) as client:
            for sub in self.ctx.subdomains:
                for scheme in ("https", "http"):
                    url = f"{scheme}://{sub}"
                    try:
                        resp = await client.get(url)
                        if resp.status_code < 500:
                            live.append(url)
                            logger.debug("LIVE: %s → %d", url, resp.status_code)
                            break  # no need to try http if https works
                    except (httpx.RequestError, httpx.HTTPStatusError):
                        continue

        self.ctx.live_hosts = sorted(set(live))
